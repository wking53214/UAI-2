"""providers: real model providers behind the provider-neutral adapter contract (adapter.py), on the standard library.

Six clients, so nothing in UAI-1 depends on any one vendor: Anthropic (Messages API), Google (Gemini generateContent), OpenAI
(ChatGPT models, Chat Completions), Copilot, Groq (the OpenAI Chat Completions wire format) and Cloudflare Workers AI. This is
the only module in the repository that talks to a model provider. "Copilot" has no single public completion API; the client speaks the OpenAI
Chat Completions wire format to the two routes Microsoft documents for it, GitHub Models and Azure OpenAI, and is labeled with the
route it used. Microsoft 365 Copilot is not covered: no equivalent public endpoint is known. Each is
only a `complete(prompt) -> text` function handed to `adapter.PromptedModelAdapter`; everything else (strict reading of the
output, the decider's policy, grants, approval) is unchanged, and none of it is given a key, a signer or an authority.

WHAT THIS MODULE DOES
  * bounded: a connect and read timeout, a response size cap, no redirects followed (a redirect would carry the key elsewhere)
  * strict: the provider's own envelope is read exactly (one text block / one candidate that finished normally); anything else
    is refused as `provider` with a reason: an HTTP error, a rate limit, a truncated or filtered answer, a missing or extra shape
  * provenance: every call records the provider, the model asked for and the model the provider reported, the digests of the
    exact request bytes sent and response bytes read, the latency, why it finished, and whether the output was accepted or
    rejected and why. The digests are this caller's own record: no provider signs its answer, so they show what this process
    says it sent and received, not proof to a third party
  * transport: `https` only, except to this machine (a loopback address), so a key is never sent in the clear to another host
  * keys: held in the closure only; never in an exception, a record or a log line

WHAT IT IS NOT. Nothing here treats a model's confidence, a stated approval or a claimed authority as anything: the strict
parser refuses any key beyond verdict, reasons, evidence and escalate. A model recommends; the decider's policy decides; a grant
permits; a person approves.

HONESTY ABOUT WHAT HAS BEEN EXECUTED. The tests run these clients against local servers that speak each provider's wire format
(labeled STUB in the tests). That checks this code's handling of the protocol, not any provider. A live call needs a key
(`interop/live_providers.py`), prints NOT EXECUTED without one, and is the only thing that may set `ProviderInfo.live`.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from .envelope import Refused

__all__ = ["Provenance", "ProvenanceLog", "anthropic_complete", "gemini_complete", "openai_complete", "copilot_complete",
           "groq_complete", "cloudflare_complete", "MAX_RESPONSE_BYTES"]

MAX_RESPONSE_BYTES = 262_144


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Provenance:
    provider: str
    model_requested: str
    model_reported: str = ""
    request_sha256: str = ""
    response_sha256: str = ""
    latency_ms: int = 0
    finish_reason: str = ""
    call: str = "not-made"      # ok, or why no usable answer came back
    outcome: str = "pending"    # accepted or rejected (by the adapter's strict reading and the decider's policy)
    reason: str = ""
    http_status: Optional[int] = None    # what the provider answered, when it answered at all
    input_tokens: Optional[int] = None   # as the provider reported them, when it did
    output_tokens: Optional[int] = None
    request_id: str = ""                 # the provider's own id for the exchange, when it gives one


class ProvenanceLog:
    """What was requested, returned, accepted and rejected, in order. In memory, and appended as JSON lines to `path` if given."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.records: List[Provenance] = []
        self._path = path

    def add(self, rec: Provenance) -> Provenance:
        self.records.append(rec)
        return rec

    def settle(self, rec: Provenance, outcome: str, reason: str = "") -> None:
        if rec.outcome != "pending":
            return  # settled once: a provider failure is not rewritten when the adapter reports it again
        rec.outcome, rec.reason = outcome, reason
        if self._path:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(rec), sort_keys=True) + "\n")

    def observer(self) -> Callable[[Any, Any, Any, Optional[Exception]], None]:
        """For `AdapterJudge(observer=...)`: settles the most recent call as accepted or rejected, with the reason."""
        def observe(raw: Any, rec: Any, judgment: Any, error: Optional[Exception]) -> None:
            if not self.records:
                return
            last = self.records[-1]
            if error is not None:
                self.settle(last, "rejected", getattr(error, "code", type(error).__name__) + ": " + str(getattr(error, "reason", error))[:160])
            else:
                self.settle(last, "accepted", f"verdict {judgment.verdict}" if judgment is not None else "")
        return observe


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a: Any, **k: Any) -> None:
        return None


def _refused(reason: str, category: str) -> Refused:
    """A provider refusal. `category` is a short stable word for callers that sort failures (the typed bridge reports it)."""
    exc = Refused("provider", reason)
    exc.category = category  # type: ignore[attr-defined]
    return exc


_LOOPBACK = ("127.0.0.1", "::1", "localhost")


def _check_url(base_url: str) -> None:
    """`https`, or `http` to this machine only. A key sent over plain http to another host is readable on the way."""
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme == "https" and parts.hostname:
        return
    if parts.scheme == "http" and parts.hostname in _LOOPBACK:
        return
    raise ValueError("base_url must be https (plain http is accepted only for a loopback address on this machine)")


def _encode(body: Dict[str, Any]) -> bytes:
    """The exact bytes sent. The request digest is taken over these, so the record matches what left this process."""
    return json.dumps(body, sort_keys=True).encode("utf-8")


def _exchange(url: str, headers: Dict[str, str], data: bytes, timeout_s: float, max_bytes: int,
              deadline: float) -> Tuple[int, bytes, str]:
    """One POST, read to the end or to `max_bytes`. Returns (status, body, the cf-ray header or "")."""
    req = urllib.request.Request(url, data=data, headers={**headers, "content-type": "application/json"}, method="POST")
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=timeout_s) as resp:
            pieces: List[bytes] = []
            size = 0
            while size <= max_bytes:
                piece = resp.read1(min(65_536, max_bytes + 1 - size))
                if not piece:
                    break
                pieces.append(piece)
                size += len(piece)
                if time.monotonic() > deadline:  # the caller has already given up; stop reading
                    raise TimeoutError()
            ray = resp.headers.get("cf-ray")
            return int(resp.status), b"".join(pieces), ray if isinstance(ray, str) else ""
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read(2048), ""


def _timed_out() -> Refused:
    return _refused("the provider could not be reached or timed out (TimeoutError)", "timeout")


def _post(url: str, headers: Dict[str, str], body: Dict[str, Any], timeout_s: float, max_bytes: int,
          rec: Optional["Provenance"] = None) -> Tuple[int, bytes]:
    """POST `body` and return (status, bytes), within `timeout_s` for the WHOLE exchange: connecting, sending, waiting
    and reading together.

    A socket timeout bounds each blocking step, not their sum. A server that sends one byte just inside it and then
    goes quiet makes the next read wait a full timeout again, and one that keeps doing so never lets go. So the
    exchange runs on a worker thread and this call waits for it no longer than the deadline. Past the deadline the
    caller gets a refusal at once; the worker is left to hit its own socket timeout (at most `timeout_s` later), sees
    that the deadline has passed, and ends. Nothing it read is used."""
    data = _encode(body)
    deadline = time.monotonic() + timeout_s
    box: Dict[str, Any] = {}

    def run() -> None:
        try:
            box["ok"] = _exchange(url, headers, data, timeout_s, max_bytes, deadline)
        except BaseException as exc:  # carried to the caller below; a worker thread must not die with it unreported
            box["error"] = exc

    worker = threading.Thread(target=run, name="uai-provider-call", daemon=True)
    worker.start()
    worker.join(max(0.0, deadline - time.monotonic()))
    if worker.is_alive() or (not box):
        raise _timed_out()
    error = box.get("error")
    if error is not None:
        if isinstance(error, (urllib.error.URLError, TimeoutError, OSError)):
            reason = getattr(error, "reason", error)
            if isinstance(reason, TimeoutError) or isinstance(error, TimeoutError):
                raise _timed_out()
            raise _refused(f"the provider could not be reached or timed out ({type(reason).__name__})",
                           "connection_error") from None
        raise error
    status, raw, ray = box["ok"]
    if rec is not None:
        rec.http_status = status
        if ray and not rec.request_id:
            rec.request_id = ray[:120]
    return status, raw


def _read_json(status: int, raw: bytes, max_bytes: int) -> Dict[str, Any]:
    if len(raw) > max_bytes:
        raise _refused(f"the provider's answer is larger than {max_bytes} bytes", "response_too_large")
    if status == 429:
        raise _refused("the provider is rate limiting this caller (HTTP 429)", "rate_limit")
    if not 200 <= status < 300:
        raise _refused(f"the provider answered HTTP {status}",
                       {401: "authentication", 403: "permission"}.get(status, "http_error"))
    try:
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise _refused("the provider's answer is not JSON", "invalid_response") from None
    if not isinstance(value, dict):
        raise _refused("the provider's answer is not a JSON object", "invalid_response")
    return value


def _usage(rec: "Provenance", usage: Any, input_key: str, output_key: str) -> None:
    """Token counts as the provider reported them. Anything that is not two non-negative integers is left unrecorded."""
    if not isinstance(usage, dict):
        return
    counts = (usage.get(input_key), usage.get(output_key))
    if all(isinstance(n, int) and not isinstance(n, bool) and n >= 0 for n in counts):
        rec.input_tokens, rec.output_tokens = counts


def _request_id(rec: "Provenance", value: Any) -> None:
    if isinstance(value, str) and value:
        rec.request_id = value[:120]


def _check_key(api_key: str) -> None:
    """A key with whitespace or a control or format character anywhere is refused before any request is built.

    A pasted key often carries a newline, a tab, a zero-width space or a byte order mark. Sent as a header it would be rejected,
    split, or silently altered. The error names the problem, never the key or any part of it."""
    if any(ch.isspace() or unicodedata.category(ch) in ("Cc", "Cf") for ch in api_key):
        raise ValueError("the API key contains whitespace or a control character; check how it was pasted (the key is not shown)")


def _client(name: str, model: str, log: ProvenanceLog, call: Callable[[str, Provenance], str]) -> Callable[[str], str]:
    def complete(prompt: str) -> str:
        rec = log.add(Provenance(provider=name, model_requested=model))
        started = time.perf_counter()
        try:
            text = call(prompt, rec)
            rec.call = "ok"
            return text
        except Refused as exc:
            if not hasattr(exc, "category"):
                exc.category = "invalid_response"  # type: ignore[attr-defined]  # the provider answered, in a shape not read
            rec.call = exc.reason[:160]
            log.settle(rec, "rejected", f"provider: {exc.reason}"[:200])
            raise
        finally:
            rec.latency_ms = int((time.perf_counter() - started) * 1000)
    return complete


_THINKING_BLOCKS = ("thinking", "redacted_thinking")  # reasoning, never an answer: skipped, not read


def anthropic_complete(api_key: str, model: str, log: ProvenanceLog, *, base_url: str = "https://api.anthropic.com",
                       timeout_s: float = 30.0, max_tokens: int = 16_000,
                       max_response_bytes: int = MAX_RESPONSE_BYTES, truncated_ok: bool = False) -> Callable[[str], str]:
    """`complete(prompt)` over the Anthropic Messages API. The key lives only in this closure.

    `truncated_ok` is for callers that want text, not a decision: an answer cut off at the token limit is returned and the
    record says so in `finish_reason`. It stays False wherever the text is read as a recommendation.

    Current models think by default, and thinking spends output tokens before the answer, so `max_tokens` leaves room for it.
    Thinking blocks (`thinking`, `redacted_thinking`) carry no answer and are skipped; what remains must be exactly one text
    block. A `refusal` stop reason is the provider declining the request and is refused as such, never read as an answer."""
    if not api_key or not model:
        raise ValueError("an API key and a model name are needed")
    _check_key(api_key)
    _check_url(base_url)

    def call(prompt: str, rec: Provenance) -> str:
        body = {"model": model, "max_tokens": max_tokens, "messages": [{"role": "user", "content": prompt}]}
        rec.request_sha256 = _digest(_encode(body))
        status, raw = _post(base_url.rstrip("/") + "/v1/messages",
                            {"x-api-key": api_key, "anthropic-version": "2023-06-01"}, body, timeout_s, max_response_bytes, rec)
        rec.response_sha256 = _digest(raw[:max_response_bytes])
        out = _read_json(status, raw, max_response_bytes)
        rec.model_reported, rec.finish_reason = str(out.get("model", "")), str(out.get("stop_reason", ""))
        _usage(rec, out.get("usage"), "input_tokens", "output_tokens")
        _request_id(rec, out.get("id"))
        blocks = out.get("content")
        if rec.finish_reason == "refusal":
            details = out.get("stop_details")
            category = details.get("category") if isinstance(details, dict) else None
            label = str(category)[:40] if isinstance(category, str) and category else "unspecified"
            raise Refused("provider", f"the provider declined the request (stop_reason 'refusal', category {label!r}): no answer")
        if rec.finish_reason != "end_turn" and not (truncated_ok and rec.finish_reason == "max_tokens"):
            raise Refused("provider", f"the answer did not end normally (stop_reason {rec.finish_reason!r}): it may be cut off")
        if not isinstance(blocks, list):
            raise Refused("provider", "the answer is not exactly one text block")
        rest = [b for b in blocks if not (isinstance(b, dict) and b.get("type") in _THINKING_BLOCKS)]
        if len(rest) != 1 or not isinstance(rest[0], dict) or rest[0].get("type") != "text" \
                or not isinstance(rest[0].get("text"), str):
            raise Refused("provider", "the answer is not exactly one text block")
        return str(rest[0]["text"])
    return _client("anthropic", model, log, call)


def gemini_complete(api_key: str, model: str, log: ProvenanceLog, *, base_url: str = "https://generativelanguage.googleapis.com",
                    timeout_s: float = 30.0, max_response_bytes: int = MAX_RESPONSE_BYTES,
                    max_tokens: Optional[int] = None, truncated_ok: bool = False) -> Callable[[str], str]:
    """`complete(prompt)` over Google's Gemini generateContent. The key is sent in a header, never in the URL.

    `max_tokens`, when given, is sent as the output limit; left out, the request carries none, as before. `truncated_ok` is
    as for `anthropic_complete`."""
    if not api_key or not model or "/" in model or "?" in model:
        raise ValueError("an API key and a plain model name are needed")
    _check_key(api_key)
    _check_url(base_url)

    def call(prompt: str, rec: Provenance) -> str:
        body: Dict[str, Any] = {"contents": [{"role": "user", "parts": [{"text": prompt}]}]}
        if max_tokens is not None:
            body["generationConfig"] = {"maxOutputTokens": max_tokens}
        rec.request_sha256 = _digest(_encode(body))
        url = f"{base_url.rstrip('/')}/v1beta/models/{urllib.parse.quote(model)}:generateContent"
        status, raw = _post(url, {"x-goog-api-key": api_key}, body, timeout_s, max_response_bytes, rec)
        rec.response_sha256 = _digest(raw[:max_response_bytes])
        out = _read_json(status, raw, max_response_bytes)
        rec.model_reported = str(out.get("modelVersion", ""))
        _usage(rec, out.get("usageMetadata"), "promptTokenCount", "candidatesTokenCount")
        _request_id(rec, out.get("responseId"))
        cands = out.get("candidates")
        if not isinstance(cands, list) or len(cands) != 1 or not isinstance(cands[0], dict):
            raise Refused("provider", "the answer is not exactly one candidate (a blocked prompt returns none)")
        rec.finish_reason = str(cands[0].get("finishReason", ""))
        if rec.finish_reason != "STOP" and not (truncated_ok and rec.finish_reason == "MAX_TOKENS"):
            raise Refused("provider", f"the answer did not finish normally (finishReason {rec.finish_reason!r})")
        parts = (cands[0].get("content") or {}).get("parts") if isinstance(cands[0].get("content"), dict) else None
        if not isinstance(parts, list) or len(parts) != 1 or not isinstance(parts[0], dict) or not isinstance(parts[0].get("text"), str):
            raise Refused("provider", "the answer is not exactly one text part")
        return str(parts[0]["text"])
    return _client("google", model, log, call)


def _chat_call(model: str, prompt: str, rec: Provenance, url: str, headers: Dict[str, str], timeout_s: float, max_tokens: int,
               max_bytes: int, send_model: bool = True, truncated_ok: bool = False) -> str:
    """One OpenAI Chat Completions exchange, read exactly: one choice, finished with `stop`, one plain text message."""
    body: Dict[str, Any] = {"messages": [{"role": "user", "content": prompt}], "max_tokens": max_tokens}
    if send_model:
        body["model"] = model
    rec.request_sha256 = _digest(_encode(body))
    status, raw = _post(url, headers, body, timeout_s, max_bytes, rec)
    rec.response_sha256 = _digest(raw[:max_bytes])
    out = _read_json(status, raw, max_bytes)
    rec.model_reported = str(out.get("model", ""))
    _usage(rec, out.get("usage"), "prompt_tokens", "completion_tokens")
    _request_id(rec, out.get("id"))
    return _read_choice(rec, out, truncated_ok)


def _read_choice(rec: Provenance, out: Dict[str, Any], truncated_ok: bool) -> str:
    """The text of a Chat Completions `choices` answer, read exactly: one choice, finished with `stop`, one plain text message."""
    choices = out.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise Refused("provider", "the answer is not exactly one choice")
    rec.finish_reason = str(choices[0].get("finish_reason", ""))
    if rec.finish_reason != "stop" and not (truncated_ok and rec.finish_reason == "length"):
        raise Refused("provider", f"the answer did not finish normally (finish_reason {rec.finish_reason!r}): it may be cut off or filtered")
    msg = choices[0].get("message")
    if not isinstance(msg, dict) or msg.get("role") != "assistant" or not isinstance(msg.get("content"), str):
        raise Refused("provider", "the answer is not one assistant text message")
    if msg.get("tool_calls") or msg.get("function_call") or msg.get("refusal"):
        raise Refused("provider", "the answer carries a tool call or a refusal, not plain text")
    return str(msg["content"])


def openai_complete(api_key: str, model: str, log: ProvenanceLog, *, base_url: str = "https://api.openai.com",
                    timeout_s: float = 30.0, max_tokens: int = 512,
                    max_response_bytes: int = MAX_RESPONSE_BYTES, truncated_ok: bool = False) -> Callable[[str], str]:
    """`complete(prompt)` over OpenAI Chat Completions (the ChatGPT model family). The key lives only in this closure."""
    if not api_key or not model:
        raise ValueError("an API key and a model name are needed")
    _check_key(api_key)
    _check_url(base_url)

    def call(prompt: str, rec: Provenance) -> str:
        return _chat_call(model, prompt, rec, base_url.rstrip("/") + "/v1/chat/completions",
                          {"authorization": "Bearer " + api_key}, timeout_s, max_tokens, max_response_bytes,
                          truncated_ok=truncated_ok)
    return _client("openai", model, log, call)


#: Groq and Cloudflare sit behind an edge that turns away the default Python client name, so these two say who they are.
_USER_AGENT = "STACK-UAI2-Provider/1.0"


def groq_complete(api_key: str, model: str, log: ProvenanceLog, *, base_url: str = "https://api.groq.com/openai/v1",
                  timeout_s: float = 30.0, max_tokens: int = 512,
                  max_response_bytes: int = MAX_RESPONSE_BYTES, truncated_ok: bool = False) -> Callable[[str], str]:
    """`complete(prompt)` over Groq, which speaks the OpenAI Chat Completions wire format. Read exactly as `openai_complete`."""
    if not api_key or not model:
        raise ValueError("an API key and a model name are needed")
    _check_key(api_key)
    _check_url(base_url)

    def call(prompt: str, rec: Provenance) -> str:
        return _chat_call(model, prompt, rec, base_url.rstrip("/") + "/chat/completions",
                          {"authorization": "Bearer " + api_key, "user-agent": _USER_AGENT}, timeout_s, max_tokens,
                          max_response_bytes, truncated_ok=truncated_ok)
    return _client("groq", model, log, call)


def cloudflare_complete(api_key: str, model: str, log: ProvenanceLog, *, account_id: str,
                        base_url: str = "https://api.cloudflare.com/client/v4", timeout_s: float = 45.0,
                        max_tokens: int = 512, max_response_bytes: int = MAX_RESPONSE_BYTES) -> Callable[[str], str]:
    """`complete(prompt)` over Cloudflare Workers AI (`/accounts/<account>/ai/run/<model>`), with an API token.

    `account_id` is yours and is letters and digits only. `model` is a catalog name such as "@cf/meta/llama-3.1-8b-instruct".
    Older catalog models answer `{"response": text}` and do not say why the answer ended, so a cut-off answer cannot be told
    from a complete one: the record's `finish_reason` stays empty, and a decider that must not act on a truncated answer
    should use a provider that reports it. Newer models answer in the Chat Completions shape (`choices`), which is read with
    the same exact rules as the OpenAI-compatible routes: one choice, finished with `stop`, one plain text message."""
    if not api_key or not model or "?" in model or "#" in model or ".." in model:
        raise ValueError("an API token and a plain model name are needed")
    if not isinstance(account_id, str) or not account_id.isalnum():
        raise ValueError("a Cloudflare account id (letters and digits) is needed")
    _check_key(api_key)
    _check_url(base_url)

    def call(prompt: str, rec: Provenance) -> str:
        # sent as `messages`: newer models answer a bare `prompt` with an empty message (seen live 2026-11-12)
        body = {"messages": [{"role": "user", "content": prompt}], "max_tokens": max_tokens}
        rec.request_sha256 = _digest(_encode(body))
        url = f"{base_url.rstrip('/')}/accounts/{account_id}/ai/run/{urllib.parse.quote(model, safe='/@')}"
        status, raw = _post(url, {"authorization": "Bearer " + api_key, "user-agent": _USER_AGENT}, body, timeout_s,
                            max_response_bytes, rec)
        rec.response_sha256 = _digest(raw[:max_response_bytes])
        out = _read_json(status, raw, max_response_bytes)
        if out.get("success") is not True:
            raise _refused("the provider reported an unsuccessful inference", "provider_error")
        result = out.get("result")
        if isinstance(result, dict) and "choices" in result:
            # newer catalog models answer in the Chat Completions shape, which does say why the answer ended
            rec.model_reported = str(result.get("model", ""))
            _usage(rec, result.get("usage"), "prompt_tokens", "completion_tokens")
            _request_id(rec, result.get("id"))
            text = _read_choice(rec, result, truncated_ok=False)
            if not text.strip():
                raise Refused("provider", "the answer carries no text")
            return text
        text = result.get("response") if isinstance(result, dict) else None
        if not isinstance(text, str) or not text.strip():
            raise Refused("provider", "the answer carries no text")
        _usage(rec, result.get("usage") if isinstance(result, dict) else None, "prompt_tokens", "completion_tokens")
        return text
    return _client("cloudflare-workers-ai", model, log, call)


COPILOT_ROUTES = ("github-models", "azure-openai")


def copilot_complete(api_key: str, model: str, log: ProvenanceLog, *, route: str = "github-models", base_url: str = "",
                     api_version: str = "2024-10-21", timeout_s: float = 30.0, max_tokens: int = 512,
                     max_response_bytes: int = MAX_RESPONSE_BYTES, truncated_ok: bool = False) -> Callable[[str], str]:
    """`complete(prompt)` for Copilot over a documented OpenAI-compatible route.

    route "github-models": `https://models.github.ai/inference/chat/completions`, bearer token, model like "openai/gpt-4.1".
    route "azure-openai": `base_url` is YOUR resource (https://<name>.openai.azure.com) and `model` is YOUR deployment name;
    the key goes in the `api-key` header. The route is part of the provenance provider name, so a record says which was used."""
    if not api_key or not model:
        raise ValueError("an API key and a model name are needed")
    _check_key(api_key)
    if base_url:
        _check_url(base_url)
    if route not in COPILOT_ROUTES:
        raise ValueError(f"unknown Copilot route {route!r}: expected one of {COPILOT_ROUTES}")
    if route == "azure-openai":
        if not base_url or "/" in model or "?" in model:
            raise ValueError("azure-openai needs base_url (your resource) and a plain deployment name")
    elif "?" in model:
        raise ValueError("a plain model name is needed")

    def call(prompt: str, rec: Provenance) -> str:
        if route == "github-models":
            url = (base_url or "https://models.github.ai/inference").rstrip("/") + "/chat/completions"
            return _chat_call(model, prompt, rec, url, {"authorization": "Bearer " + api_key,
                                                        "accept": "application/vnd.github+json"},
                              timeout_s, max_tokens, max_response_bytes, truncated_ok=truncated_ok)
        url = (f"{base_url.rstrip('/')}/openai/deployments/{urllib.parse.quote(model)}/chat/completions"
               f"?api-version={urllib.parse.quote(api_version)}")
        return _chat_call(model, prompt, rec, url, {"api-key": api_key}, timeout_s, max_tokens, max_response_bytes, send_model=False,
                          truncated_ok=truncated_ok)
    return _client("copilot-" + route, model, log, call)
