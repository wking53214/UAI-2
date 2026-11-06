"""UAI-2 Groq OpenAI-compatible HTTP adapter; stdlib only."""

import hashlib
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from cns_composition.providers.protocol import CompletionStatus, TokenUsage
from uai2_bridge import ProviderExecutionError, ProviderResult


@dataclass(frozen=True)
class GroqExecutionEvidence:
    provider: str
    model_requested: str
    model_reported: str | None
    request_sha256: str
    response_sha256: str | None
    latency_ms: int
    finish_reason: str
    request_id: str | None
    outcome: str = "success"
    error_category: str | None = None
    http_status: int | None = None


class GroqAdapter:
    MAX_RESPONSE_BYTES = 2_000_000

    def __init__(
        self, api_key, model, *,
        base_url="https://api.groq.com/openai/v1",
        timeout_s=30,
    ):
        if not isinstance(api_key, str) or not api_key.strip():
            raise ValueError("Groq API key is required")
        if not isinstance(model, str) or not model.strip():
            raise ValueError("Groq model is required")
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s
        self.last_evidence = None
        self._response_hash = None

    def __call__(self, prompt, max_output_tokens):
        body = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_output_tokens,
        }
        encoded = json.dumps(
            body, sort_keys=True, separators=(",", ":")
        ).encode()
        request_hash = hashlib.sha256(encoded).hexdigest()
        started = time.perf_counter()
        self.last_evidence = None
        self._response_hash = None

        try:
            return self._execute(encoded, request_hash)
        except ProviderExecutionError as exc:
            self.last_evidence = GroqExecutionEvidence(
                "groq", self._model, None, request_hash,
                self._response_hash,
                int((time.perf_counter() - started) * 1000),
                "ERROR", None, "failure", exc.category,
                getattr(exc, "http_status", None),
            )
            raise

    def _execute(self, encoded, request_hash):
        req = urllib.request.Request(
            f"{self._base_url}/chat/completions",
            data=encoded,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
                "User-Agent": "STACK-UAI2-Provider/1.0",
            },
            method="POST",
        )

        started = time.perf_counter()
        try:
            with urllib.request.urlopen(
                req, timeout=self._timeout_s
            ) as response:
                raw = response.read(self.MAX_RESPONSE_BYTES + 1)
                if len(raw) > self.MAX_RESPONSE_BYTES:
                    raise ProviderExecutionError(
                        "response_too_large",
                        "Groq response exceeded size limit",
                    )
                status = response.status
        except urllib.error.HTTPError as exc:
            category = {
                401: "authentication",
                403: "permission",
                429: "rate_limit",
            }.get(exc.code, "http_error")
            error = ProviderExecutionError(
                category, f"Groq HTTP status {exc.code}"
            )
            error.http_status = exc.code
            raise error from None
        except urllib.error.URLError:
            raise ProviderExecutionError(
                "connection_error", "Groq connection failed"
            ) from None
        except TimeoutError:
            raise ProviderExecutionError(
                "timeout", "Groq request timed out"
            ) from None

        if not 200 <= status < 300:
            raise ProviderExecutionError(
                "http_error", f"Groq HTTP status {status}"
            )

        self._response_hash = hashlib.sha256(raw).hexdigest()
        try:
            data = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProviderExecutionError(
                "invalid_response", "Groq returned invalid JSON"
            ) from None

        if not isinstance(data, dict):
            raise ProviderExecutionError(
                "invalid_response", "Groq response was not an object"
            )

        choices = data.get("choices")
        if (
            not isinstance(choices, list)
            or not choices
            or not isinstance(choices[0], dict)
        ):
            raise ProviderExecutionError(
                "invalid_response", "Groq returned no completion choice"
            )

        choice = choices[0]
        message = choice.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise ProviderExecutionError(
                "invalid_response", "Groq returned no text content"
            )

        finish = choice.get("finish_reason")
        if not isinstance(finish, str) or not finish:
            finish = "UNKNOWN"

        status_map = {
            "stop": CompletionStatus.COMPLETE,
            "length": CompletionStatus.MAX_TOKENS,
            "content_filter": CompletionStatus.STOPPED,
        }
        completion_status = status_map.get(
            finish, CompletionStatus.UNKNOWN
        )

        usage = None
        usage_data = data.get("usage")
        if isinstance(usage_data, dict):
            incoming = usage_data.get("prompt_tokens")
            outgoing = usage_data.get("completion_tokens")
            if (
                isinstance(incoming, int)
                and not isinstance(incoming, bool)
                and incoming >= 0
                and isinstance(outgoing, int)
                and not isinstance(outgoing, bool)
                and outgoing >= 0
            ):
                usage = TokenUsage(incoming, outgoing)

        reported_model = data.get("model")
        request_id = data.get("id")
        self.last_evidence = GroqExecutionEvidence(
            "groq", self._model,
            reported_model if isinstance(reported_model, str) else None,
            request_hash, self._response_hash,
            int((time.perf_counter() - started) * 1000), finish,
            request_id if isinstance(request_id, str) else None,
        )

        return ProviderResult(
            content=content,
            provider="groq",
            model=self._model,
            completion_status=completion_status,
            usage=usage,
            request_id=request_id if isinstance(request_id, str) else None,
            native_response={
                "finish_reason": finish,
                "model_reported": (
                    reported_model if isinstance(reported_model, str) else None
                ),
            },
        )
