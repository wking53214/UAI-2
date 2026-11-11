"""connect: the one way in. Name a provider and a model; the key is read from the environment.

    import uai
    model = uai.connect("groq", "llama-3.3-70b-versatile")     # reads GROQ_API_KEY
    judge = model.judge(policy)                                 # for a UAI-1 Decider: the decision leaves signed
    typed = model.model_provider()                              # or: plain text behind the typed contract

WHAT IS DELIBERATE HERE

  * The provider is always named, in code or in UAI_PROVIDER. Nothing is inferred from whichever key happens to be
    set: a key left in a shell would otherwise decide, silently, which company a document is sent to.
  * The key is read from the environment and handed straight to the provider client. It lives inside that client's
    closure and nowhere else: not in a field of the object returned (so not in its repr), not in any record, and not
    in any error raised here.
  * A model reached this way RECOMMENDS. `judge()` reads its answer with the strict reader, hands it to the decider's
    own policy, and never gives the model a signer, a ledger, a grant or an approval. `ProviderInfo.live` is False
    here always: only `interop/live_providers.py`, after a real call returned, may say otherwise.

All provider code is `cns_interop.providers`; this module only chooses among its clients.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from cns_interop import providers as _p
from cns_interop.providers import ProvenanceLog

from .bridge import PORTABLE_MAX_OUTPUT_TOKENS, PortableTextProvider, ProviderResult
from .protocol import CompletionStatus, TokenUsage

__all__ = ["PROVIDERS", "Connection", "connect", "from_env"]


@dataclass(frozen=True)
class _Spec:
    label: str                       # the name written in provenance records
    key_vars: Tuple[str, ...]        # the first one that holds a key is used
    make: Callable[..., Callable[[str], str]]
    extra: Tuple[Tuple[str, str], ...] = ()   # (client argument, environment variable) pairs that are needed as well
    fixed: Tuple[Tuple[str, Any], ...] = ()   # client arguments this entry always passes
    reports_finish: bool = True      # the provider says why an answer ended


#: The providers `connect` knows, by the name a caller gives. Adding one means a client in cns_interop.providers and a row here.
PROVIDERS: Mapping[str, _Spec] = {
    "anthropic": _Spec("anthropic", ("UAI_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"), _p.anthropic_complete),
    "gemini": _Spec("google", ("GEMINI_API_KEY",), _p.gemini_complete),
    "openai": _Spec("openai", ("OPENAI_API_KEY",), _p.openai_complete),
    "copilot": _Spec("copilot-github-models", ("GITHUB_MODELS_TOKEN",), _p.copilot_complete),
    "copilot-azure": _Spec("copilot-azure-openai", ("AZURE_OPENAI_API_KEY",), _p.copilot_complete,
                           extra=(("base_url", "AZURE_OPENAI_ENDPOINT"),), fixed=(("route", "azure-openai"),)),
    "groq": _Spec("groq", ("GROQ_API_KEY",), _p.groq_complete),
    "cloudflare": _Spec("cloudflare-workers-ai", ("CLOUDFLARE_API_TOKEN",), _p.cloudflare_complete,
                        extra=(("account_id", "CLOUDFLARE_ACCOUNT_ID"),), reports_finish=False),
}

_COMPLETE = {"end_turn", "STOP", "stop"}
_CUT_OFF = {"max_tokens", "MAX_TOKENS", "length"}


@dataclass(frozen=True)
class Connection:
    """One provider and one model, ready to use. `complete(prompt) -> text` is the strict client: an answer that did not
    end normally is refused, never returned. `log` holds the provenance record of every call made through this object."""

    name: str
    provider: str
    model: str
    complete: Callable[[str], str]
    log: ProvenanceLog
    _build: Callable[..., Callable[[str], str]] = field(repr=False, compare=False)

    def judge(self, policy: Any) -> Any:
        """The `Judge` a UAI-1 `Decider` takes beside a capability: this model recommends, `policy` decides."""
        from .judge import ProviderJudge

        return ProviderJudge(self, policy)

    def model_provider(self) -> PortableTextProvider:
        """This provider behind the typed contract (`uai.protocol.ModelProvider`), in the portable profile.

        Text, not a decision: an answer cut off at the token limit is returned with `CompletionStatus.MAX_TOKENS`
        instead of being refused. Any other abnormal ending is still an error."""
        log, lock = ProvenanceLog(), threading.Lock()
        text_of = self._build(log, max_tokens=PORTABLE_MAX_OUTPUT_TOKENS, truncated_ok=True)

        def complete(prompt: str, max_output_tokens: int) -> ProviderResult:
            if max_output_tokens != PORTABLE_MAX_OUTPUT_TOKENS:
                raise ValueError("the portable profile sends exactly 512 output tokens")
            with lock:
                try:
                    text = text_of(prompt)
                    rec = log.records[-1]
                finally:
                    del log.records[:]  # the bridge keeps nothing between calls
            if rec.finish_reason in _COMPLETE:
                status = CompletionStatus.COMPLETE
            elif rec.finish_reason in _CUT_OFF:
                status = CompletionStatus.MAX_TOKENS
            else:
                status = CompletionStatus.UNKNOWN  # the provider did not say (Workers AI never does)
            usage = None
            if rec.input_tokens is not None and rec.output_tokens is not None:
                usage = TokenUsage(rec.input_tokens, rec.output_tokens)
            return ProviderResult(content=text, provider=self.provider, model=self.model, completion_status=status,
                                  usage=usage, request_id=rec.request_id or None,
                                  native_response={"finish_reason": rec.finish_reason, "model_reported": rec.model_reported,
                                                   "request_sha256": rec.request_sha256,
                                                   "response_sha256": rec.response_sha256})

        return PortableTextProvider(complete, self.provider, self.model)


def _first(env: Mapping[str, str], names: Tuple[str, ...]) -> str:
    # a pasted key often ends in a newline; anything odd inside the key is refused by the client, which never shows it
    return next((v for v in (str(env.get(n, "")).strip() for n in names) if v), "")


def connect(provider: str, model: str, *, environ: Optional[Mapping[str, str]] = None, log: Optional[ProvenanceLog] = None,
            timeout_s: Optional[float] = None, base_url: Optional[str] = None) -> Connection:
    """Connect to `provider` (one of `PROVIDERS`) and `model`. The key comes from the provider's environment variable.

    Raises ValueError, naming the variable to set and never a key, when the provider is unknown, the model is empty, or
    something it needs is missing. No request is made here."""
    env = os.environ if environ is None else environ
    name = provider.strip().lower() if isinstance(provider, str) else ""
    spec = PROVIDERS.get(name)
    if spec is None:
        raise ValueError("unknown provider; expected one of: " + ", ".join(sorted(PROVIDERS)))
    if not isinstance(model, str) or not model.strip():
        raise ValueError("a model name is needed")
    model = model.strip()
    key = _first(env, spec.key_vars)
    if not key:
        raise ValueError(f"no key for {name}: set {' or '.join(spec.key_vars)}")
    options: Dict[str, Any] = dict(spec.fixed)
    for argument, variable in spec.extra:
        value = base_url if argument == "base_url" and base_url else str(env.get(variable, "")).strip()
        if not value:
            raise ValueError(f"{name} also needs {variable}")
        options[argument] = value
    if base_url and "base_url" not in options:
        options["base_url"] = base_url
    if timeout_s is not None:
        options["timeout_s"] = timeout_s

    def build(to: ProvenanceLog, *, max_tokens: Optional[int] = None, truncated_ok: bool = False) -> Callable[[str], str]:
        extra: Dict[str, Any] = dict(options)
        if max_tokens is not None:
            extra["max_tokens"] = max_tokens
        if truncated_ok and spec.reports_finish:
            extra["truncated_ok"] = True
        return spec.make(key, model, to, **extra)

    log = log if log is not None else ProvenanceLog()
    return Connection(name=name, provider=spec.label, model=model, complete=build(log), log=log, _build=build)


def _one(env: Mapping[str, str], names: Tuple[str, str]) -> str:
    values = {str(env.get(n, "")).strip() for n in names} - {""}
    if len(values) > 1:
        raise ValueError(f"{names[0]} and {names[1]} are both set and disagree; set one")
    return values.pop() if values else ""


def from_env(environ: Optional[Mapping[str, str]] = None, *, log: Optional[ProvenanceLog] = None) -> Connection:
    """`connect`, with the provider and the model read from UAI_PROVIDER and UAI_MODEL.

    UAI2_PROVIDER and UAI2_MODEL, the names the UAI-2 factory read, are accepted as the same two settings."""
    env = os.environ if environ is None else environ
    provider = _one(env, ("UAI_PROVIDER", "UAI2_PROVIDER"))
    if not provider:
        raise ValueError("UAI_PROVIDER is not set; expected one of: " + ", ".join(sorted(PROVIDERS)))
    model = _one(env, ("UAI_MODEL", "UAI2_MODEL"))
    if not model:
        raise ValueError("UAI_MODEL is not set")
    return connect(provider, model, environ=env, log=log)
