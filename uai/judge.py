"""judge: a model's recommendation on its way to a signed UAI-1 decision, with the record of the call bound into it.

`ProviderJudge` is the `Judge` a `cns_interop.session.Decider` takes. It is `cns_interop.adapter.AdapterJudge` (the
strict reader, then the decider's own policy) with one addition: when the capability lists the evidence kind
`provider-call`, a pass carries what this process recorded about the provider call that produced the recommendation,
so the signed decision says which provider and model were asked and gives the digests of the request sent and the
answer read.

WHO WRITES THAT EVIDENCE. This process, never the model. The model is shown the capability without `provider-call`, so
the strict reader refuses an answer that claims it, like any evidence kind the capability does not produce.

WHAT IT PROVES. That the decider says this is the exchange it had. No provider signs its answers, so a verifier learns
what the decider attests and can compare it with the decider's own provenance log; it is not proof against a decider
that lies. Only a pass carries evidence (UAI-1 sends none with any other verdict), so the record of a refused or
lowered recommendation stays in the provenance log.
"""

from __future__ import annotations

import dataclasses
import threading
from typing import Any, Dict

from cns.gate import GateOutcome

from cns_interop.adapter import AdapterJudge, PromptedModelAdapter, ProviderInfo
from cns_interop.envelope import Refused
from cns_interop.session import Judgment

__all__ = ["PROVIDER_CALL", "ProviderJudge"]

#: The evidence kind a capability lists to have the provider call's record signed into a pass.
PROVIDER_CALL = "provider-call"


class ProviderJudge:
    def __init__(self, connection: Any, policy: Any) -> None:
        self._connection, self._policy, self._lock = connection, policy, threading.Lock()
        self.info = ProviderInfo(agent="uai", provider=connection.provider, model=connection.model, kind="provider",
                                 live=False)

    def __call__(self, capability: Any, disclosed: Dict[str, Any], subject: Dict[str, str]) -> Judgment:
        shown = dataclasses.replace(capability, evidence=tuple(k for k in capability.evidence if k != PROVIDER_CALL))
        log = self._connection.log
        inner = AdapterJudge(PromptedModelAdapter(shown, self._connection.complete, self.info), self._policy,
                             observer=log.observer())
        with self._lock:  # one call at a time, so the record read below is this call's
            seen = len(log.records)
            judgment = inner(shown, disclosed, subject)
            made = log.records[seen:]
        if judgment.verdict != GateOutcome.PASS.value or PROVIDER_CALL not in capability.evidence:
            return judgment
        if len(made) != 1 or made[0].call != "ok":
            raise Refused("adapter_output", "a pass needs the record of exactly one provider call, and there is none")
        rec = made[0]
        evidence = {k: dict(v) for k, v in judgment.evidence.items() if k != PROVIDER_CALL}
        evidence[PROVIDER_CALL] = {"provider": rec.provider, "model_requested": rec.model_requested,
                                   "model_reported": rec.model_reported, "request_sha256": rec.request_sha256,
                                   "response_sha256": rec.response_sha256, "finish_reason": rec.finish_reason}
        return Judgment(judgment.verdict, judgment.reasons, evidence)
