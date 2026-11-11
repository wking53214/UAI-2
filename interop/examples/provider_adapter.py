"""provider_adapter.py: plug a model provider into a decider through the adapter boundary.

    python interop/examples/provider_adapter.py

Reads OPENAI_API_KEY/OPENAI_MODEL, ANTHROPIC_API_KEY/ANTHROPIC_MODEL, GEMINI_API_KEY/GEMINI_MODEL or
GITHUB_MODELS_TOKEN/COPILOT_MODEL. With none set it says NOT EXECUTED and runs a LOCAL STAND-IN that answers in the same
strict shape, so you can see the flow without pretending a provider was called. The model only RECOMMENDS: the strict reader
refuses anything beyond verdict, reasons, evidence and escalate, and the decider's own policy may lower the recommendation.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cns_interop.adapter import AdapterJudge, PromptedModelAdapter, ProviderInfo, Recommendation  # noqa: E402
from cns_interop.manifest import Capability  # noqa: E402
from cns_interop.providers import (ProvenanceLog, anthropic_complete, copilot_complete, gemini_complete,  # noqa: E402
                                   openai_complete)

CAP = Capability(name="income-screen", version=1, summary="monthly income at or above 4500.00",
                 accepts=("doc_type", "monthly_income_cents"), requires=("doc_type", "monthly_income_cents"),
                 evidence=("threshold-check",), max_ttl_ms=120_000)
PROVIDERS = (("openai", "OPENAI_API_KEY", "OPENAI_MODEL", openai_complete),
             ("anthropic", "ANTHROPIC_API_KEY", "ANTHROPIC_MODEL", anthropic_complete),
             ("google", "GEMINI_API_KEY", "GEMINI_MODEL", gemini_complete),
             ("copilot-github-models", "GITHUB_MODELS_TOKEN", "COPILOT_MODEL", copilot_complete))


def policy(cap, disclosed, subject, rec: Recommendation) -> Recommendation:
    """The decider's own rule. A model's 'pass' is only a recommendation: it is re-checked here."""
    clears = disclosed.get("monthly_income_cents", 0) >= 450_000
    if rec.verdict == "pass" and not clears:
        return Recommendation("retry", rec.reasons + ("the decider's policy re-checked and it does not clear",), {})
    return rec


def stand_in(prompt: str) -> str:
    """NOT a provider. A local function that answers in the strict shape a real model is asked to."""
    return json.dumps({"verdict": "pass", "reasons": ["stand-in"], "evidence": {"threshold-check": {"observed_cents": 512000}},
                       "escalate": False})


def main() -> int:
    log = ProvenanceLog()
    complete, label, model, live = stand_in, "local-stand-in", "none", False
    for name, key_var, model_var, make in PROVIDERS:
        if os.environ.get(key_var) and os.environ.get(model_var):
            complete, label, model, live = make(os.environ[key_var], os.environ[model_var], log), name, os.environ[model_var], True
            break
        print(f"NOT EXECUTED: {name} (set {key_var} and {model_var})")
    judge = AdapterJudge(PromptedModelAdapter(CAP, complete, ProviderInfo("example", label, model, "provider", live=False)),
                         policy, observer=log.observer())
    j = judge(CAP, {"doc_type": "paystub", "monthly_income_cents": 512_000}, {"identity": "loan-17", "digest": "00" * 32})
    print(f"source: {label} (live provider call: {live}); recommendation became verdict: {j.verdict}")
    for rec in log.records:
        print("provenance:", rec.provider, rec.model_requested, rec.call, rec.outcome)
    return 0


if __name__ == "__main__":
    sys.exit(main())
