"""live_providers.py: run ONE real exchange through each provider that has a key, and write the evidence.

    UAI_ANTHROPIC_API_KEY=... ANTHROPIC_MODEL=...  GEMINI_API_KEY=... GEMINI_MODEL=...
    OPENAI_API_KEY=... OPENAI_MODEL=...  GITHUB_MODELS_TOKEN=... COPILOT_MODEL=openai/gpt-4.1  python interop/live_providers.py --out evidence.json

The Anthropic key is read from UAI_ANTHROPIC_API_KEY first and from ANTHROPIC_API_KEY when that is empty or unset (some hosts
reserve ANTHROPIC_API_KEY for themselves). A provider with no key is reported as NOT EXECUTED and is never counted. If NOTHING was executed the exit status is 3, so a
script or a CI job cannot mistake "no keys" for "passed". Nothing here is a stub: the base URLs are the providers' own, and
`ProviderInfo.live` is set only after a call really returned and its output was read by the strict parser. The model never
receives a signer, a ledger, a grant or an approval, and what it returns is a recommendation that the decider's policy may
lower and that no grant has to honor.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cns_interop.adapter import AdapterJudge, PromptedModelAdapter, ProviderInfo, Recommendation  # noqa: E402
from cns_interop.manifest import Capability  # noqa: E402
from cns_interop.providers import ProvenanceLog, anthropic_complete, copilot_complete, gemini_complete, openai_complete  # noqa: E402

CAP = Capability(name="income-screen", version=1, summary="monthly income at or above 450000 cents",
                 accepts=("doc_type", "monthly_income_cents"), requires=("doc_type", "monthly_income_cents"),
                 evidence=("threshold-check",), max_ttl_ms=120_000)

# A live call waits up to this long. Current models think before answering, and a slow Opus answer is not a provider failure.
LIVE_TIMEOUT_S = 120.0


def policy(cap: Any, disclosed: Dict[str, Any], subject: Any, rec: Recommendation) -> Recommendation:
    clears = disclosed.get("doc_type") in ("paystub", "tax-return") and disclosed.get("monthly_income_cents", 0) >= 450_000
    if rec.verdict == "pass" and not clears:
        return Recommendation("retry", rec.reasons + ("the decider's policy re-checked and it does not clear",), {})
    return rec


def run_one(name: str, complete: Any, log: ProvenanceLog, model: str) -> Dict[str, Any]:
    judge = AdapterJudge(PromptedModelAdapter(CAP, complete, ProviderInfo("live", name, model, "provider", live=False)),
                         policy, observer=log.observer())
    out: Dict[str, Any] = {"provider": name, "model": model, "executed": True}
    for label, income in (("clears", 512_000), ("below", 100_000)):
        try:
            j = judge(CAP, {"doc_type": "paystub", "monthly_income_cents": income}, {"identity": "live-demo", "digest": "00" * 32})
            out[label] = {"verdict": j.verdict, "reasons": list(j.reasons)}
        except Exception as exc:  # a refusal is a result: the strict reader said no
            out[label] = {"refused": f"{getattr(exc, 'code', type(exc).__name__)}: {getattr(exc, 'reason', exc)}"[:300]}
    out["live"] = any(r.call == "ok" for r in log.records)
    out["provenance"] = [r.__dict__ for r in log.records]
    return out


def main(argv: List[str]) -> int:
    results: List[Dict[str, Any]] = []
    for name, key_vars, model_var, make in (("anthropic", ("UAI_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"), "ANTHROPIC_MODEL",
                                             anthropic_complete),
                                            ("google", ("GEMINI_API_KEY",), "GEMINI_MODEL", gemini_complete),
                                            ("openai", ("OPENAI_API_KEY",), "OPENAI_MODEL", openai_complete),
                                            ("copilot-github-models", ("GITHUB_MODELS_TOKEN",), "COPILOT_MODEL", copilot_complete)):
        key_var = " or ".join(key_vars)
        # the first variable that holds a key wins; a pasted key often ends in a newline
        key = next((v for v in (os.environ.get(n, "").strip() for n in key_vars) if v), "")
        model = os.environ.get(model_var, "")
        if not key or not model:
            print(f"NOT EXECUTED: {name} (set {key_var} and {model_var})")
            results.append({"provider": name, "executed": False})
            continue
        log = ProvenanceLog()
        results.append(run_one(name, make(key, model, log, timeout_s=LIVE_TIMEOUT_S), log, model))
        print(f"EXECUTED: {name} live={results[-1]['live']} clears={results[-1].get('clears')}")
    if "--out" in argv:
        Path(argv[argv.index("--out") + 1]).write_text(json.dumps(results, indent=1, sort_keys=True) + "\n")
    return 0 if any(r["executed"] for r in results) else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
