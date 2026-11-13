"""policy_reference.py: the Python reference for docs/interop/POLICY_CHAIN_SPEC.md, run through the REAL chain.

One JSON request per line on stdin, one JSON answer per line on stdout (the protocol is in the spec):

    {"doc": {...}, "answer_b64": "<base64 of the model's answer bytes>"}
    -> {"refused": true}   |   {"verdict": "pass|retry|terminal_breach", "evidence": ["threshold-check"] | []}

The answer goes through `AdapterJudge` exactly as a live provider's would: the strict reader (`parse_recommendation`), the decider's
policy (`live_providers.policy`), then the escalation rule. A crash is reported as {"refused": true, "crash": "<type>"} so a
comparison can show it instead of hiding it. Nothing here touches a network.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any, Dict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cns_interop.adapter import AdapterJudge, PromptedModelAdapter, ProviderInfo  # noqa: E402
from cns_interop.envelope import Refused  # noqa: E402
from live_providers import CAP, policy  # noqa: E402

SUBJECT = {"identity": "differential", "digest": "00" * 32}


def run(doc: Dict[str, Any], answer: bytes) -> Dict[str, Any]:
    judge = AdapterJudge(PromptedModelAdapter(CAP, lambda prompt: answer, ProviderInfo("ref", "ref", "ref", "provider")), policy)
    try:
        j = judge(CAP, dict(doc), dict(SUBJECT))
    except Refused:
        return {"refused": True}
    except Exception as exc:  # reported, never hidden
        return {"refused": True, "crash": type(exc).__name__}
    return {"verdict": j.verdict, "evidence": sorted(j.evidence)}


def main() -> int:
    for line in sys.stdin:
        req = json.loads(line)
        print(json.dumps(run(req["doc"], base64.b64decode(req["answer_b64"]))), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
