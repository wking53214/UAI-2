"""campaign (Python side): runs contracts/uai-interop-vectors.json through the Python reference and reports, per case,
what it did. The Node side is interop/node/campaign.mjs. Neither side reads an expectation: the test compares both
reports with the hand-written expectations and with each other.

    python interop/campaign.py            prints the Python report as JSON
"""

from __future__ import annotations

import base64
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cns.gate import _canonical, subject_digest  # noqa: E402

from cns_interop.decision import RemoteDecisionGuard  # noqa: E402
from cns_interop.envelope import Refused, check_profile, open_envelope  # noqa: E402
from cns_interop.ledger import MemoryLedger  # noqa: E402
from cns_interop.manifest import Capability  # noqa: E402
from cns_interop.negotiate import propose_terms  # noqa: E402
from cns_interop.revocation import RevocationStore  # noqa: E402
from cns_interop.trust import TrustPolicy  # noqa: E402
from cns_interop.wire import loads  # noqa: E402

VECTORS = ROOT / "contracts" / "uai-interop-vectors.json"


def _code(exc: BaseException) -> str:
    return exc.code if isinstance(exc, Refused) else f"internal:{type(exc).__name__}"


def _bytes(case: Dict[str, Any]) -> bytes:
    gen = case.get("generate")
    if gen == "exact_mib":
        return b'{"a":"' + b"x" * ((1 << 20) - 8) + b'"}'
    if gen == "over_mib":
        return b'{"a":"' + b"x" * ((1 << 20) - 7) + b'"}'
    return base64.b64decode(case["b64"])


def run_digest(case: Dict[str, Any]) -> Dict[str, Any]:
    try:
        v = loads(case["text"].encode("utf-8"))
        check_profile(v)
        return {"outcome": "ok", "canonical": _canonical(v), "sha256": subject_digest(v)}
    except Exception as exc:
        return {"outcome": "refuse", "code": _code(exc)}


def run_wire(case: Dict[str, Any]) -> Dict[str, Any]:
    try:
        loads(_bytes(case))
        return {"outcome": "ok"}
    except Exception as exc:
        return {"outcome": "refuse", "code": _code(exc)}


def run_envelope(case: Dict[str, Any]) -> Dict[str, Any]:
    try:
        wire = loads(case["text"].encode("utf-8"))
        open_envelope(wire, now=case["now"], audience=case["audience"],
                      kinds=set(case["kinds"]) if case["kinds"] else None)
        return {"outcome": "ok"}
    except Exception as exc:
        return {"outcome": "refuse", "code": _code(exc)}


def run_negotiation(case: Dict[str, Any]) -> Dict[str, Any]:
    try:
        raw = case["capability"]
        fields: Dict[str, Any] = {k: (tuple(v) if isinstance(v, list) else v) for k, v in raw.items()}
        cap = Capability(**fields)
        terms = propose_terms(cap, case["request"], decider=case["decider"], requester=case["requester"])
        return {"outcome": "ok", "terms": terms}
    except Exception as exc:
        return {"outcome": "refuse", "code": _code(exc)}


class _Receiver:
    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.cfg = cfg
        self.store = RevocationStore(Path(tempfile.mkdtemp()) / "r.db")
        self.ledger = MemoryLedger()
        self.trust = TrustPolicy(pinned=frozenset(cfg["pinned"]), revocations=self.store,
                                 max_staleness_ms=cfg["max_staleness_ms"], follow_rotation=cfg["follow_rotation"])


def run_sequence(case: Dict[str, Any]) -> Dict[str, Any]:
    rx, results = _Receiver(case["config"]), []
    for step in case["steps"]:
        try:
            if step["op"] == "receive":
                env = open_envelope(loads(step["text"].encode("utf-8")), now=step["now"], audience=rx.cfg["self"],
                                    kinds={"request"})
                rx.trust.admit(env.sender, now=step["now"])
                rx.ledger.spend(env.sender, env.id, env.expires_at, now=step["now"])
            elif step["op"] == "revocation":
                rx.store.accept(loads(step["text"].encode("utf-8")), authorities=rx.cfg["authorities"], now=step["now"])
            elif step["op"] == "fresh":
                rx.store.mark_fresh(step["now"])
            results.append("ok")
        except Exception as exc:
            results.append(_code(exc))
    return {"steps": results}


def run_decisions(case: Dict[str, Any]) -> Dict[str, Any]:
    cfg, clock, results = case["config"], [0], []
    ledger = MemoryLedger()

    def subject_of(artifact: object) -> Tuple[str, str]:
        pair: Any = artifact
        return str(pair[0]), str(pair[1])

    def new_guard() -> RemoteDecisionGuard:
        return RemoteDecisionGuard(subject_of, acting_for=cfg["acting_for"], capability=tuple(cfg["capability"]),
                                   trust=TrustPolicy(pinned=frozenset(cfg["pinned"])), ledger=ledger,
                                   clock=lambda: clock[0])

    guard = new_guard()
    for step in case["steps"]:
        clock[0] = step.get("now", clock[0])
        try:
            if step["op"] == "authorize":
                guard.authorize(step["decision"], terms=step["terms"], accept_digest=step["accept_digest"],
                                lease_ms=step["lease_ms"])
                results.append("ok")
            elif step["op"] == "use":
                results.append("true" if guard(step["artifact"]) else "false")
            elif step["op"] == "new_guard":
                guard = new_guard()
                results.append("ok")
            elif step["op"] == "revoke_decider":
                guard.revoke(cfg["pinned"][0])
                results.append("ok")
            elif step["op"] == "complete":
                guard.complete()
                results.append("ok")
        except Exception as exc:
            results.append(_code(exc))
    return {"steps": results}


GROUPS = {"digest": run_digest, "wire": run_wire, "envelope": run_envelope, "negotiation": run_negotiation,
          "sequences": run_sequence, "decisions": run_decisions}


def run_all(vectors: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {c["id"]: GROUPS[g](c) for g in GROUPS for c in vectors[g]}


if __name__ == "__main__":
    print(json.dumps(run_all(json.loads(VECTORS.read_text(encoding="utf-8")))))
