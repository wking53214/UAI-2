"""key_drill.py: a SIMULATED signing-key compromise drill, run against the real revocation and trust code.

    python interop/key_drill.py --out drill.json

Everything here is software on one machine with fixed throwaway keys and a simulated clock. It exercises `cns_interop.revocation`
and `cns_interop.trust` only. It is NOT an operational drill: no person is paged, no key is in a vault or an HSM, no real receiver
is told, and nothing here measures how long a real organisation takes. It shows what the code does in each order of events, so the
procedure in docs/KEY_CUSTODY.md can be written against facts instead of inference. Each scenario reports what it expected and what
happened; the exit status is 1 if any scenario's expectation fails.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cns_interop.envelope import Refused  # noqa: E402
from cns_interop.identity import Signer  # noqa: E402
from cns_interop.revocation import RevocationStore, revoke, rotate  # noqa: E402
from cns_interop.trust import TrustPolicy  # noqa: E402

# Fixed throwaway seeds: the report is the same on every run. These keys protect nothing.
AUTH, KEY, NEXT, FRESH, ATTACKER_NEXT = (Signer(bytes([i] * 32)) for i in (101, 102, 103, 104, 105))
T = 1_800_000_000_000


def _admit(policy: TrustPolicy, agent: str, t: int) -> str:
    """What a receiver does with a message from `agent` at time t: how it was admitted, or the refusal code."""
    try:
        return policy.admit(agent, now=t).via
    except Refused as exc:
        return exc.code


def _store(tmp: str, name: str) -> RevocationStore:
    return RevocationStore(Path(tmp) / f"{name}.db")


def planned_rotation(tmp: str) -> Dict[str, Any]:
    s = _store(tmp, "planned")
    pol = TrustPolicy(pinned=frozenset({KEY.agent}), revocations=s, follow_rotation=True)
    before = _admit(pol, KEY.agent, T)
    s.accept(rotate(KEY, NEXT.agent, reason="scheduled rotation", now=T).to_wire(), now=T)
    return {"expected": {"old_before": "pinned", "old_after": "untrusted", "new_after": "rotated"},
            "observed": {"old_before": before, "old_after": _admit(pol, KEY.agent, T + 1), "new_after": _admit(pol, NEXT.agent, T + 1)}}


def compromise_attacker_rotates_first_then_authority_revokes(tmp: str) -> Dict[str, Any]:
    s = _store(tmp, "c1")
    pol = TrustPolicy(pinned=frozenset({KEY.agent}), revocations=s, follow_rotation=True)
    s.accept(rotate(KEY, ATTACKER_NEXT.agent, reason="attacker", now=T).to_wire(), now=T)
    during = _admit(pol, ATTACKER_NEXT.agent, T + 1)
    s.accept(revoke(AUTH, KEY.agent, reason="compromised", now=T + 2).to_wire(), authorities=[AUTH.agent], now=T + 2)
    return {"expected": {"attacker_successor_during_window": "rotated", "attacker_successor_after_revoke": "untrusted",
                         "stolen_key_after_revoke": "untrusted"},
            "observed": {"attacker_successor_during_window": during, "attacker_successor_after_revoke": _admit(pol, ATTACKER_NEXT.agent, T + 3),
                         "stolen_key_after_revoke": _admit(pol, KEY.agent, T + 3)}}


def compromise_authority_revokes_before_attacker_rotates(tmp: str) -> Dict[str, Any]:
    s = _store(tmp, "c2")
    pol = TrustPolicy(pinned=frozenset({KEY.agent}), revocations=s, follow_rotation=True)
    s.accept(revoke(AUTH, KEY.agent, reason="compromised", now=T).to_wire(), authorities=[AUTH.agent], now=T)
    s.accept(rotate(KEY, ATTACKER_NEXT.agent, reason="attacker, too late", now=T + 1).to_wire(), now=T + 1)
    return {"expected": {"attacker_successor": "untrusted", "stolen_key": "untrusted"},
            "observed": {"attacker_successor": _admit(pol, ATTACKER_NEXT.agent, T + 2), "stolen_key": _admit(pol, KEY.agent, T + 2)}}


def attacker_rotation_first_blocks_the_owners_real_rotation(tmp: str) -> Dict[str, Any]:
    """The owner notices late: the attacker has already rotated. The owner's own rotate to the real successor is the first
    thing they try. A receiver keeps the first statement for a subject, so it does not take effect."""
    s = _store(tmp, "c3")
    pol = TrustPolicy(pinned=frozenset({KEY.agent}), revocations=s, follow_rotation=True)
    s.accept(rotate(KEY, ATTACKER_NEXT.agent, reason="attacker", now=T).to_wire(), now=T)
    s.accept(rotate(KEY, NEXT.agent, reason="the owner's real rotation", now=T + 1).to_wire(), now=T + 1)
    return {"expected": {"real_successor_admitted": "untrusted", "attacker_successor_admitted": "rotated"},
            "observed": {"real_successor_admitted": _admit(pol, NEXT.agent, T + 2), "attacker_successor_admitted": _admit(pol, ATTACKER_NEXT.agent, T + 2)},
            "note": "first statement wins: until an authority revokes, the attacker's successor is the one followed"}


def the_owners_own_revoke_does_not_withdraw_the_attackers_successor(tmp: str) -> Dict[str, Any]:
    """Only an authority's revoke withdraws a successor the key named. The key revoking itself does not."""
    s = _store(tmp, "c4")
    pol = TrustPolicy(pinned=frozenset({KEY.agent}), revocations=s, follow_rotation=True)
    s.accept(rotate(KEY, ATTACKER_NEXT.agent, reason="attacker", now=T).to_wire(), now=T)
    s.accept(revoke(KEY, KEY.agent, reason="the owner revoking its own key", now=T + 1).to_wire(), now=T + 1)
    return {"expected": {"attacker_successor_after_self_revoke": "rotated"},
            "observed": {"attacker_successor_after_self_revoke": _admit(pol, ATTACKER_NEXT.agent, T + 2)},
            "note": "a self-revoke cannot end this incident; an authority the receiver lists must revoke"}


def recovery_by_pinning_a_fresh_identity(tmp: str) -> Dict[str, Any]:
    s = _store(tmp, "c5")
    s.accept(rotate(KEY, ATTACKER_NEXT.agent, reason="attacker", now=T).to_wire(), now=T)
    s.accept(revoke(AUTH, KEY.agent, reason="compromised", now=T + 1).to_wire(), authorities=[AUTH.agent], now=T + 1)
    recovered = TrustPolicy(pinned=frozenset({FRESH.agent}), revocations=s, follow_rotation=True)
    return {"expected": {"stolen_key": "untrusted", "attacker_successor": "untrusted", "fresh_identity_pinned_out_of_band": "pinned"},
            "observed": {"stolen_key": _admit(recovered, KEY.agent, T + 2), "attacker_successor": _admit(recovered, ATTACKER_NEXT.agent, T + 2),
                         "fresh_identity_pinned_out_of_band": _admit(recovered, FRESH.agent, T + 2)},
            "note": "recovery after compromise is a new identity pinned by each receiver, not a rotation"}


def a_receiver_that_does_not_list_the_authority_cannot_be_told(tmp: str) -> Dict[str, Any]:
    s = _store(tmp, "c6")
    pol = TrustPolicy(pinned=frozenset({KEY.agent}), revocations=s)
    try:
        s.accept(revoke(AUTH, KEY.agent, reason="compromised", now=T).to_wire(), authorities=[], now=T)
        accepted = "accepted"
    except Refused as exc:
        accepted = exc.code
    return {"expected": {"revoke_from_unlisted_authority": "untrusted", "stolen_key_still": "pinned"},
            "observed": {"revoke_from_unlisted_authority": accepted, "stolen_key_still": _admit(pol, KEY.agent, T + 1)},
            "note": "the authority must be configured on every receiver before the incident"}


def a_receiver_that_never_got_the_revocation_keeps_trusting_the_key(tmp: str) -> Dict[str, Any]:
    """Distribution is not provided (KEY_CUSTODY.md Part 1, OPEN). Two receivers; only one is told."""
    told, not_told = _store(tmp, "told"), _store(tmp, "not_told")
    told.accept(revoke(AUTH, KEY.agent, reason="compromised", now=T).to_wire(), authorities=[AUTH.agent], now=T)
    a = TrustPolicy(pinned=frozenset({KEY.agent}), revocations=told)
    b = TrustPolicy(pinned=frozenset({KEY.agent}), revocations=not_told)
    return {"expected": {"receiver_told": "untrusted", "receiver_not_told": "pinned"},
            "observed": {"receiver_told": _admit(a, KEY.agent, T + 1), "receiver_not_told": _admit(b, KEY.agent, T + 1)},
            "note": "nothing in the software carries the revocation to a receiver; that is the operator's channel"}


def a_stale_list_refuses_instead_of_trusting(tmp: str) -> Dict[str, Any]:
    s = _store(tmp, "stale")
    pol = TrustPolicy(pinned=frozenset({KEY.agent}), revocations=s, max_staleness_ms=60_000)
    never = _admit(pol, KEY.agent, T)
    s.mark_fresh(T)
    fresh = _admit(pol, KEY.agent, T + 30_000)
    stale = _admit(pol, KEY.agent, T + 120_000)
    return {"expected": {"never_refreshed": "unavailable", "fresh": "pinned", "stale": "unavailable"},
            "observed": {"never_refreshed": never, "fresh": fresh, "stale": stale},
            "note": "off unless the receiver sets max_staleness_ms"}


SCENARIOS: List[Callable[[str], Dict[str, Any]]] = [
    planned_rotation, compromise_attacker_rotates_first_then_authority_revokes, compromise_authority_revokes_before_attacker_rotates,
    attacker_rotation_first_blocks_the_owners_real_rotation, the_owners_own_revoke_does_not_withdraw_the_attackers_successor,
    recovery_by_pinning_a_fresh_identity, a_receiver_that_does_not_list_the_authority_cannot_be_told,
    a_receiver_that_never_got_the_revocation_keeps_trusting_the_key, a_stale_list_refuses_instead_of_trusting,
]


def run() -> Dict[str, Any]:
    out = []
    with tempfile.TemporaryDirectory() as tmp:
        for fn in SCENARIOS:
            res = fn(tmp)
            res = {"scenario": fn.__name__, **res, "ok": res["expected"] == res["observed"]}
            out.append(res)
    return {"kind": "SIMULATED key-compromise drill; not operational", "scenarios": out, "ok": all(s["ok"] for s in out)}


def main(argv: Any = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="", help="write the machine-readable report here")
    opts = ap.parse_args(argv)
    rep = run()
    text = json.dumps(rep, indent=2, sort_keys=True) + "\n"
    if opts.out:
        Path(opts.out).write_text(text, encoding="utf-8")
    for s in rep["scenarios"]:
        print(("PASS " if s["ok"] else "FAIL ") + s["scenario"])
        if not s["ok"]:
            print("   expected", s["expected"], "\n   observed", s["observed"])
    print("ok" if rep["ok"] else "FAILED")
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
