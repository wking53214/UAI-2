"""preauth benchmark: what an unauthenticated message costs a UAI-1 receiver, and what the T2 controls change.

    python interop/bench/preauth.py                 print the table
    python interop/bench/preauth.py --out FILE      also write the results as JSON
    python interop/bench/preauth.py --quick         fewer samples (the test uses this)

METHOD. Single thread, one process, `time.perf_counter`. Each figure is the MEDIAN of `n` timed calls (n is printed). Inputs are
built before the clock starts. The unknown-sender flood sends well-formed, correctly signed requests from fresh keys: the
cheapest message for an attacker that still costs a verification. Hardware and runtime are recorded with the results. These are
CPU costs of one receiver core on a shared virtual machine, not network throughput, and not the cost of a real transport.
Nothing here weakens verification: the controls only decide whether to spend it.
"""

from __future__ import annotations

import json
import os
import platform
import statistics as st
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from cns_interop import crypto_backend as cb  # noqa: E402
from cns_interop.disclosure import commit  # noqa: E402
from cns_interop.envelope import Refused, open_envelope, seal  # noqa: E402
from cns_interop.identity import Signer  # noqa: E402
from cns_interop.limits import RateLimiter  # noqa: E402
from cns_interop.manifest import Capability  # noqa: E402
from cns_interop.negotiate import request_body  # noqa: E402
from cns_interop.session import Decider, Judgment  # noqa: E402
from cns_interop.trust import TrustPolicy  # noqa: E402
from cns_interop.wire import loads  # noqa: E402

CAP = Capability(name="income-screen", version=1, summary="s", accepts=("monthly_income_cents",),
                 requires=("monthly_income_cents",), evidence=("threshold-check",), max_ttl_ms=60_000)


def median_ms(fn: Callable[[], Any], n: int) -> Dict[str, float]:
    xs = []
    for _ in range(n):
        t = time.perf_counter()
        try:
            fn()
        except Refused:
            pass
        xs.append((time.perf_counter() - t) * 1000)
    return {"median_ms": round(st.median(xs), 4), "n": n}


def run(quick: bool = False) -> Dict[str, Any]:
    n = 30 if quick else 200
    out: Dict[str, Any] = {"context": {"python": platform.python_version(), "platform": platform.platform(),
                                       "cpus": os.cpu_count(), "quick": quick}}
    me, known = Signer.generate(), Signer.generate()
    body = request_body(CAP.name, 1, identity="d", digest=commit("d", {"monthly_income_cents": 5}).digest,
                        offer_fields=["monthly_income_cents"], require_evidence=["threshold-check"], max_ttl_ms=1000)
    for backend in ("pure", "cryptography"):
        cb.use(backend)
        strangers = [Signer.generate() for _ in range(40)]
        msgs = [seal(strangers[i % 40], "request", body, to=me.agent, ttl_ms=60_000).to_wire() for i in range(n)]

        def decider(mode: str, **kw: Any) -> Decider:
            return Decider(me, name="d", implementation="bench", capabilities=[(CAP, lambda c, d, s: Judgment("retry"))],
                           trust=TrustPolicy(pinned=frozenset({known.agent})), unknown_sender=mode, **kw)

        it = iter(msgs * 3)
        refuse, drop = decider("refuse"), decider("drop")
        r: Dict[str, Any] = {}
        r["unknown sender, signed refusal (revision 2 behavior)"] = median_ms(lambda: refuse.handle(next(it)), n)
        r["unknown sender, dropped (revision 3 default)"] = median_ms(lambda: drop.handle(next(it)), n)
        valid = seal(known, "request", body, to=me.agent, ttl_ms=60_000).to_wire()
        r["valid envelope, parse and verify"] = median_ms(lambda: open_envelope(loads(json.dumps(valid))), n)
        big = {"a": [1] * 350_000}
        wire = {**valid, "body": big}
        r["1 MiB list of small integers, no node bound (revision 2)"] = median_ms(lambda: open_envelope(wire), 3)
        r["1 MiB list of small integers, max_nodes=20000 (revision 3)"] = median_ms(
            lambda: open_envelope(wire, max_nodes=20_000), 3)
        out[backend] = r
    cb.use("pure")
    flood = RateLimiter(global_rate=100, global_burst=50, sender_rate=10, sender_burst=5, clock=lambda: 0)
    passed = sum(flood.allow(f"uai:ed25519:{i:064x}") for i in range(5000))  # 5000 messages, 5000 claimed identities, one instant
    out["rate limiter"] = {"messages": 5000, "claimed_identities": 5000, "let_through": passed, "global_burst": 50}
    return out


def main(argv: list) -> int:
    res = run("--quick" in argv)
    print(f"python {res['context']['python']} on {res['context']['platform']} ({res['context']['cpus']} cpus)")
    for backend in ("pure", "cryptography"):
        print(f"[{backend}]")
        for k, v in res[backend].items():
            print(f"  {k:62} median {v['median_ms']:9.4f} ms   n={v['n']}")
    print("rate limiter:", res["rate limiter"])
    if "--out" in argv:
        Path(argv[argv.index("--out") + 1]).write_text(json.dumps(res, indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
