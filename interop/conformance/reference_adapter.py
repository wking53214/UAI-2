"""The Python reference's side of the UAI-1 conformance protocol (see contracts/uai1/README.md).

Reads one JSON request per line on stdin, writes one JSON answer per line on stdout. Any independent implementation
exposes the same two operations and can then be checked with contracts/uai1/run_conformance.py:

    {"op": "reset"}                                    -> {"ok": true}       forget every spent message
    {"op": "receive", "wire_text": "<raw text>", "now": <ms>, "trust": ["<id>", ...] | null,
     "audience": "<id>" | null, "kinds": ["<kind>", ...] | null, "ledger": true | false}
                                                       -> {"accept": {"digest": "<hex>"}} | {"refuse": "<code>"}

`receive` is what a receiver does to bytes that arrive, in this order: read them strictly; open the envelope (version,
fields, signature, time window, audience, kind); admit the signer only if `trust` names it; and, when `ledger` is true,
spend the message once. It is NOT authorization and decides nothing about the content.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cns_interop.envelope import Refused, open_envelope  # noqa: E402
from cns_interop.ledger import MemoryLedger  # noqa: E402
from cns_interop.wire import loads  # noqa: E402


def main() -> int:
    ledger = MemoryLedger()
    for line in sys.stdin:
        req = json.loads(line)
        if req["op"] == "reset":
            ledger = MemoryLedger()
            out = {"ok": True}
        else:
            try:
                env = open_envelope(loads(req["wire_text"]), now=req["now"], audience=req["audience"],
                                    kinds=req["kinds"])
                if req["trust"] is not None and env.sender not in req["trust"]:
                    raise Refused("untrusted", "the signer is not one this receiver admits")
                if req["ledger"]:
                    ledger.spend(env.sender, env.id, env.expires_at, now=req["now"])
                out = {"accept": {"digest": env.digest}}
            except Refused as exc:
                out = {"refuse": exc.code}
        print(json.dumps(out), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
