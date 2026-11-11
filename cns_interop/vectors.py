"""vectors: UAI-1 as a file another implementation can check itself against.

`contracts/digest-vectors.json` pins the canonical digest. This file pins everything UAI-1 adds on top: identities
from fixed seeds, signed envelopes (Ed25519 is deterministic, so a correct implementation reproduces each signature
byte for byte), envelopes a receiver must refuse and with which code, wire text a strict reader must refuse, a
selective-disclosure commitment set, and a terms digest. The Node implementation in interop/node/ reads it in its own
tests; tests/test_uai_vectors.py asserts the committed file is exactly what this module produces now.

    python -m cns_interop.vectors --write   regenerate contracts/uai-vectors.json
    python -m cns_interop.vectors           check that the file is up to date
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from cns.gate import subject_digest

from .disclosure import commit
from .envelope import Envelope, sign_envelope
from .identity import Signer
from .negotiate import terms_digest

ROOT = Path(__file__).resolve().parent.parent
PATH = ROOT / "contracts" / "uai-vectors.json"

SEEDS = {"alice": "00" * 31 + "01", "bob": "11" * 32, "authority": "42" * 32}
T = 1_800_000_000_000


def _signer(name: str) -> Signer:
    return Signer(bytes.fromhex(SEEDS[name]))


def _env(name: str, kind: str, body: Dict[str, Any], *, to: str = "", n: int = 1, reply: str = "",
         expires: Any = T + 60_000) -> Envelope:
    s = _signer(name)
    mid = f"{n:032x}"
    return sign_envelope(s, Envelope(kind=kind, id=mid, sender=s.agent, to=to, conversation=mid, in_reply_to=reply,
                                     issued_at=T, expires_at=expires, body=body))


def build() -> Dict[str, Any]:
    alice, bob = _signer("alice"), _signer("bob")
    tricky = {"z": [1, -1, 0, 9007199254740991, -9007199254740991], "A": None, "b": True, "c": False,
              "été": "café", "Ａ": "fullwidth", "\U0001f600": "astral key sorts after U+FF21",
              "nested": {"list": [[], {}, [{"k": "v"}]], "empty": ""}, "quote\"and\\slash": "line\nbreak\ttab"}
    good = [
        _env("alice", "request", {"capability": "income-screen", "version": 1}, to=bob.agent, n=1),
        _env("bob", "offer", tricky, to=alice.agent, n=2, reply="ab" * 32),
        _env("authority", "manifest", {}, n=3, expires=None),
    ]
    envelopes = [{"name": f"{e.kind}-{i}", "signer": signer, "wire": e.to_wire(), "digest": e.digest,
                  "signing_digest": subject_digest(e.unsigned())}
                 for i, (e, signer) in enumerate(zip(good, ["alice", "bob", "authority"]))]

    def bad(name: str, code: str, change) -> Dict[str, Any]:
        w = json.loads(json.dumps(good[0].to_wire()))
        change(w)
        return {"name": name, "wire": w, "code": code, "now": T}

    rejections: List[Dict[str, Any]] = [
        bad("body-edited", "signature", lambda w: w["body"].update(version=2)),
        bad("sender-swapped", "signature", lambda w: w.update({"from": bob.agent})),
        bad("extra-field", "malformed", lambda w: w.update(extra=1)),
        bad("missing-field", "malformed", lambda w: w.pop("to")),
        bad("other-version", "version", lambda w: w.update(v="uai/2")),
        bad("unknown-kind", "malformed", lambda w: w.update(kind="gossip")),
        bad("bad-sig-hex", "malformed", lambda w: w.update(sig="zz" * 64)),
        bad("expires-before-issue", "malformed", lambda w: w.update(expires_at=T)),
        # Keys that must never verify: the identity point (anyone can "sign" for it with R = identity, s = 0), and a
        # non-canonical encoding (y = p + 1) that some Ed25519 libraries accept and the Python reference does not.
        bad("small-order-key", "signature", lambda w: w.update({
            "from": "uai:ed25519:01" + "00" * 31, "sig": "01" + "00" * 63})),
        bad("non-canonical-key", "signature", lambda w: w.update({
            "from": "uai:ed25519:ee" + "ff" * 30 + "7f", "sig": w["sig"]})),
        {"name": "expired", "wire": good[0].to_wire(), "code": "expired", "now": T + 60_000},
        {"name": "from-the-future", "wire": good[0].to_wire(), "code": "not_yet_valid", "now": T - 120_001},
    ]
    wire_text = [
        {"name": "duplicate-key", "text": '{"a":1,"a":2}', "code": "malformed"},
        {"name": "float", "text": '{"a":1.0}', "code": "profile"},
        {"name": "exponent", "text": '{"a":1e3}', "code": "profile"},
        {"name": "big-int", "text": '{"a":9007199254740992}', "code": "profile"},
        {"name": "nan", "text": '{"a":NaN}', "code": "malformed"},
        {"name": "not-object", "text": "[1]", "code": "malformed"},
    ]
    doc = commit("loan-app-17", {"monthly_income_cents": 512000, "doc_type": "paystub", "ssn": "000-00-0000"},
                 salts={"monthly_income_cents": "0" * 31 + "1", "doc_type": "0" * 31 + "2", "ssn": "0" * 31 + "3"})
    terms = {"capability": "income-screen", "version": 1, "decider": bob.agent, "requester": alice.agent,
             "subject": {"identity": doc.identity, "digest": doc.digest}, "disclose": ["doc_type", "monthly_income_cents"],
             "evidence": ["threshold-check"], "decision_ttl_ms": 300000}
    return {
        "schema": "cns-uai-vectors/1",
        "note": "regenerate with python -m cns_interop.vectors --write; spec in docs/interop/UAI-1.md",
        "seeds": {k: {"seed": v, "agent": _signer(k).agent} for k, v in SEEDS.items()},
        "envelopes": envelopes,
        "rejections": rejections,
        "wire_text": wire_text,
        "disclosure": {"identity": doc.identity, "values": dict(doc.values), "salts": dict(doc.salts),
                       "commitments": doc.commitments, "digest": doc.digest,
                       "reveal": doc.reveal(["doc_type", "monthly_income_cents"])},
        "terms": {"terms": terms, "digest": terms_digest(terms)},
    }


def render() -> str:
    return json.dumps(build(), indent=2, ensure_ascii=False) + "\n"


def main(argv: Any = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--write", action="store_true")
    args = p.parse_args(argv)
    if args.write:
        PATH.write_text(render(), encoding="utf-8")
        print(f"wrote {PATH.relative_to(ROOT)}")
        return 0
    if not PATH.exists() or PATH.read_text(encoding="utf-8") != render():
        print("contracts/uai-vectors.json is out of date; run python -m cns_interop.vectors --write")
        return 1
    print("contracts/uai-vectors.json is up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
