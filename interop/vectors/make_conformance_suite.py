"""Build contracts/uai1/conformance-suite.json: the cases an independent UAI-1 implementation is checked against.

    python interop/vectors/make_conformance_suite.py            # print
    python interop/vectors/make_conformance_suite.py --write    # write the contracts file

Every case is plain data (raw text in, the receiver's answer out) so an implementation in any language can run it with
contracts/uai1/run_conformance.py and no CNS code. The valid envelopes, the rejections and the strict-reading cases come from
contracts/uai-vectors.json (the published answer key). The additional cases are built here from the same deterministic
seeds. Where a case's expected answer is not stated by the specification alone it is marked `basis: "reference"`: both
shipped implementations (Python and Node) agree on it, and a third implementation that disagrees has found either a bug or
an ambiguity worth reporting; it is not yet evidence that the specification is complete.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

SUITE = ROOT / "contracts" / "uai1" / "conformance-suite.json"
VECTORS = ROOT / "contracts" / "uai-vectors.json"


def _step(text: str, now: int, expect: Dict[str, Any], *, trust: Any = None, audience: Any = None, kinds: Any = None,
          ledger: bool = False) -> Dict[str, Any]:
    return {"receive": {"wire_text": text, "now": now, "trust": trust, "audience": audience, "kinds": kinds, "ledger": ledger},
            "expect": expect}


def _case(name: str, klass: str, basis: str, steps: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"name": name, "class": klass, "basis": basis, "steps": steps}


def build() -> Dict[str, Any]:
    v = json.loads(VECTORS.read_text(encoding="utf-8"))
    ids = {k: s["agent"] for k, s in v["seeds"].items()}
    ts = {e["name"]: e for e in v["envelopes"]}
    req = ts["request-0"]["wire"]
    issued = req["issued_at"]
    cases: List[Dict[str, Any]] = []
    dumps = lambda w: json.dumps(w, sort_keys=True, separators=(",", ":"))  # noqa: E731

    for e in v["envelopes"]:
        cases.append(_case(f"valid-{e['name']}", "valid", "specification",
                           [_step(dumps(e["wire"]), e["wire"]["issued_at"], {"accept": True})]))
    for r in v["rejections"]:
        cases.append(_case(f"reject-{r['name']}", "rejected", "specification",
                           [_step(dumps(r["wire"]), r["now"], {"refuse": r["code"]})]))
    for w in v["wire_text"]:
        cases.append(_case(f"text-{w['name']}", "ambiguous-or-malformed", "specification",
                           [_step(w["text"], issued, {"refuse": w["code"]})]))

    text = dumps(req)
    cases += [
        _case("replay-is-refused", "replayed", "specification",
              [_step(text, issued, {"accept": True}, ledger=True), _step(text, issued, {"refuse": "replayed"}, ledger=True)]),
        _case("replay-needs-the-ledger-so-without-it-both-are-accepted", "replayed", "reference",
              [_step(text, issued, {"accept": True}), _step(text, issued, {"accept": True})]),
        _case("unauthorized-signer-is-refused", "unauthorized", "specification",
              [_step(text, issued, {"refuse": "untrusted"}, trust=[ids["bob"]])]),
        _case("authorized-signer-is-accepted", "valid", "specification",
              [_step(text, issued, {"accept": True}, trust=[ids["alice"]])]),
        _case("addressed-to-someone-else", "unauthorized", "specification",
              [_step(text, issued, {"refuse": "audience"}, audience=ids["alice"])]),
        _case("kind-not-expected", "unauthorized", "specification",
              [_step(text, issued, {"refuse": "kind"}, kinds=["offer"])]),
        _case("digest-substitution-in-reply-link", "tampered", "specification",
              [_step(dumps({**req, "in_reply_to": "0" * 64}), issued, {"refuse": "signature"})]),
        _case("expired-just-after-expiry", "expired", "specification",
              [_step(text, req["expires_at"] + 120_001, {"refuse": "expired"})]),
        _case("oversized-message", "malformed", "specification",
              [_step('{"a":"' + "x" * (1 << 20) + '"}', issued, {"refuse": "malformed"})]),
        _case("deeply-nested-value", "malformed", "reference",
              [_step('{"a":' + "[" * 200 + "]" * 200 + "}", issued, {"refuse": "malformed"})]),
        _case("duplicate-key-nested", "ambiguous-or-malformed", "specification",
              [_step('{"body":{"x":1,"x":2}}', issued, {"refuse": "malformed"})]),
        _case("unicode-escape-duplicate-key", "ambiguous-or-malformed", "reference",
              [_step('{"a":1,"\\u0061":2}', issued, {"refuse": "malformed"})]),
    ]
    return {"schema": "uai1-conformance/1", "note": "regenerate with python interop/vectors/make_conformance_suite.py --write; "
            "protocol in contracts/uai1/README.md", "identities": ids, "cases": cases}


def render() -> str:
    return json.dumps(build(), indent=1, sort_keys=True) + "\n"


def main(argv: List[str]) -> int:
    if "--write" in argv:
        SUITE.write_text(render(), encoding="utf-8")
        print(f"wrote {SUITE.relative_to(ROOT)}")
    else:
        sys.stdout.write(render())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
