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


# Cases first added as `reference` whose answer the text of docs/interop/UAI-1.md decides on its own, with the words that
# decide it. A case not listed here stays `reference`: see docs/interop/implementers/README.md for why each one does.
S2_FIELDS = "UAI-1.md section 2, the field table and check 1: exactly the fields above, each in its form (malformed)"
S2_WIRE = ("UAI-1.md section 2, Wire: a reader refuses duplicate keys and anything that is not a JSON object; "
           "check 1 (malformed)")
DECIDED_BY = {
    "deeply-nested-value": S2_FIELDS + "; it is not an envelope",
    "unicode-escape-duplicate-key": S2_WIRE + "; keys are compared as the text they decode to",
    "sig-all-zeros": "UAI-1.md section 2, Signature and check 2: it is well formed and does not verify (signature)",
    "sig-last-bit-flipped": "UAI-1.md section 2, Signature and check 2: it is well formed and does not verify (signature)",
    "sig-one-hex-char-short": S2_FIELDS + "; `sig` is 128 lowercase hex digits",
    "sig-uppercase-hex": S2_FIELDS + "; `sig` is 128 lowercase hex digits",
    "version-uppercase": "UAI-1.md section 2, check 1: `v` is `uai/1` (version); a receiver never guesses at a dialect",
    "from-uppercase-hex": S2_FIELDS + "; section 3: an identity is `uai:ed25519:` and 64 lowercase hex digits",
    "from-other-key-scheme": S2_FIELDS + "; section 3: an identity is `uai:ed25519:` and 64 lowercase hex digits",
    "id-too-short": S2_FIELDS + "; `id` is 32 lowercase hex digits",
    "id-uppercase-hex": S2_FIELDS + "; `id` is 32 lowercase hex digits",
    "issued-at-as-text": S2_FIELDS + "; `issued_at` is an integer",
    "to-null": S2_FIELDS + "; `to` is an identity or the empty text",
    "kind-as-number": S2_FIELDS + "; `kind` is one of the listed names",
    "trailing-garbage": S2_WIRE,
    "second-object-appended": S2_WIRE + "; one envelope per message",
    "leading-zero-number": S2_WIRE + "; it is not JSON (RFC 8259 forbids leading zeros)",
    "lone-surrogate-in-body": "UAI-1.md section 1: text must be valid Unicode, no unpaired surrogates; check 1 (profile)",
    "nul-character-in-body": "UAI-1.md section 1: U+0000 is valid Unicode text, so the body is in the profile; "
                             "it was edited, so check 2 (signature)",
    "proto-key-duplicate": S2_WIRE,
    "proto-key-added-to-body": "UAI-1.md section 1: `__proto__` is an ordinary text key; the body was edited, so check 2 "
                               "(signature)",
    "empty-text": S2_WIRE,
    "json-null": S2_WIRE,
    "surrounding-whitespace-is-accepted": "UAI-1.md section 2, Wire: spacing does not matter (JSON allows whitespace "
                                          "around a value)",
    "pretty-printed-is-accepted": "UAI-1.md section 2, Wire: key order and spacing do not matter",
    "reordered-keys-are-accepted": "UAI-1.md section 2, Wire: key order and spacing do not matter",
    "expired-exactly-at-expires-at": "UAI-1.md section 2, check 4: now is BEFORE `expires_at` (expired)",
    "accepted-one-ms-before-expires-at": "UAI-1.md section 2, check 4: now is before `expires_at`",
    "replay-in-pretty-printed-text-is-refused": "UAI-1.md section 2, check 6: the pair (from, id) has not been accepted "
                                                "before (replayed); the text's layout is not part of it",
    "replay-with-reordered-keys-is-refused": "UAI-1.md section 2, check 6: the pair (from, id) has not been accepted "
                                             "before (replayed); the text's layout is not part of it",
}


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
    cases += adversarial(req, text, issued, dumps)
    for c in cases:
        if c["name"] in DECIDED_BY:
            c["basis"], c["spec"] = "specification", DECIDED_BY[c["name"]]
    return {"schema": "uai1-conformance/1", "note": "regenerate with python interop/vectors/make_conformance_suite.py --write; "
            "protocol in contracts/uai1/README.md", "identities": ids, "cases": cases}


def adversarial(req: Dict[str, Any], text: str, issued: int, dumps: Any) -> List[Dict[str, Any]]:
    """Attack inputs added after an outside review asked for wider adversarial coverage. Both shipped implementations were
    probed with each one first and gave the same answer (2026-11-12). Built as `reference`; those whose answer the
    specification text decides are promoted in build() through DECIDED_BY, with the words that decide them."""
    w = lambda **kw: dumps({**req, **kw})  # noqa: E731
    sig, exp, frm = req["sig"], req["expires_at"], req["from"]
    pretty = json.dumps(req, sort_keys=True, indent=2)
    reordered = json.dumps(dict(reversed(list(req.items()))))
    one = lambda name, klass, t, code, now=issued: _case(  # noqa: E731
        name, klass, "reference", [_step(t, now, {"accept": True} if code == "accept" else {"refuse": code})])
    return [
        one("sig-all-zeros", "tampered", w(sig="0" * 128), "signature"),
        one("sig-last-bit-flipped", "tampered", w(sig=sig[:-1] + format(int(sig[-1], 16) ^ 1, "x")), "signature"),
        one("sig-one-hex-char-short", "malformed", w(sig=sig[:-1]), "malformed"),
        one("sig-uppercase-hex", "malformed", w(sig=sig.upper()), "malformed"),
        one("version-uppercase", "rejected", w(v="UAI/1"), "version"),
        one("from-uppercase-hex", "malformed", w(**{"from": "uai:ed25519:" + frm.split(":")[-1].upper()}), "malformed"),
        one("from-other-key-scheme", "malformed", w(**{"from": frm.replace("ed25519", "rsa")}), "malformed"),
        one("id-too-short", "malformed", w(id=req["id"][:-2]), "malformed"),
        one("id-uppercase-hex", "malformed", w(id=req["id"].upper().replace("0", "A")), "malformed"),
        one("issued-at-as-text", "malformed", w(issued_at=str(issued)), "malformed"),
        one("issued-at-negative", "malformed", w(issued_at=-1), "malformed"),
        one("to-null", "malformed", w(to=None), "malformed"),
        one("kind-as-number", "malformed", w(kind=1), "malformed"),
        one("trailing-garbage", "ambiguous-or-malformed", text + "x", "malformed"),
        one("second-object-appended", "ambiguous-or-malformed", text + text, "malformed"),
        one("leading-byte-order-mark", "ambiguous-or-malformed", "\ufeff" + text, "malformed"),
        one("leading-zero-number", "ambiguous-or-malformed",
            text.replace(f'"issued_at":{issued}', f'"issued_at":0{issued}'), "malformed"),
        one("lone-surrogate-in-body", "ambiguous-or-malformed",
            text.replace('"income-screen"', '"income-screen\\ud800"'), "profile"),
        one("nul-character-in-body", "tampered", text.replace('"income-screen"', '"income-screen\\u0000"'), "signature"),
        one("proto-key-duplicate", "ambiguous-or-malformed", '{"__proto__":1,"__proto__":2}', "malformed"),
        one("proto-key-added-to-body", "tampered", dumps({**req, "body": {**req["body"], "__proto__": {"x": 1}}}),
            "signature"),
        one("empty-text", "malformed", "", "malformed"),
        one("json-null", "malformed", "null", "malformed"),
        one("surrounding-whitespace-is-accepted", "valid", " \n" + text + "\n ", "accept"),
        one("pretty-printed-is-accepted", "valid", pretty, "accept"),
        one("reordered-keys-are-accepted", "valid", reordered, "accept"),
        one("expired-exactly-at-expires-at", "expired", text, "expired", now=exp),
        one("accepted-one-ms-before-expires-at", "valid", text, "accept", now=exp - 1),
        _case("replay-in-pretty-printed-text-is-refused", "replayed", "reference",
              [_step(text, issued, {"accept": True}, ledger=True), _step(pretty, issued, {"refuse": "replayed"}, ledger=True)]),
        _case("replay-with-reordered-keys-is-refused", "replayed", "reference",
              [_step(text, issued, {"accept": True}, ledger=True),
               _step(reordered, issued, {"refuse": "replayed"}, ledger=True)]),
    ]


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
