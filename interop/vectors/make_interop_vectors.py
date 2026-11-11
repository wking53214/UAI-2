"""make_interop_vectors: the independent answer key for the UAI-1 interoperability campaign.

    python interop/vectors/make_interop_vectors.py            write contracts/uai-interop-vectors.json
    python interop/vectors/make_interop_vectors.py --check    fail if the committed file differs

WHY THIS IS NOT THE PYTHON REFERENCE CHECKING ITSELF

  * It imports nothing from `cns`, `cns_composition` or `cns_interop`. Its canonical encoder (`canon`) is written here
    from UAI-1.md section 1, in about twenty lines, and every digest case also carries the canonical TEXT written out
    by hand, so a reader can check the encoding without running anything.
  * Signatures are made by the OpenSSL command line (`openssl pkeyutl -sign -rawin`), a third Ed25519 that is neither
    the Python module nor Node's binding. Ed25519 is deterministic, so the output is reproducible.
  * Every expected result is typed into the case tables below with a `why`. Nothing is read back from an
    implementation. A case that an implementation disagrees with is a finding, not a vector to regenerate.

The seeds are public test keys. They sign nothing real.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "contracts" / "uai-interop-vectors.json"
NOW = 1_800_000_000_000
TAG = b"uai/1 sig\n"
PKCS8 = bytes.fromhex("302e020100300506032b657004220420")


def canon(v: Any) -> str:
    """The canonical text of a value, from UAI-1.md section 1: null n:, booleans b:1 b:0, integers i:N:, text
    s:LEN:TEXT with LEN in code points, lists l:N: then the items, mappings d:N: then key and value for each key
    in code point order. Python orders text by code point already; that is the rule, so nothing special is done."""
    if v is None:
        return "n:"
    if v is True:
        return "b:1"
    if v is False:
        return "b:0"
    if isinstance(v, int):
        return f"i:{v}:"
    if isinstance(v, str):
        return f"s:{len(v)}:{v}"
    if isinstance(v, list):
        return f"l:{len(v)}:" + "".join(canon(x) for x in v)
    if isinstance(v, dict):
        return f"d:{len(v)}:" + "".join(canon(k) + canon(v[k]) for k in sorted(v))
    raise TypeError(type(v))


def digest(v: Any) -> str:
    return hashlib.sha256(canon(v).encode("utf-8")).hexdigest()


class Key:
    def __init__(self, byte: int) -> None:
        self.seed = bytes([byte]) * 32
        self._dir = tempfile.mkdtemp()
        self._der = os.path.join(self._dir, "k.der")
        Path(self._der).write_bytes(PKCS8 + self.seed)
        pub = subprocess.run(["openssl", "pkey", "-in", self._der, "-inform", "DER", "-pubout", "-outform", "DER"],
                             capture_output=True, check=True).stdout[-32:]
        self.agent = "uai:ed25519:" + pub.hex()

    def sign(self, message: bytes) -> str:
        m = os.path.join(self._dir, "m")
        Path(m).write_bytes(message)
        return subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", self._der, "-keyform", "DER", "-rawin",
                               "-in", m], capture_output=True, check=True).stdout.hex()


A, B, AUTH, EVE, C = (Key(b) for b in (0x51, 0x52, 0x53, 0x54, 0x55))


def env(key: Key, kind: str, body: Dict[str, Any], *, to: str = "", n: int = 1, issued: int = NOW,
        ttl: Optional[int] = 60_000, reply: str = "", **over: Any) -> Dict[str, Any]:
    fields: Dict[str, Any] = {"v": "uai/1", "kind": kind, "id": f"{n:032x}", "from": key.agent, "to": to,
                              "conversation": f"{n:032x}", "in_reply_to": reply, "issued_at": issued,
                              "expires_at": None if ttl is None else issued + ttl, "body": body}
    fields.update(over)
    sig = key.sign(TAG + digest(fields).encode("ascii"))
    return {**fields, "sig": sig}


def wire_digest(wire: Dict[str, Any]) -> str:
    return digest(wire)


def text(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ------------------------------------------------------------------------------------------------ digest cases
def digest_cases() -> List[Dict[str, Any]]:
    D = [
        ("key-order-is-sorted", '{"b":1,"a":2}', "d:2:s:1:ai:2:s:1:bi:1:", "keys are sorted, so order on the wire never matters"),
        ("key-order-is-sorted-other-way", '{"a":2,"b":1}', "d:2:s:1:ai:2:s:1:bi:1:", "the same mapping written the other way digests alike"),
        ("nfc-text", '{"a":"\\u00e9"}', "d:1:s:1:as:1:é", "one code point, length 1"),
        ("nfd-text", '{"a":"e\\u0301"}', "d:1:s:1:as:2:é", "two code points, length 2: text is NEVER normalized, so NFC and NFD digest differently"),
        ("astral-length", '{"a":"\\ud83d\\ude00"}', "d:1:s:1:as:1:\U0001F600", "a surrogate pair is one code point, length 1, in every language"),
        ("astral-raw", '{"a":"\U0001F600"}', "d:1:s:1:as:1:\U0001F600", "raw and escaped spellings of the same text digest alike"),
        ("code-point-key-order", '{"\\ud83d\\ude00":1,"\\uffff":2}', "d:2:s:1:￿i:2:s:1:\U0001F600i:1:", "keys sort by code point: U+FFFF before U+1F600 (UTF-16 order would reverse them)"),
        ("negative-zero", '{"a":-0}', "d:1:s:1:ai:0:", "an integer has no sign of zero"),
        ("max-safe-int", '{"a":9007199254740991}', "d:1:s:1:ai:9007199254740991:", "the largest integer every runtime can hold"),
        ("min-safe-int", '{"a":-9007199254740991}', "d:1:s:1:ai:-9007199254740991:", "the smallest"),
        ("true-false-null", '{"a":[true,false,null]}', "d:1:s:1:al:3:b:1b:0n:", "booleans are not integers"),
        ("empty-containers", '{"a":[],"b":{}}', "d:2:s:1:al:0:s:1:bd:0:", "empty list and mapping"),
        ("empty-key", '{"":1}', "d:1:s:0:i:1:", "the empty text is a legal key"),
        ("nul-character", '{"a":"\\u0000"}', "d:1:s:1:as:1:\x00", "NUL is one code point"),
        ("proto-and-constructor-keys", '{"constructor":2,"__proto__":1}', "d:2:s:9:__proto__i:1:s:11:constructori:2:", "keys that mean something to some runtimes are ordinary keys"),
        ("whitespace-and-escapes", ' { "a" : "\\/\\u00E9" } ', "d:1:s:1:as:2:/é", "insignificant whitespace, \\/ and an uppercase hex escape"),
        ("nested", '{"a":{"b":[1,{"c":"d"}]}}', "d:1:s:1:ad:1:s:1:bl:2:i:1:d:1:s:1:cs:1:d", "nesting is just recursion"),
    ]
    out = []
    for name, t, c, why in D:
        assert canon(json.loads(t)) == c, f"hand-written canonical text for {name} is wrong"
        out.append({"id": f"digest/{name}", "text": t, "canonical": c, "sha256": hashlib.sha256(c.encode()).hexdigest(),
                    "expect": {"outcome": "ok"}, "why": why})
    return out


# ------------------------------------------------------------------------------------------------ wire cases
def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def wire_cases() -> List[Dict[str, Any]]:
    R = [  # (name, bytes, outcome, [codes], why)
        ("duplicate-key", b'{"a":1,"a":2}', "refuse", ["malformed"], "two receivers would disagree on which value counts"),
        ("duplicate-key-by-escape", b'{"a":1,"\\u0061":2}', "refuse", ["malformed"], "the same key spelled two ways is still twice"),
        ("float-one-point-zero", b'{"a":1.0}', "refuse", ["profile"], "UAI-1 carries integers only"),
        ("float-exponent", b'{"a":1e3}', "refuse", ["profile"], "an exponent is a float"),
        ("float-exponent-capital", b'{"a":1E3}', "refuse", ["profile"], "an exponent is a float"),
        ("float-negative-zero", b'{"a":-0.0}', "refuse", ["profile"], "a float"),
        ("float-half", b'{"a":0.5}', "refuse", ["profile"], "a float"),
        ("integer-too-big", b'{"a":9007199254740992}', "refuse", ["profile"], "outside +/-(2**53-1)"),
        ("integer-too-small", b'{"a":-9007199254740992}', "refuse", ["profile"], "outside +/-(2**53-1)"),
        ("nan", b'{"a":NaN}', "refuse", ["malformed"], "not a JSON value"),
        ("infinity", b'{"a":Infinity}', "refuse", ["malformed"], "not a JSON value"),
        ("negative-infinity", b'{"a":-Infinity}', "refuse", ["malformed"], "not a JSON value"),
        ("top-level-array", b'[1]', "refuse", ["malformed"], "a message is one object"),
        ("top-level-number", b'1', "refuse", ["malformed"], "a message is one object"),
        ("top-level-string", b'"x"', "refuse", ["malformed"], "a message is one object"),
        ("empty", b'', "refuse", ["malformed"], "nothing to read"),
        ("whitespace-only", b'   ', "refuse", ["malformed"], "nothing to read"),
        ("trailing-text", b'{"a":1} x', "refuse", ["malformed"], "one object and nothing after it"),
        ("two-objects", b'{"a":1}{"b":2}', "refuse", ["malformed"], "one object and nothing after it"),
        ("byte-order-mark", b'\xef\xbb\xbf{"a":1}', "refuse", ["malformed"], "a BOM is not JSON whitespace"),
        ("invalid-utf8-byte", b'{"a":"\xff"}', "refuse", ["malformed"], "0xFF is never UTF-8; a lenient decoder would swap in U+FFFD and two receivers would read different text"),
        ("overlong-utf8", b'{"a":"\xc0\xaf"}', "refuse", ["malformed"], "an overlong encoding of '/'"),
        ("truncated-utf8", b'{"a":"\xe2\x82"}', "refuse", ["malformed"], "a multi-byte sequence cut short"),
        ("encoded-surrogate", b'{"a":"\xed\xa0\x80"}', "refuse", ["malformed"], "UTF-8 may not encode a surrogate"),
        ("raw-control-character", b'{"a":"\x01"}', "refuse", ["malformed"], "control characters must be escaped"),
        ("single-quotes", b"{'a':1}", "refuse", ["malformed"], "not JSON"),
        ("trailing-comma", b'{"a":1,}', "refuse", ["malformed"], "not JSON"),
        ("leading-zero", b'{"a":01}', "refuse", ["malformed"], "not JSON"),
        ("plus-sign", b'{"a":+1}', "refuse", ["malformed"], "not JSON"),
        ("hex-number", b'{"a":0x10}', "refuse", ["malformed"], "not JSON"),
        ("unterminated", b'{"a":1', "refuse", ["malformed"], "not JSON"),
        ("bad-escape", b'{"a":"\\x41"}', "refuse", ["malformed"], "not a JSON escape"),
        ("short-unicode-escape", b'{"a":"\\u12"}', "refuse", ["malformed"], "not a JSON escape"),
        ("non-ascii-whitespace", '{"a": 1}'.encode(), "refuse", ["malformed"], "only space, tab, newline and carriage return are whitespace"),
        ("form-feed-whitespace", b'{"a":\x0c1}', "refuse", ["malformed"], "form feed is not JSON whitespace"),
    ]
    out = [{"id": f"wire/{n}", "b64": b64(b), "expect": {"outcome": o, "codes": c}, "why": w} for n, b, o, c, w in R]
    big = b'{"a":"' + b"x" * ((1 << 20) - 8) + b'"}'
    assert len(big) == 1 << 20
    out.append({"id": "wire/exactly-one-mebibyte", "generate": "exact_mib", "expect": {"outcome": "ok"},
                "why": "the limit is more than 1 MiB, so exactly 1 MiB reads"})
    out.append({"id": "wire/one-byte-over-a-mebibyte", "generate": "over_mib", "expect": {"outcome": "refuse", "codes": ["malformed"]},
                "why": "more than 1 MiB is refused before anything else looks at it"})
    return out


# ------------------------------------------------------------------------------------------------ envelope cases
def envelope_cases() -> List[Dict[str, Any]]:
    good = env(A, "request", {"hello": "world"}, to=B.agent, n=1)
    out: List[Dict[str, Any]] = []

    def add(name, wire=None, *, txt=None, now=NOW + 1, audience=None, kinds=None, outcome="refuse", codes=None, why=""):
        c: Dict[str, Any] = {"id": f"envelope/{name}", "now": now, "audience": audience, "kinds": kinds,
                             "expect": {"outcome": outcome, **({"codes": codes} if codes else {})}, "why": why}
        c["text"] = txt if txt is not None else text(wire)
        out.append(c)

    add("valid", good, outcome="ok", why="a well-formed, correctly signed, unexpired envelope")
    add("valid-audience", good, audience=B.agent, outcome="ok", why="addressed to exactly this receiver")
    rev = json.dumps({k: good[k] for k in reversed(list(good))}, indent=3, ensure_ascii=False)
    add("valid-key-order-and-spacing", txt=rev, outcome="ok", why="JSON is only transport: the signature is over the canonical digest, so key order and spacing do not matter")
    add("body-edited", {**good, "body": {"hello": "there"}}, codes=["signature"], why="content changed after signing")
    add("sender-swapped", {**good, "from": EVE.agent}, codes=["signature"], why="the signature is not the claimed sender's")
    add("to-swapped", {**good, "to": C.agent}, codes=["signature"], why="the audience is signed")
    add("id-changed", {**good, "id": f"{2:032x}"}, codes=["signature"], why="the id is signed")
    add("unknown-field", {**good, "extra": 1}, codes=["malformed"], why="exactly the UAI-1 fields and no others")
    missing = dict(good)
    del missing["conversation"]
    add("missing-field", missing, codes=["malformed"], why="exactly the UAI-1 fields")
    add("version-two", env(A, "request", {}, to=B.agent, n=3, v="uai/2"), codes=["version"], why="an unsupported protocol version is refused, never guessed at")
    add("version-wrong-type", {**good, "v": 1}, codes=["version"], why="the version is the text uai/1")
    add("unknown-kind", env(A, "gossip", {}, to=B.agent, n=4), codes=["malformed"], why="the kind is one of the defined kinds")
    add("kind-not-accepted-here", good, kinds=["offer"], codes=["kind"], why="a request is not what this step accepts")
    add("algorithm-substitution-ed448", {**good, "from": "uai:ed448:" + "ab" * 57}, codes=["malformed"], why="the only algorithm is ed25519; another is refused, never mapped")
    add("algorithm-none", {**good, "from": "uai:none:" + "ab" * 32}, codes=["malformed"], why="no 'none' algorithm")
    add("identity-uppercase-hex", {**good, "from": "uai:ed25519:" + good["from"][12:].upper()}, codes=["malformed"], why="an identity is lowercase hex")
    add("identity-wrong-length", {**good, "from": good["from"][:-2]}, codes=["malformed"], why="an identity is 64 hex digits")
    add("signature-uppercase", {**good, "sig": good["sig"].upper()}, codes=["malformed"], why="a signature is 128 lowercase hex digits")
    add("signature-short", {**good, "sig": good["sig"][:-2]}, codes=["malformed"], why="a signature is 128 hex digits")
    add("small-order-key", env(A, "request", {}, to=B.agent, n=5, **{"from": "uai:ed25519:" + "01" + "00" * 31}), codes=["signature"], why="a small-order key is 'signed for' by anyone, so it is refused")
    for label, point in (("identity", "01" + "00" * 31), ("order-two", "ecff" + "ff" * 29 + "7f")):
        forged = {**env(A, "request", {}, to=B.agent, n=17, **{"from": "uai:ed25519:" + point}), "sig": point + "00" * 32}
        add(f"small-order-key-forged-signature-{label}", forged, codes=["signature"],
            why="a small-order public key verifies a crafted (R = the point, s = 0) signature for ANY message under the bare "
                "equation, so anyone could speak as that identity; it must be refused before the equation is tried")
    add("expired", good, now=NOW + 60_000, codes=["expired"], why="valid until, not including, expires_at")
    add("last-valid-millisecond", good, now=NOW + 59_999, outcome="ok", why="one millisecond before expiry is still valid")
    add("clock-skew-allowed", env(A, "request", {}, to=B.agent, n=6, issued=NOW + 120_000), now=NOW, outcome="ok", why="up to 120 s of clock skew is tolerated")
    add("from-the-future", env(A, "request", {}, to=B.agent, n=7, issued=NOW + 120_001), now=NOW, codes=["not_yet_valid"], why="beyond the skew")
    add("audience-mismatch", good, audience=C.agent, codes=["audience"], why="addressed to someone else")
    add("broadcast-to-a-named-receiver", env(A, "request", {}, to="", n=8), audience=B.agent, codes=["audience"], why="a message to no one in particular is not addressed to this receiver")
    add("expires-before-issue", env(A, "request", {}, to=B.agent, n=9, expires_at=NOW - 1), codes=["malformed"], why="expires_at is after issued_at")
    add("expires-as-text", env(A, "request", {}, to=B.agent, n=10, expires_at="soon"), codes=["malformed"], why="a time is an integer")
    add("issued-negative", env(A, "request", {}, to=B.agent, n=11, issued_at=-1), codes=["malformed"], why="a time is not negative")
    add("issued-as-boolean", env(A, "request", {}, to=B.agent, n=12, issued_at=True), codes=["malformed"], why="true is not an integer")
    float_form = text(good).replace(f'"issued_at":{NOW}', f'"issued_at":{NOW}.0')
    add("issued-as-float-text", txt=float_form, codes=["profile"], why="1800000000000.0 is a float, however round")
    neg0 = env(A, "request", {}, to=B.agent, n=13, issued=0, ttl=NOW * 2)
    add("issued-negative-zero", txt=text(neg0).replace('"issued_at":0', '"issued_at":-0'), now=1, outcome="ok", why="-0 is the integer 0, so the digest and the signature are unchanged")
    nfd_wire = env(A, "request", {"name": "é"}, to=B.agent, n=14)
    add("unicode-nfd-signed-as-nfd", nfd_wire, outcome="ok", why="text is taken as written: signed as NFD, verified as NFD")
    add("unicode-renormalized-to-nfc", {**nfd_wire, "body": {"name": "é"}}, codes=["signature"], why="re-normalizing changes the signed content, so a normalizing transport breaks the signature instead of silently changing meaning")

    def nest(depth: int) -> Dict[str, Any]:
        v: Any = "x"
        for _ in range(depth):
            v = [v]
        return {"deep": v}
    # body is depth 0; {"deep": [...]} puts the list at depth 1, so `depth` lists reach depth `depth`
    add("body-depth-32", env(A, "request", nest(31), to=B.agent, n=15), outcome="ok", why="nesting up to 32 levels is in the profile")
    add("body-depth-33", env(A, "request", nest(32), to=B.agent, n=16), codes=["profile"], why="33 levels is not")
    add("lone-surrogate-in-body", txt=text(good).replace('"hello":"world"', '"hello":"\\ud800"'), codes=["profile", "signature"], why="text that is not valid Unicode is outside the profile (and cannot have been signed)")
    add("body-float", txt=text(good).replace('"hello":"world"', '"hello":1.5'), codes=["profile"], why="floats are outside the profile")
    add("sixty-four-bit-integer-in-body", txt=text(good).replace('"hello":"world"', '"hello":9007199254740993'), codes=["profile"], why="not exactly representable everywhere")
    return out


# ------------------------------------------------------------------------------------------------ negotiation cases
CAP = {"name": "income-screen", "version": 1, "summary": "s", "accepts": ["doc_type", "monthly_income_cents"],
       "requires": ["monthly_income_cents"], "evidence": ["threshold-check"], "max_ttl_ms": 300000}
SUBJECT = {"identity": "loan-1", "digest": "ab" * 32}


def req(**kw: Any) -> Dict[str, Any]:
    base = {"capability": "income-screen", "version": 1, "subject": SUBJECT,
            "offer_fields": ["doc_type", "monthly_income_cents"], "require_evidence": ["threshold-check"], "max_ttl_ms": 600000}
    base.update(kw)
    return base


def negotiation_cases() -> List[Dict[str, Any]]:
    def terms(**kw: Any) -> Dict[str, Any]:
        t = {"capability": "income-screen", "version": 1, "decider": B.agent, "requester": A.agent, "subject": SUBJECT,
             "disclose": ["doc_type", "monthly_income_cents"], "evidence": ["threshold-check"], "decision_ttl_ms": 300000}
        t.update(kw)
        return t
    N = [
        ("agreeable", req(), {"outcome": "ok", "terms": terms()}, "terms intersect what is offered with what is accepted; the ttl is the smaller"),
        ("requester-ttl-is-smaller", req(max_ttl_ms=1000), {"outcome": "ok", "terms": terms(decision_ttl_ms=1000)}, "the shorter of the two limits"),
        ("unneeded-field-never-disclosed", req(offer_fields=["monthly_income_cents", "full_name"]), {"outcome": "ok", "terms": terms(disclose=["monthly_income_cents"])}, "a field the capability does not accept is not disclosed even though it was offered"),
        ("required-field-withheld", req(offer_fields=["doc_type"]), {"outcome": "refuse", "codes": ["terms"]}, "the capability must see a field the requester will not disclose"),
        ("evidence-not-produced", req(require_evidence=["something-else"]), {"outcome": "refuse", "codes": ["terms"]}, "the requester needs evidence the capability does not produce"),
        ("other-capability", req(capability="other"), {"outcome": "refuse", "codes": ["capability"]}, "a manifest is an advertisement: the request names exactly one capability and version"),
        ("other-version", req(version=2), {"outcome": "refuse", "codes": ["capability"]}, "versions are not interchangeable"),
        ("unknown-request-field", {**req(), "purpose": "marketing"}, {"outcome": "refuse", "codes": ["malformed"]}, "a request has exactly its fields: nothing smuggled in beside them"),
        ("request-missing-field", {k: v for k, v in req().items() if k != "max_ttl_ms"}, {"outcome": "refuse", "codes": ["malformed"]}, "a request has exactly its fields"),
        ("fields-not-distinct", req(offer_fields=["doc_type", "doc_type"]), {"outcome": "refuse", "codes": ["malformed"]}, "a list of distinct names"),
        ("field-name-uppercase", req(offer_fields=["Doc_Type"]), {"outcome": "refuse", "codes": ["malformed"]}, "names are lowercase"),
        ("ttl-zero", req(max_ttl_ms=0), {"outcome": "refuse", "codes": ["malformed"]}, "a positive integer"),
        ("ttl-boolean", req(max_ttl_ms=True), {"outcome": "refuse", "codes": ["malformed"]}, "true is not an integer"),
        ("subject-extra-key", req(subject={**SUBJECT, "owner": "x"}), {"outcome": "refuse", "codes": ["malformed"]}, "a subject is exactly identity and digest"),
    ]
    return [{"id": f"negotiation/{n}", "capability": CAP, "request": r, "decider": B.agent, "requester": A.agent,
             "expect": e, "why": w} for n, r, e, w in N]


# ------------------------------------------------------------------------------------------------ sequences
def receiving(n: int, key: Key = A, **kw: Any) -> Dict[str, Any]:
    return env(key, "request", {"n": n}, to=B.agent, n=n, **kw)


def sequences() -> List[Dict[str, Any]]:
    S: List[Dict[str, Any]] = []

    def seq(name, cfg, steps, why):
        S.append({"id": f"sequence/{name}", "config": {"self": B.agent, "pinned": [], "authorities": [], "max_staleness_ms": None,
                                                       "follow_rotation": False, **cfg}, "steps": steps, "why": why})

    def rx(wire, now=NOW + 1, expect="ok"):
        return {"op": "receive", "text": text(wire), "now": now, "expect": expect}

    def rv(wire, now=NOW + 1, expect="ok"):
        return {"op": "revocation", "text": text(wire), "now": now, "expect": expect}

    m1, m2 = receiving(21), receiving(22)
    seq("replay", {"pinned": [A.agent]}, [rx(m1), rx(m1, expect="replayed"), rx(m2), rx(m2, expect="replayed"), rx(m1, expect="replayed")],
        "a message is accepted once; a second delivery of the same bytes is a replay, however many other messages came between")
    e1, e2, e3 = receiving(23), receiving(24), receiving(25)
    seq("expiry-boundary", {"pinned": [A.agent]}, [rx(e1, now=NOW + 59_999), rx(e2, now=NOW + 60_000, expect="expired"), rx(e3, now=NOW + 60_001, expect="expired")],
        "valid until, not including, expires_at")
    seq("untrusted-sender", {"pinned": [A.agent]}, [rx(receiving(26, EVE), expect="untrusted"), rx(receiving(27, EVE), expect="untrusted")],
        "a valid signature from an identity the receiver did not pin is not permission, every time")
    seq("self-revocation", {"pinned": [A.agent]},
        [rx(receiving(28)), rv(env(A, "revocation", {"subject": A.agent, "action": "revoke", "successor": "", "reason": "key lost", "effective_at": NOW}, n=29, ttl=None)),
         rx(receiving(30), expect="untrusted")], "a key's own revocation closes it for the receiver that stored it")
    seq("revocation-by-a-stranger-is-refused", {"pinned": [A.agent, B.agent]},
        [rv(env(EVE, "revocation", {"subject": A.agent, "action": "revoke", "successor": "", "reason": "spite", "effective_at": NOW}, n=31, ttl=None), expect="untrusted"),
         rx(receiving(32))], "only the subject or a listed authority can revoke")
    seq("revocation-by-a-listed-authority", {"pinned": [A.agent], "authorities": [AUTH.agent]},
        [rv(env(AUTH, "revocation", {"subject": A.agent, "action": "revoke", "successor": "", "reason": "breach", "effective_at": NOW}, n=33, ttl=None)),
         rx(receiving(34), expect="untrusted")], "a receiver-listed authority may revoke any identity")
    seq("revocation-with-future-effect", {"pinned": [A.agent]},
        [rv(env(A, "revocation", {"subject": A.agent, "action": "revoke", "successor": "", "reason": "planned", "effective_at": NOW + 10_000}, n=35, ttl=None)),
         rx(receiving(36), now=NOW + 9_999), rx(receiving(37), now=NOW + 10_000, expect="untrusted")], "binds once its effective time arrives")
    seq("stale-revocation-list", {"pinned": [A.agent], "max_staleness_ms": 60_000},
        [rx(receiving(38), expect="unavailable"), {"op": "fresh", "now": NOW, "expect": "ok"}, rx(receiving(39), now=NOW + 59_000),
         rx(receiving(40, issued=NOW + 61_000 - 1), now=NOW + 61_000, expect="unavailable")],
        "not knowing is not the same as nothing being revoked: a list never refreshed, or refreshed too long ago, refuses")
    A2 = C
    rot = env(A, "revocation", {"subject": A.agent, "action": "rotate", "successor": A2.agent, "reason": "scheduled", "effective_at": NOW}, n=41, ttl=None)
    seq("rotation-off-by-default", {"pinned": [A.agent]}, [rv(rot), rx(receiving(42, A2), expect="untrusted"), rx(receiving(43), expect="untrusted")],
        "a rotation can add trust, so it is ignored unless the receiver chose to follow it; the old key is retired either way")
    seq("rotation-followed", {"pinned": [A.agent], "follow_rotation": True}, [rv(rot), rx(receiving(44, A2)), rx(receiving(45), expect="untrusted")],
        "when followed, the pinned identity's chosen successor is admitted and the old key is not")
    seq("rotation-withdrawn-by-authority", {"pinned": [A.agent], "follow_rotation": True, "authorities": [AUTH.agent]},
        [rv(rot), rx(receiving(46, A2)),
         rv(env(AUTH, "revocation", {"subject": A.agent, "action": "revoke", "successor": "", "reason": "it was compromised", "effective_at": NOW}, n=47, ttl=None)),
         rx(receiving(48, A2), expect="untrusted")], "an authority's revoke of a key that already rotated withdraws the successor it named")
    seq("rotation-by-someone-else-is-refused", {"pinned": [A.agent], "follow_rotation": True, "authorities": [AUTH.agent]},
        [rv(env(AUTH, "revocation", {"subject": A.agent, "action": "rotate", "successor": A2.agent, "reason": "x", "effective_at": NOW}, n=49, ttl=None), expect="untrusted"),
         rx(receiving(50, A2), expect="untrusted"), rx(receiving(51))], "only an identity can rotate itself")
    return S


# ------------------------------------------------------------------------------------------------ decisions
def exchange(*, ttl_ms: int = 60_000, verdict: str = "pass", body_over: Optional[Dict[str, Any]] = None, n: int = 100,
             reply: Optional[str] = None, evidence_digest: Optional[str] = None, evidence: bool = True) -> Dict[str, Any]:
    subject = {"identity": "loan-1", "digest": "cd" * 32}
    terms = {"capability": "income-screen", "version": 1, "decider": B.agent, "requester": A.agent, "subject": subject,
             "disclose": ["monthly_income_cents"], "evidence": ["threshold-check"], "decision_ttl_ms": ttl_ms}
    offer_digest = hashlib.sha256(f"offer-{n}".encode()).hexdigest()
    accept = env(A, "accept", {"terms_digest": digest(terms), "disclosure": None}, to=B.agent, n=n, reply=offer_digest)
    content = {"observed": 1}
    ev = [{"kind": "threshold-check", "content": content, "digest": evidence_digest or digest(content)}] if (evidence and verdict == "pass") else []
    body = {"verdict": verdict, "terms_digest": digest(terms), "subject": subject, "reasons": ["because"], "evidence": ev, "cns_root": ""}
    body.update(body_over or {})
    decision = env(B, "decision", body, to=A.agent, n=n + 1, ttl=ttl_ms, reply=reply or digest(accept))
    return {"terms": terms, "accept_digest": digest(accept), "decision": decision, "subject": [subject["identity"], subject["digest"]]}


def decision_sequences() -> List[Dict[str, Any]]:
    S: List[Dict[str, Any]] = []
    base = {"acting_for": A.agent, "capability": ["income-screen", 1], "pinned": [B.agent], "authorities": [], "max_staleness_ms": None}

    def seq(name, steps, why, **cfg):
        S.append({"id": f"decision/{name}", "config": {**base, **cfg}, "steps": steps, "why": why})

    def auth(x, now=NOW + 1, expect="ok", lease_ms=None, terms=None, accept_digest=None):
        return {"op": "authorize", "decision": x["decision"], "terms": terms or x["terms"], "accept_digest": accept_digest or x["accept_digest"],
                "now": now, "lease_ms": lease_ms, "expect": expect}

    def use(x, artifact=None, now=NOW + 1, expect="true"):
        return {"op": "use", "artifact": artifact or x["subject"], "now": now, "expect": expect}

    x = exchange(n=100)
    seq("one-action-on-the-one-document", [auth(x), use(x, ["loan-1", "other"], expect="false"), use(x), use(x, expect="false")],
        "permission opens once, for the judged document only, and not again")
    seq("replay-on-a-shared-ledger", [auth(x), {"op": "new_guard", "expect": "ok"}, auth(x, expect="replayed")], "a second guard on the same ledger cannot redeem the decision again")
    seq("capability-mismatch", [auth(x, expect="terms")], "a decision negotiated for one capability does not open an action guarded for another", capability=["other", 1])
    seq("version-mismatch", [auth(x, expect="terms")], "nor for another version of the same capability", capability=["income-screen", 2])
    seq("audience-mismatch", [auth(x, expect="audience")], "terms for a requester this guard does not act for", acting_for=EVE.agent)
    seq("decider-not-trusted", [auth(x, expect="untrusted")], "a valid signature from a decider this guard does not trust is not permission", pinned=[EVE.agent])
    seq("expiry-boundary", [auth(exchange(n=102), now=NOW + 60_000, expect="expired"), {"op": "new_guard", "expect": "ok"}, auth(exchange(n=104), now=NOW + 59_999)],
        "a decision is valid until, not including, its expiry")
    y = exchange(n=106)
    altered = {**y["terms"], "disclose": ["doc_type", "monthly_income_cents"]}
    seq("terms-altered", [auth(y, terms=altered, expect="terms")], "the decision names the exact terms it was made under")
    seq("answers-another-accept", [auth(exchange(n=108), accept_digest="ef" * 32, expect="terms")], "bound to the exact accept it answers")
    seq("retry-verdict-opens-nothing", [auth(exchange(n=110, verdict="retry"), expect="refused"), use(x, expect="false")], "a verified retry is not a pass")
    z = exchange(n=112)
    seq("decider-revoked-after-authorize", [auth(z), {"op": "revoke_decider", "now": NOW + 2, "expect": "ok"}, use(z, now=NOW + 3, expect="false")],
        "trust was checked at authorize; a revocation that arrives after it closes the guard")
    seq("evidence-digest-mismatch", [auth(exchange(n=114, evidence_digest="00" * 32), expect="malformed")], "evidence must match its digest even from the real decider")
    seq("extra-body-field", [auth(exchange(n=116, body_over={"surprise": 1}), expect="malformed")], "a decision body has exactly its fields")
    seq("unknown-verdict", [auth(exchange(n=118, body_over={"verdict": "maybe"}), expect="malformed")], "the verdicts are pass, retry, terminal_breach")
    seq("pass-without-its-evidence", [auth(exchange(n=120, evidence=False), expect="terms")], "a pass carries exactly the evidence the terms require")
    w = exchange(n=122)
    seq("lease-survives-a-crash", [auth(w, lease_ms=10_000), use(w), {"op": "new_guard", "expect": "ok"}, auth(w, now=NOW + 5_000, lease_ms=10_000, expect="replayed"),
                                   {"op": "new_guard", "expect": "ok"}, auth(w, now=NOW + 10_002, lease_ms=10_000), use(w, now=NOW + 10_003), {"op": "complete", "now": NOW + 10_004, "expect": "ok"},
                                   {"op": "new_guard", "expect": "ok"}, auth(w, now=NOW + 10_005, lease_ms=10_000, expect="replayed")],
        "while a lease is live nobody else redeems; once it lapses a retry can; once committed it is spent for good")
    return S


def build() -> Dict[str, Any]:
    return {
        "schema": "uai-interop-vectors/1",
        "note": "Independent answer key for the UAI-1 interoperability campaign. Every expected result was typed by hand with its "
                "reason; signatures come from the OpenSSL command line; no implementation produced any expectation. "
                "Regenerate with interop/vectors/make_interop_vectors.py. Public test seeds: 0x51..0x55 repeated 32 times.",
        "keys": {n: {"seed": k.seed.hex(), "agent": k.agent} for n, k in {"requester": A, "decider": B, "authority": AUTH, "eve": EVE, "other": C}.items()},
        "now": NOW,
        "digest": digest_cases(), "wire": wire_cases(), "envelope": envelope_cases(), "negotiation": negotiation_cases(),
        "sequences": sequences(), "decisions": decision_sequences(),
    }


def main(argv: List[str]) -> int:
    got = json.dumps(build(), indent=1, sort_keys=True, ensure_ascii=True) + "\n"
    if "--check" in argv:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != got:
            print("contracts/uai-interop-vectors.json is not what this generator produces", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(got, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
