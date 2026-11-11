"""envelope: the one shape every UAI-1 message takes, signed so the receiver can check it alone.

WHY THIS EXISTS

CNS's contracts let two systems agree on what a decision MEANS. They did not say how one system hands another a
request, an offer or a decision, or how the receiver tells a genuine message from a forged, edited, replayed or
expired one. Without that, "interoperable" meant "imports the same Python package in the same process".

An envelope is a small, fixed set of fields around a free-form `body`:

    v            "uai/1", the protocol version. Anything else is refused, never guessed at.
    kind         what the message is (KINDS; `revocation` was added after the first release, see docs/migrations).
    id           32 random hex digits, unique per message; a receiver's ledger refuses a second use.
    from         the sender's identity (identity.py). The signature must verify as this key.
    to           the one identity it is addressed to, or "" for a broadcast such as a manifest.
    conversation the id of the message that opened the exchange.
    in_reply_to  the digest of the envelope this answers, or "". A reply is bound to exact content, not to an id.
    issued_at    milliseconds since the epoch, an integer.
    expires_at   milliseconds, an integer after issued_at, or null for a message that does not expire.
    body         a mapping, in the profile below.
    sig          Ed25519 over the domain tag "uai/1 sig\\n" and the CNS subject digest of every other field.

The digest is `cns.gate.subject_digest`, the length-prefixed canonical encoding CNS already publishes with
cross-language vectors (contracts/digest-vectors.json). JSON is only the transport; two senders that write the same
envelope with different spacing or key order produce the same signature input.

THE PROFILE

Values are text, booleans, null, integers within +/-(2**53 - 1), lists, and mappings with text keys. Floats are
refused: every runtime renders a float its own way, and a signature that one implementation cannot reproduce is a
signature that implementation cannot check. Send a decimal as text or as an integer in the smallest unit. Nesting is
limited to 32 levels and the wire form to 1 MiB.

WHAT IT DOES NOT DO

It authenticates; it does not encrypt. An envelope on an open channel can be read by anyone on it. Confidentiality is
the transport's job (TLS, an SSH pipe, a sealed queue); see docs/interop/UAI-1.md for what that leaves open.
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, Mapping, Optional

from cns.gate import subject_digest

from . import crypto_backend
from .identity import Signer, is_agent_id, public_of

__all__ = ["VERSION", "KINDS", "FIELDS", "Envelope", "Refused", "seal", "sign_envelope", "open_envelope", "now_ms",
           "check_profile", "MAX_INT", "MAX_DEPTH", "bounded_nodes"]

VERSION = "uai/1"
KINDS: FrozenSet[str] = frozenset({
    "manifest",     # what an agent can do and on what terms (manifest.py)
    "endorsement",  # an authority vouching for an agent (trust.py)
    "request",      # asking an agent to exercise a capability
    "offer",        # the terms the agent will work on
    "accept",       # the requester agreeing to those terms, with what it discloses
    "refuse",       # either side declining, with reasons
    "decision",     # the agent's signed verdict (decision.py)
    "revocation",   # a signed statement that an identity or endorsement is no longer trusted, or was replaced
})
FIELDS: FrozenSet[str] = frozenset({"v", "kind", "id", "from", "to", "conversation", "in_reply_to", "issued_at",
                                    "expires_at", "body", "sig"})
MAX_INT = 2 ** 53 - 1
MAX_DEPTH = 32
_HEX32 = re.compile(r"\A[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_HEX128 = re.compile(r"\A[0-9a-f]{128}\Z")
_SIG_TAG = b"uai/1 sig\n"


class Refused(Exception):
    """A message, or a step of an exchange, that a receiver will not act on. `code` is stable; `reason` is for people."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason


def now_ms() -> int:
    return int(time.time() * 1000)


def check_profile(value: Any, *, where: str = "body", depth: int = 0) -> None:
    """Raise Refused('profile') unless `value` is in the UAI-1 value profile (see the module docstring)."""
    if depth > MAX_DEPTH:
        raise Refused("profile", f"{where} nests deeper than {MAX_DEPTH} levels")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -MAX_INT <= value <= MAX_INT:
            raise Refused("profile", f"{where} holds an integer outside +/-(2**53 - 1), which not every runtime "
                                     "can represent exactly")
        return
    if isinstance(value, float):
        raise Refused("profile", f"{where} holds a float; send it as text or as an integer in the smallest unit")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise Refused("profile", f"{where} holds text that is not valid Unicode") from None
        return
    if isinstance(value, Mapping):
        for k, v in value.items():
            if not isinstance(k, str):
                raise Refused("profile", f"{where} has a key that is not text")
            check_profile(k, where=where, depth=depth + 1)
            check_profile(v, where=f"{where}.{k}", depth=depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            check_profile(v, where=f"{where}[{i}]", depth=depth + 1)
        return
    raise Refused("profile", f"{where} holds a {type(value).__name__}, which UAI-1 does not carry")


def bounded_nodes(value: Any, limit: int) -> int:
    """Count the values in `value` without recursion, and refuse (Refused('profile')) as soon as the count would pass
    `limit`. Children are counted from their container's LENGTH before any of them is visited, so the work done is at most
    `limit` steps however large one list or mapping is: a 2-million-element list costs the same to refuse as a small one."""
    seen, stack = 1, [value]
    if seen > limit:
        raise Refused("profile", f"the message holds more than {limit} values, which this receiver does not read")
    while stack:
        v = stack.pop()
        if isinstance(v, Mapping):
            seen += 2 * len(v)
            children: Any = None
        elif isinstance(v, (list, tuple)):
            seen += len(v)
            children = v
        else:
            continue
        if seen > limit:
            raise Refused("profile", f"the message holds more than {limit} values, which this receiver does not read")
        if isinstance(v, Mapping):
            stack.extend(v.keys())
            stack.extend(v.values())
        else:
            stack.extend(children)
    return seen


def _plain(value: Any) -> Any:
    """A deep copy as plain dicts and lists, so a sealed envelope cannot be changed through a reference."""
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


@dataclass(frozen=True)
class Envelope:
    """A sealed message. Build one with `seal`; read one from the wire with `open_envelope`."""

    kind: str
    id: str
    sender: str
    to: str
    conversation: str
    in_reply_to: str
    issued_at: int
    expires_at: Optional[int]
    body: Dict[str, Any] = field(default_factory=dict)
    sig: str = ""

    def unsigned(self) -> Dict[str, Any]:
        return {"v": VERSION, "kind": self.kind, "id": self.id, "from": self.sender, "to": self.to,
                "conversation": self.conversation, "in_reply_to": self.in_reply_to, "issued_at": self.issued_at,
                "expires_at": self.expires_at, "body": _plain(self.body)}

    def to_wire(self) -> Dict[str, Any]:
        """The envelope as a plain mapping, ready for `wire.dumps`."""
        return {**self.unsigned(), "sig": self.sig}

    @property
    def digest(self) -> str:
        """The digest of the whole signed envelope: what a reply's `in_reply_to` names."""
        return subject_digest(self.to_wire())


def _signing_input(unsigned: Mapping[str, Any]) -> bytes:
    return _SIG_TAG + subject_digest(unsigned).encode("ascii")


def seal(signer: Signer, kind: str, body: Mapping[str, Any], *, to: str = "", reply_to: Optional[Envelope] = None,
         conversation: Optional[str] = None, ttl_ms: Optional[int] = None, now: Optional[int] = None) -> Envelope:
    """Sign a new message. A reply (`reply_to`) inherits the conversation and names the exact envelope it answers."""
    if kind not in KINDS:
        raise ValueError(f"unknown kind {kind!r}")
    if to and not is_agent_id(to):
        raise ValueError("to must be an agent identity, or empty for a broadcast")
    if ttl_ms is not None and (isinstance(ttl_ms, bool) or not isinstance(ttl_ms, int) or ttl_ms <= 0):
        raise ValueError("ttl_ms must be a positive integer, or None")
    body = _plain(body)
    if not isinstance(body, dict):
        raise ValueError("body must be a mapping")
    check_profile(body)
    issued = now_ms() if now is None else now
    msg_id = secrets.token_hex(16)
    if reply_to is not None:
        conv, in_reply_to = reply_to.conversation, reply_to.digest
    else:
        conv, in_reply_to = conversation or msg_id, ""
    env = Envelope(kind=kind, id=msg_id, sender=signer.agent, to=to, conversation=conv, in_reply_to=in_reply_to,
                   issued_at=issued, expires_at=issued + ttl_ms if ttl_ms is not None else None, body=body)
    sig = signer.sign(_signing_input(env.unsigned()))
    return Envelope(**{**env.__dict__, "sig": sig.hex()})


def sign_envelope(signer: Signer, env: Envelope) -> Envelope:
    """Sign an envelope whose every field is already chosen. For reproducible vectors and for other front ends;
    `seal` is the ordinary way to make a message, and draws a fresh id itself."""
    if env.sender != signer.agent:
        raise ValueError("the envelope names a different sender than the signer")
    check_profile(env.body)
    sig = signer.sign(_signing_input(env.unsigned()))
    return Envelope(**{**env.__dict__, "body": _plain(env.body), "sig": sig.hex()})


def _need(cond: bool, reason: str) -> None:
    if not cond:
        raise Refused("malformed", reason)


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def open_envelope(wire: Mapping[str, Any], *, now: Optional[int] = None, skew_ms: int = 120_000,
                  audience: Optional[str] = None, kinds: Optional[Iterable[str]] = None,
                  max_nodes: Optional[int] = None) -> Envelope:
    """Check a received envelope completely and return it, or raise Refused saying why.

    Checked: exactly the UAI-1 fields and no others, the version, the kind (and that it is one of `kinds`, if given),
    every field's form, the value profile, the signature against `from`, that it was not issued more than `skew_ms`
    in the future, that it has not expired, and, when `audience` is given, that it is addressed to exactly that
    identity. Replay is NOT checked here: that needs the receiver's memory (ledger.py)."""
    _need(isinstance(wire, Mapping), "an envelope is a mapping")
    keys = set(wire.keys())
    _need(keys == FIELDS, "fields missing: " + ", ".join(sorted(FIELDS - keys)) if FIELDS - keys
          else "fields UAI-1 does not define: " + ", ".join(sorted(map(str, keys - FIELDS))))
    if wire["v"] != VERSION:
        raise Refused("version", f"this receiver speaks {VERSION}, the envelope says {wire['v']!r}")
    _need(isinstance(wire["kind"], str) and wire["kind"] in KINDS, f"unknown kind {wire['kind']!r}")
    if kinds is not None and wire["kind"] not in set(kinds):
        raise Refused("kind", f"a {wire['kind']} is not what this step accepts")
    _need(isinstance(wire["id"], str) and _HEX32.match(wire["id"]) is not None, "id is not 32 hex digits")
    _need(is_agent_id(wire["from"]), "from is not an agent identity")
    _need(wire["to"] == "" or is_agent_id(wire["to"]), "to is not an agent identity or empty")
    _need(isinstance(wire["conversation"], str) and _HEX32.match(wire["conversation"]) is not None,
          "conversation is not 32 hex digits")
    _need(wire["in_reply_to"] == "" or (isinstance(wire["in_reply_to"], str)
                                         and _HEX64.match(wire["in_reply_to"]) is not None),
          "in_reply_to is not an envelope digest or empty")
    _need(_is_int(wire["issued_at"]) and 0 <= wire["issued_at"] <= MAX_INT, "issued_at is not a time in ms")
    _need(wire["expires_at"] is None or (_is_int(wire["expires_at"]) and wire["issued_at"] < wire["expires_at"]
                                         <= MAX_INT), "expires_at is not a time after issued_at")
    _need(isinstance(wire["body"], Mapping), "body is not a mapping")
    _need(isinstance(wire["sig"], str) and _HEX128.match(wire["sig"]) is not None, "sig is not 128 hex digits")
    if max_nodes is not None:
        bounded_nodes(wire["body"], max_nodes)  # a receiver's own bound, applied before any per-value or signature work
    check_profile(wire["body"])
    env = Envelope(kind=wire["kind"], id=wire["id"], sender=wire["from"], to=wire["to"],
                   conversation=wire["conversation"], in_reply_to=wire["in_reply_to"], issued_at=wire["issued_at"],
                   expires_at=wire["expires_at"], body=_plain(wire["body"]), sig=wire["sig"])
    if not crypto_backend.verify(public_of(env.sender), _signing_input(env.unsigned()), bytes.fromhex(env.sig)):
        raise Refused("signature", "the signature does not verify as the sender, so the envelope was forged or "
                                   "changed after it was signed")
    t = now_ms() if now is None else now
    if env.issued_at > t + skew_ms:
        raise Refused("not_yet_valid", "the envelope is dated in the future beyond the allowed clock skew")
    if env.expires_at is not None and t >= env.expires_at:
        raise Refused("expired", "the envelope has expired")
    if audience is not None and env.to != audience:
        raise Refused("audience", "the envelope is addressed to " + (env.to or "everyone") + ", not to this receiver")
    return env
