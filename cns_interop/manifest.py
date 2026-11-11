"""manifest: an agent describing, in a signed message, what it can do and on what terms.

A manifest is how one system discovers another without a shared registry. It lists each capability by name and
version, the document fields the capability can use (`accepts`) and must see (`requires`), the evidence it can return,
and the longest a decision from it stays valid. It names the protocol versions the agent speaks; a reader that shares
none refuses, rather than guessing at a dialect. It may carry endorsements, so a receiver that does not know the agent
can still admit it through an authority it does know (trust.py).

A manifest is a claim, not a contract. The contract is the `offer` the agent signs for one request (negotiate.py), and
the agent may refuse a request its manifest seems to allow. That keeps the agent its own authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Sequence, Tuple

from .envelope import VERSION, Envelope, Refused, open_envelope, seal
from .identity import Signer
from .trust import MAX_ENDORSEMENTS, Admission, TrustPolicy

__all__ = ["Capability", "Manifest", "publish", "read_manifest", "NAME"]

NAME = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,63}\Z")
MAX_CAPABILITIES = 64
_CAP_KEYS = {"name", "version", "summary", "accepts", "requires", "evidence", "max_ttl_ms"}
_MAN_KEYS = {"name", "implementation", "protocols", "capabilities", "endorsements"}


def _names(value: Any, what: str) -> Tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not all(isinstance(v, str) and NAME.match(v) for v in value):
        raise Refused("malformed", f"{what} must be a list of lowercase names")
    if len(set(value)) != len(value):
        raise Refused("malformed", f"{what} lists a name twice")
    return tuple(sorted(value))


@dataclass(frozen=True)
class Capability:
    name: str
    version: int
    summary: str
    accepts: Tuple[str, ...]
    requires: Tuple[str, ...]
    evidence: Tuple[str, ...]
    max_ttl_ms: int

    def __post_init__(self) -> None:
        if not (isinstance(self.name, str) and NAME.match(self.name)):
            raise Refused("malformed", "a capability name is a lowercase name")
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 1:
            raise Refused("malformed", "a capability version is a positive integer")
        if not isinstance(self.summary, str):
            raise Refused("malformed", "a capability summary is text")
        for what in ("accepts", "requires", "evidence"):
            object.__setattr__(self, what, _names(getattr(self, what), what))
        if not set(self.requires) <= set(self.accepts):
            raise Refused("malformed", "a capability cannot require a field it does not accept")
        if isinstance(self.max_ttl_ms, bool) or not isinstance(self.max_ttl_ms, int) or self.max_ttl_ms <= 0:
            raise Refused("malformed", "max_ttl_ms is a positive integer")

    def to_body(self) -> Mapping[str, Any]:
        return {"name": self.name, "version": self.version, "summary": self.summary, "accepts": list(self.accepts),
                "requires": list(self.requires), "evidence": list(self.evidence), "max_ttl_ms": self.max_ttl_ms}

    @classmethod
    def from_body(cls, body: Any) -> "Capability":
        if not isinstance(body, Mapping) or set(body) != _CAP_KEYS:
            raise Refused("malformed", "a capability has exactly: " + ", ".join(sorted(_CAP_KEYS)))
        return cls(**{k: body[k] for k in _CAP_KEYS})


@dataclass(frozen=True)
class Manifest:
    agent: str
    name: str
    implementation: str
    protocols: Tuple[str, ...]
    capabilities: Tuple[Capability, ...]
    endorsements: Tuple[Mapping[str, Any], ...]
    envelope: Envelope

    def capability(self, name: str, version: int) -> Capability:
        for cap in self.capabilities:
            if cap.name == name and cap.version == version:
                return cap
        raise Refused("capability", f"{self.name} does not offer {name} version {version}")


def publish(signer: Signer, name: str, implementation: str, capabilities: Sequence[Capability], *,
            endorsements: Iterable[Envelope] = (), ttl_ms: Optional[int] = None, now: Optional[int] = None) -> Envelope:
    """Sign a manifest, broadcast (addressed to no one in particular)."""
    caps = list(capabilities)
    if len({(c.name, c.version) for c in caps}) != len(caps):
        raise ValueError("a capability name and version appear twice")
    body = {"name": name, "implementation": implementation, "protocols": [VERSION],
            "capabilities": [c.to_body() for c in caps], "endorsements": [e.to_wire() for e in endorsements]}
    return seal(signer, "manifest", body, ttl_ms=ttl_ms, now=now)


def read_manifest(wire: Mapping[str, Any], *, now: Optional[int] = None, trust: Optional[TrustPolicy] = None,
                  domain: Optional[str] = None) -> Tuple[Manifest, Optional[Admission]]:
    """Check a manifest completely. With `trust`, also admit its sender (Refused 'untrusted' if not admitted)."""
    env = open_envelope(wire, now=now, kinds={"manifest"})
    body = env.body
    if set(body) != _MAN_KEYS:
        raise Refused("malformed", "a manifest body has exactly: " + ", ".join(sorted(_MAN_KEYS)))
    if not isinstance(body["name"], str) or not isinstance(body["implementation"], str):
        raise Refused("malformed", "a manifest's name and implementation are text")
    protocols = body["protocols"]
    if not isinstance(protocols, list) or not all(isinstance(p, str) for p in protocols):
        raise Refused("malformed", "protocols is a list of version names")
    if VERSION not in protocols:
        raise Refused("version", f"the agent speaks {', '.join(protocols) or 'nothing'}; this reader speaks {VERSION}")
    if not isinstance(body["capabilities"], list) or not isinstance(body["endorsements"], list):
        raise Refused("malformed", "capabilities and endorsements are lists")
    if len(body["endorsements"]) > MAX_ENDORSEMENTS or len(body["capabilities"]) > MAX_CAPABILITIES:
        raise Refused("malformed", f"a manifest carries at most {MAX_ENDORSEMENTS} endorsements and "
                                   f"{MAX_CAPABILITIES} capabilities")
    caps = tuple(Capability.from_body(c) for c in body["capabilities"])
    if len({(c.name, c.version) for c in caps}) != len(caps):
        raise Refused("malformed", "a capability name and version appear twice")
    manifest = Manifest(agent=env.sender, name=body["name"], implementation=body["implementation"],
                        protocols=tuple(protocols), capabilities=caps, endorsements=tuple(body["endorsements"]),
                        envelope=env)
    admission = trust.admit(env.sender, manifest.endorsements, now=now, domain=domain) if trust is not None else None
    return manifest, admission
