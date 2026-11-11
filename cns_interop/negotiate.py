"""negotiate: two systems agreeing what one will decide, on what, seeing what, before anything is disclosed.

THE EXCHANGE

    requester -> decider   request   capability and version, the document (identity and digest only), the fields the
                                     requester is WILLING to disclose, the evidence it NEEDS back, the longest it will
                                     accept a decision living
    decider   -> requester offer     the terms, or a refuse naming why
    requester -> decider   accept    the terms' digest, and the disclosure of exactly the agreed fields
    decider   -> requester decision  a signed verdict bound to the terms and the document (decision.py)

Each side keeps its own authority throughout. The decider sets the terms and may refuse; the requester checks the
terms against what it asked (`check_terms`) and may refuse them. Nothing is disclosed until both have agreed, and only
the agreed fields are disclosed then.

THE TERMS

    capability, version   what is being exercised
    decider, requester    the two identities, so terms cannot be lifted into another pair's exchange
    subject               {"identity", "digest"}: the one document (disclosure.py gives the digest)
    disclose              the fields the decider will see: what the requester offered AND the capability accepts.
                          Every field the capability requires must be in it, or there is no deal.
    evidence              exactly the evidence kinds the requester needs; each must be one the capability returns
    decision_ttl_ms       the shorter of the capability's limit and the requester's

`terms_digest` (the CNS subject digest of the terms) is what the accept and the decision carry, so a decision
always names the precise terms it was made under.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping

from cns.gate import subject_digest

from .envelope import Refused
from .identity import is_agent_id
from .manifest import NAME, Capability

__all__ = ["request_body", "read_request", "propose_terms", "check_terms", "terms_digest", "TERMS_KEYS"]

_REQ_KEYS = {"capability", "version", "subject", "offer_fields", "require_evidence", "max_ttl_ms"}
TERMS_KEYS = frozenset({"capability", "version", "decider", "requester", "subject", "disclose", "evidence",
                        "decision_ttl_ms"})


def _pos_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


def _subject(v: Any) -> Dict[str, str]:
    if not isinstance(v, Mapping) or set(v) != {"identity", "digest"} or not all(
            isinstance(v[k], str) and v[k] for k in ("identity", "digest")):
        raise Refused("malformed", "a subject is exactly identity and digest, both non-empty text")
    return {"identity": v["identity"], "digest": v["digest"]}


def _names(v: Any, what: str) -> list:
    if not isinstance(v, list) or not all(isinstance(n, str) and NAME.match(n) for n in v) or len(set(v)) != len(v):
        raise Refused("malformed", f"{what} is a list of distinct lowercase names")
    return sorted(v)


def request_body(capability: str, version: int, *, identity: str, digest: str, offer_fields: Iterable[str],
                 require_evidence: Iterable[str] = (), max_ttl_ms: int) -> Dict[str, Any]:
    body = {"capability": capability, "version": version, "subject": {"identity": identity, "digest": digest},
            "offer_fields": sorted(offer_fields), "require_evidence": sorted(require_evidence),
            "max_ttl_ms": max_ttl_ms}
    return read_request(body)


def read_request(body: Any) -> Dict[str, Any]:
    if not isinstance(body, Mapping) or set(body) != _REQ_KEYS:
        raise Refused("malformed", "a request body has exactly: " + ", ".join(sorted(_REQ_KEYS)))
    if not (isinstance(body["capability"], str) and NAME.match(body["capability"])) or not _pos_int(body["version"]):
        raise Refused("malformed", "a request names a capability and a positive version")
    if not _pos_int(body["max_ttl_ms"]):
        raise Refused("malformed", "max_ttl_ms is a positive integer")
    return {"capability": body["capability"], "version": body["version"], "subject": _subject(body["subject"]),
            "offer_fields": _names(body["offer_fields"], "offer_fields"),
            "require_evidence": _names(body["require_evidence"], "require_evidence"), "max_ttl_ms": body["max_ttl_ms"]}


def propose_terms(cap: Capability, request: Mapping[str, Any], *, decider: str, requester: str) -> Dict[str, Any]:
    """The decider's side: the terms it will work on for this request, or Refused('terms') saying what cannot be met."""
    req = read_request(request)
    if (req["capability"], req["version"]) != (cap.name, cap.version):
        raise Refused("capability", "the request is for a different capability or version")
    withheld = sorted(set(cap.requires) - set(req["offer_fields"]))
    if withheld:
        raise Refused("terms", "the capability must see fields the requester will not disclose: " + ", ".join(withheld))
    unavailable = sorted(set(req["require_evidence"]) - set(cap.evidence))
    if unavailable:
        raise Refused("terms", "the requester needs evidence this capability does not produce: "
                      + ", ".join(unavailable))
    return {"capability": cap.name, "version": cap.version, "decider": decider, "requester": requester,
            "subject": req["subject"], "disclose": sorted(set(req["offer_fields"]) & set(cap.accepts)),
            "evidence": req["require_evidence"], "decision_ttl_ms": min(cap.max_ttl_ms, req["max_ttl_ms"])}


def check_terms(terms: Any, request: Mapping[str, Any], *, decider: str, requester: str) -> Dict[str, Any]:
    """The requester's side: refuse terms that ask for more than was offered or give less than was needed."""
    req = read_request(request)
    if not isinstance(terms, Mapping) or set(terms) != TERMS_KEYS:
        raise Refused("malformed", "terms have exactly: " + ", ".join(sorted(TERMS_KEYS)))
    if terms["decider"] != decider or terms["requester"] != requester or not (
            is_agent_id(decider) and is_agent_id(requester)):
        raise Refused("terms", "the terms name a different decider or requester")
    if (terms["capability"], terms["version"]) != (req["capability"], req["version"]):
        raise Refused("terms", "the terms are for a different capability or version")
    if _subject(terms["subject"]) != req["subject"]:
        raise Refused("terms", "the terms are for a different document")
    disclose = _names(terms["disclose"], "disclose")
    if not set(disclose) <= set(req["offer_fields"]):
        raise Refused("terms", "the terms ask to see fields that were not offered: "
                      + ", ".join(sorted(set(disclose) - set(req["offer_fields"]))))
    if _names(terms["evidence"], "evidence") != req["require_evidence"]:
        raise Refused("terms", "the terms do not return exactly the evidence that was required")
    ttl = terms["decision_ttl_ms"]
    if not _pos_int(ttl) or ttl > req["max_ttl_ms"]:
        raise Refused("terms", "the terms let a decision live longer than the requester allows")
    return dict(terms)


def terms_digest(terms: Mapping[str, Any]) -> str:
    return subject_digest(dict(terms))
