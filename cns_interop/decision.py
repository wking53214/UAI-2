"""decision: a verdict another system can check on its own, and a guard that acts on it once.

WHY THIS EXISTS

`SuperGate.decide` proves its decisions with an HMAC under a key that never leaves the process, and `DecisionGuard`
spends a decision's nonce in a set that lives in the same process. Both are right for one process and say nothing to
any other. This module is the distributed counterpart:

  `issue` signs a decision as a UAI-1 envelope, bound to the exact terms, the exact document, the exact accept it
    answers and the one identity it is addressed to, and expiring when the terms say.
  `from_super_gate` exports a CNS `Decision` that THIS process's SuperGate issued (`decision.issued`). A hand-built
    or edited Decision is refused at export, so the in-process proof is not laundered into a signature.
  `verify_decision` is everything the receiving system checks, with no access to the decider: the signature, that
    the signer is the decider the terms name, the audience, the reply binding, the terms digest, the document, the
    evidence, that the decision lives no longer than agreed, and (through its ledger) that it is new.
  `RemoteDecisionGuard` is `DecisionGuard` for a decision that came from elsewhere: closed until a verified, allowed
    decision opens it, then permits one action on the one document. Its ledger may be a `FileLedger`, so the
    process that performs the action need not be the one that received the decision.

The verdict vocabulary is CNS's own `GateOutcome`: "pass", "retry", "terminal_breach".
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple

from cns.gate import GateOutcome, subject_digest

from .envelope import Envelope, Refused, now_ms, open_envelope, seal
from .identity import Signer, is_agent_id
from .ledger import Ledger, Reservation
from .manifest import NAME
from .negotiate import TERMS_KEYS, terms_digest
from .trust import TrustPolicy

__all__ = ["VERDICTS", "Verified", "issue", "from_super_gate", "verify_decision", "RemoteDecisionGuard"]

VERDICTS = tuple(o.value for o in GateOutcome)
_BODY_KEYS = {"verdict", "terms_digest", "subject", "reasons", "evidence", "cns_root"}


def _evidence_list(evidence: Mapping[str, Mapping[str, Any]]) -> list:
    return [{"kind": k, "content": dict(v), "digest": subject_digest(dict(v))} for k, v in sorted(evidence.items())]


def issue(signer: Signer, accept: Envelope, terms: Mapping[str, Any], verdict: str, *, reasons: Sequence[str] = (),
          evidence: Optional[Mapping[str, Mapping[str, Any]]] = None, cns_root: str = "",
          now: Optional[int] = None) -> Envelope:
    """Sign a decision answering `accept`, under `terms`. A pass must carry exactly the evidence the terms name."""
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}")
    if signer.agent != terms["decider"]:
        raise ValueError("only the decider the terms name can issue this decision")
    evidence = dict(evidence or {})
    if verdict == GateOutcome.PASS.value and sorted(evidence) != list(terms["evidence"]):
        raise ValueError("a pass must carry exactly the evidence the terms require: " + ", ".join(terms["evidence"]))
    if not set(evidence) <= set(terms["evidence"]):
        raise ValueError("evidence the terms did not ask for is not sent")
    body = {"verdict": verdict, "terms_digest": terms_digest(terms), "subject": dict(terms["subject"]),
            "reasons": list(reasons), "evidence": _evidence_list(evidence), "cns_root": cns_root}
    return seal(signer, "decision", body, to=terms["requester"], reply_to=accept,
                ttl_ms=terms["decision_ttl_ms"], now=now)


def from_super_gate(signer: Signer, accept: Envelope, terms: Mapping[str, Any], decision: Any, *,
                    evidence: Optional[Mapping[str, Mapping[str, Any]]] = None, now: Optional[int] = None) -> Envelope:
    """Export a SuperGate Decision. It must have been issued by a SuperGate in this process, and an allowed one must
    have judged the very document the terms name. A pass that `allowed` does not confirm goes out as a breach."""
    from cns_composition.super_gate import Decision

    if not isinstance(decision, Decision) or not decision.issued:
        raise ValueError("only a decision a SuperGate in this process issued can be exported")
    if decision.allowed:
        subject = decision.subject
        if subject is None or (subject.identity, subject.digest) != (terms["subject"]["identity"],
                                                                     terms["subject"]["digest"]):
            raise ValueError("the SuperGate judged a different document than the terms name")
        verdict = GateOutcome.PASS.value
    else:
        verdict = decision.outcome.value if decision.outcome is not GateOutcome.PASS else \
            GateOutcome.TERMINAL_BREACH.value
    return issue(signer, accept, terms, verdict, reasons=decision.reasons(),
                 evidence=evidence if verdict == GateOutcome.PASS.value else None, cns_root=decision.root, now=now)


@dataclass(frozen=True)
class Verified:
    """A decision that passed every check. `allowed` is True only for a pass."""

    verdict: str
    reasons: Tuple[str, ...]
    evidence: Mapping[str, Mapping[str, Any]]
    subject: Mapping[str, str]
    cns_root: str
    envelope: Envelope
    #: Set when the decision was taken under a lease (`lease_ms`): the idempotency key and the lease to commit or release.
    reservation: Optional[Reservation] = None

    @property
    def allowed(self) -> bool:
        return self.verdict == GateOutcome.PASS.value

    @property
    def terms_digest(self) -> str:
        """The digest of the exact terms this decision was made under, as the decider signed it. A receiver that acts
        on the decision must hold terms that hash to this, or it is acting on terms the decision never named."""
        return str(self.envelope.body["terms_digest"])


def _redeem(ledger: Any, env: Envelope, now: Optional[int], lease_ms: Optional[int]) -> Optional[Reservation]:
    """Spend the decision, or lease it when `lease_ms` is given. A ledger that cannot give a definite answer (any
    error that is not a refusal) means there is no authoritative state, so the answer is Refused('unavailable'):
    permission is never inferred from a failure to check."""
    try:
        if lease_ms is not None:
            reserve = getattr(ledger, "reserve", None)
            if reserve is None:
                raise ValueError("lease_ms needs a ledger with reserve, commit and release")
            got: Reservation = reserve(env.sender, env.id, env.expires_at, lease_ms=lease_ms, now=now)
            return got
        try:
            ledger.spend(env.sender, env.id, env.expires_at, now=now)
        except TypeError as exc:
            if "'now'" not in str(exc):
                raise
            ledger.spend(env.sender, env.id, env.expires_at)  # a ledger written before spend took the clock
        return None
    except (Refused, ValueError):
        raise
    except Exception as exc:
        raise Refused("unavailable", "the ledger could not say whether this decision is new, so it is not "
                                     f"accepted ({type(exc).__name__})") from None


def verify_decision(wire: Mapping[str, Any], *, terms: Mapping[str, Any], accept_digest: str, ledger: Ledger,
                    now: Optional[int] = None, lease_ms: Optional[int] = None) -> Verified:
    """Check a decision completely, as the requester (or anyone acting for it) holding only public information.

    With `lease_ms` the decision is leased, not spent: the returned `Verified.reservation` must be committed when the
    action is done or released when it was not (see ledger.py, TWO PHASES)."""
    if not isinstance(terms, Mapping) or set(terms) != TERMS_KEYS:
        raise Refused("terms", "the terms to check against are not complete terms")
    env = open_envelope(wire, now=now, audience=terms["requester"], kinds={"decision"})
    if env.sender != terms["decider"]:
        raise Refused("untrusted", "the decision is signed by someone other than the decider the terms name")
    if env.in_reply_to != accept_digest:
        raise Refused("terms", "the decision answers a different accept")
    body = env.body
    if set(body) != _BODY_KEYS:
        raise Refused("malformed", "a decision body has exactly: " + ", ".join(sorted(_BODY_KEYS)))
    if body["terms_digest"] != terms_digest(terms):
        raise Refused("terms", "the decision was made under different terms")
    if body["subject"] != dict(terms["subject"]):
        raise Refused("subject", "the decision judged a different document")
    if body["verdict"] not in VERDICTS:
        raise Refused("malformed", "unknown verdict")
    if env.expires_at is None or env.expires_at - env.issued_at > terms["decision_ttl_ms"]:
        raise Refused("terms", "the decision lives longer than the terms allow")
    if not isinstance(body["reasons"], list) or not all(isinstance(r, str) for r in body["reasons"]):
        raise Refused("malformed", "reasons is a list of text")
    if not isinstance(body["cns_root"], str) or not isinstance(body["evidence"], list):
        raise Refused("malformed", "cns_root is text and evidence a list")
    evidence: Dict[str, Mapping[str, Any]] = {}
    for item in body["evidence"]:
        if not isinstance(item, Mapping) or set(item) != {"kind", "content", "digest"} or not isinstance(
                item["content"], Mapping) or not isinstance(item["kind"], str) or item["kind"] in evidence:
            raise Refused("malformed", "each evidence item is a distinct kind, its content and its digest")
        if subject_digest(dict(item["content"])) != item["digest"]:
            raise Refused("malformed", f"evidence {item['kind']} does not match its digest")
        evidence[item["kind"]] = item["content"]
    if not set(evidence) <= set(terms["evidence"]):
        raise Refused("terms", "the decision carries evidence the terms did not ask for")
    if body["verdict"] == GateOutcome.PASS.value and sorted(evidence) != list(terms["evidence"]):
        raise Refused("terms", "a pass that does not carry the evidence the terms require")
    reservation = _redeem(ledger, env, now, lease_ms)
    return Verified(verdict=body["verdict"], reasons=tuple(body["reasons"]), evidence=evidence,
                    subject=dict(body["subject"]), cns_root=body["cns_root"], envelope=env, reservation=reservation)


class RemoteDecisionGuard:
    """Closed until a verified, allowed remote decision opens it; then permits one action on that one document.

    The guard's own configuration, never the caller's, says who it acts for (`acting_for`: decisions addressed to
    anyone else are refused), which capability it protects (`capability`, a (name, version) pair: a decision negotiated
    for any other capability or version is refused as `terms`), which deciders it accepts (`trust`: the terms' decider
    must be admitted), and where it remembers spent decisions (`ledger`). Terms handed to `authorize` can only narrow
    what is accepted, never widen it.

    `subject_of(artifact)` reads (identity, digest) from whatever the action is about to touch. Like `DecisionGuard`
    it answers True at most once, also under concurrent calls, never raises, and a refusal does not spend the
    permission. A decider revoked in the guard's `trust`, or with `revoke`, after `authorize` closes the guard."""

    def __init__(self, subject_of: Callable[[object], Tuple[str, str]], *, acting_for: str,
                 capability: Tuple[str, int], trust: TrustPolicy, ledger: Ledger,
                 clock: Callable[[], int] = now_ms, grants: Optional[Any] = None,
                 action: Optional[str] = None) -> None:
        if not callable(subject_of):
            raise ValueError("subject_of must read (identity, digest) from an artifact")
        if not is_agent_id(acting_for):
            raise ValueError("acting_for is the identity this guard acts for")
        if (not isinstance(capability, (tuple, list)) or len(capability) != 2
                or not isinstance(capability[0], str) or not NAME.match(capability[0])
                or type(capability[1]) is not int or capability[1] < 1):
            raise ValueError("capability is the (name, version) this guard protects")
        if not isinstance(trust, TrustPolicy):
            raise ValueError("a guard needs its own trust policy for deciders")
        if (grants is None) != (action is None) or (action is not None and (not isinstance(action, str) or not action)):
            raise ValueError("grants and action go together: the guard then acts only under the receiver's own policy")
        self._grants, self._action, self._permit = grants, action, None
        self._subject_of, self._ledger, self._clock = subject_of, ledger, clock
        self._acting_for, self._trust = acting_for, trust
        self._capability = (capability[0], capability[1])
        self._lock = threading.Lock()
        self._approved: Optional[Tuple[str, str]] = None
        self._decider: Optional[str] = None
        self._expires_at: Optional[int] = None
        self._spent = False
        self._reservation: Optional[Reservation] = None
        self._closed = False

    def _finish(self, reservation: Reservation, *, commit: bool) -> None:
        try:
            (self._ledger.commit if commit else self._ledger.release)(reservation, now=self._clock())  # type: ignore[attr-defined]
        except Refused:
            raise
        except Exception as exc:
            raise Refused("unavailable", f"the ledger did not confirm the {'commit' if commit else 'release'} "
                                         f"({type(exc).__name__})") from None

    def complete(self) -> None:
        """The action the guard permitted is done: spend the decision for good. Needs `authorize(lease_ms=...)`.
        Raises Refused('unavailable') if the ledger cannot confirm; the lease then lapses by itself and the action
        may be offered again, which is why it must be idempotent on `idempotency_key`."""
        with self._lock:
            if self._reservation is None or self._closed or not self._spent:
                raise ValueError("complete() follows a leased authorize and a permitted call, once")
            self._closed = True
            reservation = self._reservation
        self._finish(reservation, commit=True)
        if self._permit is not None:
            self._permit.complete()

    def abort(self) -> None:
        """The action did not happen: give the decision back so it can be redeemed again. Needs a leased authorize."""
        with self._lock:
            if self._reservation is None or self._closed:
                raise ValueError("abort() follows a leased authorize, once, and not after complete()")
            self._closed = True
            self._spent = True  # this guard never permits again; a new guard may redeem the decision
            reservation = self._reservation
        self._finish(reservation, commit=False)
        if self._permit is not None:
            self._permit.abort()

    @property
    def idempotency_key(self) -> Optional[str]:
        """Pass this to the action, so a retry after a crash does it once. None unless the authorize was leased."""
        return self._reservation.key if self._reservation is not None else None

    def authorize(self, wire: Mapping[str, Any], *, terms: Mapping[str, Any], accept_digest: str,
                  lease_ms: Optional[int] = None, approval: Optional[Any] = None) -> Verified:
        with self._lock:
            if self._approved is not None:
                raise ValueError("this guard was already authorized; one guard serves one decision")
            if not isinstance(terms, Mapping) or terms.get("requester") != self._acting_for:
                raise Refused("audience", "the terms are for a requester this guard does not act for")
            if (terms.get("capability"), terms.get("version")) != self._capability or type(
                    terms.get("version")) is not int:
                raise Refused("terms", "the decision was negotiated for a different capability or version than "
                              "this guard protects")
            sync = getattr(self._clock, "sync", None)
            if callable(sync):
                sync()  # a trusted clock (ledger_postgres.TrustedClock) is re-read from its reference for EVERY decision
            now = self._clock()
            self._trust.admit(terms.get("decider", ""), now=now)
            if self._grants is not None and lease_ms is None:
                lease_ms = 30_000  # under receiver policy a refusal that a person can cure must not burn the decision
            got = verify_decision(wire, terms=terms, accept_digest=accept_digest, ledger=self._ledger, now=now,
                                  lease_ms=lease_ms)
            if not got.allowed:
                if got.reservation is not None:
                    self._finish(got.reservation, commit=True)  # a non-pass is consumed like any decision
                raise Refused("refused", "the decision is not a pass: " + "; ".join(got.reasons))
            if self._grants is not None:
                try:  # the receiver's own policy decides; a signed decision alone never opens the guard
                    self._permit = self._grants.permit(self._action, got, terms, approval=approval, now=now)
                except Refused:
                    if got.reservation is not None:
                        self._finish(got.reservation, commit=False)  # give the decision back: approval may yet come
                    raise
            self._reservation = got.reservation
            self._approved = (got.subject["identity"], got.subject["digest"])
            self._decider = got.envelope.sender
            self._expires_at = got.envelope.expires_at
            return got

    def revoke(self, agent: str) -> None:
        """Stop trusting `agent` from now on. A decider revoked before `authorize` is refused there; one revoked after
        closes the guard. The guard swaps in its own policy with the identity added, so the policy it was built with,
        which belongs to the caller, is never changed."""
        if not is_agent_id(agent):
            raise ValueError("revoke takes an agent identity")
        with self._lock:
            t = self._trust
            self._trust = TrustPolicy(pinned=t.pinned, authorities=t.authorities, revoked=t.revoked | {agent},
                                      revocations=t.revocations, max_staleness_ms=t.max_staleness_ms,
                                      follow_rotation=t.follow_rotation)

    @property
    def permit(self) -> Optional[Any]:
        """The receiver's Permit for this redemption, when the guard was built with `grants`."""
        return self._permit

    def __call__(self, artifact: object) -> bool:
        try:
            seen = tuple(self._subject_of(artifact))
        except Exception:
            return False
        with self._lock:  # check and spend as one step, so concurrent callers cannot all pass the check
            if self._approved is None or self._spent:
                return False
            if self._grants is not None and self._permit is None:
                return False
            try:  # trust was checked at authorize; revocation can come after it, and a store that cannot answer closes it
                if self._decider is None or self._trust.is_revoked(self._decider, now=self._clock()):
                    return False
            except Exception:
                return False
            if self._expires_at is not None and self._clock() >= self._expires_at:
                return False
            if seen != self._approved:
                return False
            self._spent = True
            return True
