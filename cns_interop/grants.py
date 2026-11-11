"""grants: what THIS receiver permits, for which purpose, to whom, until when, and with whose approval.

WHY THIS EXISTS

A signature is not permission, and a manifest is an advertisement. A verified decision says a decider judged a document;
it does not say this receiver will act on it. Without a receiver-side step, any code that holds a `Verified` decision
decides for itself what that permits. A `GrantTable` is that step. It is the receiver's own policy, default deny, and
nothing a sender signs can add to it.

THE QUESTIONS IT ANSWERS (each a stable refusal code)

  Is there a grant at all for this capability and version?     no_grant
  Is it still in force, and not withdrawn?                      grant_expired, withdrawn
  Is the decider one this grant names?                          decider
  Is the action one this grant names?                           action
  Will this receiver disclose what the terms ask to see?        disclosure   (a ceiling on `terms["disclose"]`)
  Does this action need a human, and did one say yes?           approval_required, approval
  Could the evidence be retained?                               unavailable  (the audit write failed, so nothing is permitted)

PURPOSE needs no new field on the wire. UAI-1 terms are signed over the capability NAME and VERSION, so a purpose is
a capability name that carries it (`income-screen.loan-underwriting`). A decision negotiated under one purpose names
that capability and a grant for another purpose does not match it. The receiver chooses its purposes by choosing the
names it grants.

HUMAN APPROVAL is local to the receiver. An `Approval` is signed by an approver identity the grant lists, bound to
one decision, one action and one document, and expires. The approver can never be the decider, the requester, or any
identity the receiver treats as an agent, so an agent or a model cannot approve its own recommendation. This module
never gives any signing key to an adapter (adapter.py); approval keys belong to people.

EVIDENCE: every permit and every refusal is appended to a hash-chained audit record. Each entry carries the digest of
the one before, so removing or editing an entry is detectable (`verify_audit`); it does not stop someone with write
access from truncating the tail, which is what an external anchor of the last digest is for.

NOT HERE: delegation (a grant is for the requester it names, and cannot be passed on), and a shared grant store across
hosts (the table is one receiver's own memory, loaded from its own configuration).
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Mapping, Optional

from cns.gate import subject_digest

from . import crypto_backend
from .decision import Verified
from .envelope import MAX_INT, Refused, now_ms
from .identity import Signer, is_agent_id, public_of
from .ledger import MemoryLedger, Reservation
from .negotiate import TERMS_KEYS, terms_digest

__all__ = ["Grant", "GrantTable", "GrantStore", "Approval", "approve", "Permit", "verify_audit", "append_audit",
           "load_grants"]

_APPROVAL_TAG = b"uai/1 approval\n"


@dataclass(frozen=True)
class Grant:
    """One purpose-bound permission. `capability` is the (purpose-carrying) name the terms must name."""

    id: str
    capability: str
    version: int
    requester: str                               # the identity this receiver acts as; the grant is for no one else
    deciders: FrozenSet[str]
    actions: FrozenSet[str]
    disclose_max: FrozenSet[str] = frozenset()   # the most this receiver will let the decider see; empty means nothing
    expires_at: Optional[int] = None             # None: no expiry (a receiver may choose that; it is its own)
    approvers: FrozenSet[str] = frozenset()      # humans whose approval an action needs; empty means none is needed
    retain_ms: int = 0                           # how long the audit entry for this grant must be kept (recorded)

    def __post_init__(self) -> None:
        if not self.id or not self.capability or not self.actions or not self.deciders:
            raise ValueError("a grant names an id, a capability, at least one decider and at least one action")
        if not is_agent_id(self.requester) or not all(is_agent_id(d) for d in self.deciders | self.approvers):
            raise ValueError("requester, deciders and approvers are agent identities")
        if self.approvers & (self.deciders | {self.requester}):
            raise ValueError("an approver is never the decider or the requester: a party cannot approve itself")
        for name in ("deciders", "actions", "disclose_max", "approvers"):
            object.__setattr__(self, name, frozenset(getattr(self, name)))
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 1:
            raise ValueError("version is a positive integer")


@dataclass(frozen=True)
class Approval:
    """A human's signed yes to ONE action on ONE document under ONE decision."""

    approver: str
    decision_id: str
    action: str
    subject_digest: str
    expires_at: int
    sig: str

    def body(self) -> Dict[str, Any]:
        return {"approver": self.approver, "decision_id": self.decision_id, "action": self.action,
                "subject_digest": self.subject_digest, "expires_at": self.expires_at}


def approve(approver: Signer, verified: Verified, action: str, *, ttl_ms: int = 300_000,
            now: Optional[int] = None) -> Approval:
    """What a person's tool calls after reading what the decision and the action are."""
    t = now_ms() if now is None else now
    draft = Approval(approver=approver.agent, decision_id=verified.envelope.id, action=action,
                     subject_digest=verified.subject["digest"], expires_at=t + ttl_ms, sig="")
    sig = approver.sign(_APPROVAL_TAG + subject_digest(draft.body()).encode("ascii"))
    return Approval(approver=draft.approver, decision_id=draft.decision_id, action=action,
                    subject_digest=draft.subject_digest, expires_at=draft.expires_at, sig=sig.hex())


@dataclass(frozen=True)
class Permit:
    """The receiver's yes. Holding one is what an action may rely on, not holding a Verified decision.

    A permit is SINGLE USE: it is a lease on `(decision, action)` in the table's permit ledger. `complete()` spends it
    for good once the action is done; `abort()` gives it back when the action did not happen. A holder that does
    neither loses it when the lease lapses, and the action may then be offered again, so the action must be idempotent
    on `idempotency_key`."""

    grant: str
    action: str
    capability: str
    version: int
    decision_id: str
    subject_digest: str
    approver: str
    audit_digest: str
    terms_digest: str = ""
    idempotency_key: str = ""
    _reservation: Optional[Reservation] = field(default=None, repr=False, compare=False)
    _ledger: Any = field(default=None, repr=False, compare=False)

    def complete(self) -> None:
        if self._reservation is None or self._ledger is None:
            raise ValueError("this permit holds no lease to complete")
        _finish(self._ledger, self._reservation, commit=True)

    def abort(self) -> None:
        if self._reservation is None or self._ledger is None:
            raise ValueError("this permit holds no lease to abort")
        _finish(self._ledger, self._reservation, commit=False)


def _finish(ledger: Any, reservation: Reservation, *, commit: bool) -> None:
    try:
        (ledger.commit if commit else ledger.release)(reservation)
    except Refused:
        raise
    except Exception as exc:
        raise Refused("unavailable", f"the permit ledger did not confirm the {'commit' if commit else 'release'} "
                                     f"({type(exc).__name__})") from None


class GrantStore:
    """The receiver's durable grant state: which grants have been withdrawn. SQLite, shared by every process on the
    host. A withdrawal written here survives a restart and is seen by every process; an unreadable store answers
    Refused('unavailable'), never 'not withdrawn'."""

    def __init__(self, path: "os.PathLike[str] | str", *, busy_ms: int = 5_000) -> None:
        self._path, self._busy = str(path), busy_ms
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._run("CREATE TABLE IF NOT EXISTS withdrawn (grant_id TEXT PRIMARY KEY, at INTEGER NOT NULL)")

    def _run(self, sql: str, args: tuple = ()) -> list:  # type: ignore[type-arg]
        try:
            db = sqlite3.connect(self._path, timeout=self._busy / 1000, isolation_level=None)
            try:
                db.execute("PRAGMA synchronous=FULL")
                return db.execute(sql, args).fetchall()
            finally:
                db.close()
        except sqlite3.Error as exc:
            raise Refused("unavailable", f"the grant store did not answer ({exc})") from None

    def withdraw(self, grant_id: str, now: Optional[int] = None) -> None:
        self._run("INSERT OR IGNORE INTO withdrawn VALUES (?, ?)", (grant_id, now_ms() if now is None else now))

    def is_withdrawn(self, grant_id: str) -> bool:
        return bool(self._run("SELECT 1 FROM withdrawn WHERE grant_id=?", (grant_id,)))


def load_grants(text: str) -> List[Grant]:
    """Read a receiver's grants from its own configuration file: one JSON object `{"grants": [ ... ]}`, read as strictly
    as a wire message. Anything unexpected raises ValueError, so a typo can never become a wider grant."""
    from .wire import loads

    try:
        doc = loads(text)
    except Refused as exc:
        raise ValueError(f"the grants file is not strict JSON ({exc.code})") from None
    if set(doc) != {"grants"} or not isinstance(doc["grants"], list):
        raise ValueError('the grants file is exactly {"grants": [...]}')
    keys = {"id", "capability", "version", "requester", "deciders", "actions", "disclose_max", "expires_at",
            "approvers", "retain_ms"}
    required = {"id", "capability", "version", "requester", "deciders", "actions"}
    out = []
    for g in doc["grants"]:
        if not isinstance(g, dict) or not required <= set(g) <= keys:
            raise ValueError("a grant has " + ", ".join(sorted(required)) + " and optionally the rest of: "
                             + ", ".join(sorted(keys - required)))
        for lst in ("deciders", "actions", "disclose_max", "approvers"):
            if lst in g and (not isinstance(g[lst], list) or not all(isinstance(x, str) for x in g[lst])):
                raise ValueError(f"{lst} is a list of text")
        fields: Dict[str, Any] = {k: (frozenset(v) if isinstance(v, list) else v) for k, v in g.items()}
        out.append(Grant(**fields))
    return out


class GrantTable:
    """The receiver's policy. `store` makes withdrawals durable and shared; `permit_ledger` makes permits single use
    across processes (pass a `FileLedger`, `SqliteLedger` or coordinated ledger; the default is this process only);
    `audit_path` is safe for several writers. Without `store` a withdrawal lasts only as long as this object."""

    def __init__(self, grants: List[Grant] = (), *, audit_path: "os.PathLike[str] | str | None" = None,  # type: ignore[assignment]
                 store: Optional[GrantStore] = None, permit_ledger: Any = None, permit_lease_ms: int = 60_000,
                 audit_recover: bool = False, audit_sink: Any = None) -> None:
        if audit_sink is not None and audit_path is not None:
            raise ValueError("an audit record is a file or a shared sink, not both")
        self._sink = audit_sink
        self._grants: Dict[tuple, Grant] = {}  # type: ignore[type-arg]
        for g in grants:
            if (g.capability, g.version) in self._grants:
                raise ValueError(f"two grants for {g.capability} version {g.version}")
            self._grants[(g.capability, g.version)] = g
        self._withdrawn: set = set()  # type: ignore[type-arg]
        self._store = store
        self._permits = permit_ledger if permit_ledger is not None else MemoryLedger()
        if not callable(getattr(self._permits, "reserve", None)):
            raise ValueError("permit_ledger needs reserve, commit and release (see ledger.TwoPhaseLedger)")
        self._lease_ms = permit_lease_ms
        self._lock = threading.Lock()
        self._audit = Path(audit_path) if audit_path is not None else None
        self._last = "0" * 64
        if self._sink is not None:
            self._last = self._sink.verify()  # a damaged shared chain is refused here, before anything is permitted
        if self._audit is not None:
            self._audit.parent.mkdir(parents=True, exist_ok=True)
            try:
                self._last = verify_audit(self._audit)
            except Refused:
                if not audit_recover:
                    raise
                self._last = _recover_audit(self._audit)

    def withdraw(self, grant_id: str) -> None:
        """Permission withdrawn. From the next `permit` on, every action under this grant is refused (`withdrawn`), in
        every process that shares the `store`, and after a restart."""
        if self._store is not None:
            self._store.withdraw(grant_id)
            return
        with self._lock:
            self._withdrawn.add(grant_id)

    def _is_withdrawn(self, grant_id: str) -> bool:
        if grant_id in self._withdrawn:
            return True
        return self._store.is_withdrawn(grant_id) if self._store is not None else False

    def _grant_for(self, capability: Any, version: Any) -> Grant:
        g = self._grants.get((capability, version)) if isinstance(capability, str) else None
        if g is None:
            raise Refused("no_grant", "this receiver has granted nothing for that capability and version")
        return g

    def check_terms(self, terms: Mapping[str, Any], *, now: Optional[int] = None) -> Grant:
        """Before anything is disclosed: is there a grant, in force, naming this decider, whose disclosure ceiling
        covers every field the terms ask to see? Raises Refused. A requester calls this on the offer."""
        t = now_ms() if now is None else now
        g = self._grant_for(terms.get("capability"), terms.get("version"))
        if self._is_withdrawn(g.id):
            raise Refused("withdrawn", "the permission for this purpose was withdrawn")
        if g.expires_at is not None and t >= g.expires_at:
            raise Refused("grant_expired", "the permission for this purpose has expired")
        if terms.get("requester") != g.requester:
            raise Refused("no_grant", "the grant is for a different requester than the terms name")
        if terms.get("decider") not in g.deciders:
            raise Refused("decider", "this grant does not name that decider")
        asked = set(terms.get("disclose") or ())
        if not asked <= g.disclose_max:
            raise Refused("disclosure", "the terms ask to see fields this receiver will not disclose for this "
                                        "purpose: " + ", ".join(sorted(asked - g.disclose_max)))
        return g

    def permit(self, action: str, verified: Verified, terms: Mapping[str, Any], *, approval: Optional[Approval] = None,
               now: Optional[int] = None) -> Permit:
        """May this receiver perform `action` on what `verified` judged? A single-use Permit, or Refused with the
        reason. The terms must be the terms the decision was made under (their digest is compared with the one the
        decider signed). Every outcome is written to the audit record: if that cannot be written, nothing is permitted
        and the lease on the permit is given back."""
        t = now_ms() if now is None else now
        approver = ""
        reservation: Optional[Reservation] = None
        g: Optional[Grant] = None
        try:
            if not isinstance(terms, Mapping) or set(terms) != TERMS_KEYS:
                raise Refused("terms", "the terms are not complete UAI-1 terms")
            if not verified.allowed:
                raise Refused("refused", "a decision that is not a pass permits nothing")
            try:
                held = terms_digest(terms)
            except TypeError:
                raise Refused("terms", "the terms cannot be digested") from None
            if held != verified.terms_digest:
                raise Refused("terms", "these are not the terms the decision was made under")
            g = self.check_terms(terms, now=t)
            if verified.envelope.sender != terms["decider"] or verified.subject != dict(terms["subject"]):
                raise Refused("terms", "the verified decision is not the one the terms describe")
            if action not in g.actions:
                raise Refused("action", f"this grant does not permit {action!r}")
            if g.approvers:
                approver = self._check_approval(g, approval, verified, action, t)
            reservation = self._reserve(g, verified, action, t)
        except Refused as exc:
            self._record(t, action, terms, verified, approver, exc.code, "")
            raise
        assert g is not None and reservation is not None
        try:
            digest = self._record(t, action, terms, verified, approver, "permitted", g.id)
        except Refused:
            _finish(self._permits, reservation, commit=False)
            raise
        return Permit(grant=g.id, action=action, capability=g.capability, version=g.version,
                      decision_id=verified.envelope.id, subject_digest=verified.subject["digest"], approver=approver,
                      audit_digest=digest, terms_digest=held, idempotency_key=reservation.key,
                      _reservation=reservation, _ledger=self._permits)

    def _reserve(self, g: Grant, verified: Verified, action: str, now: int) -> Reservation:
        try:
            got: Reservation = self._permits.reserve(f"permit:{g.id}", f"{verified.envelope.id}:{action}",
                                                     verified.envelope.expires_at, lease_ms=self._lease_ms, now=now)
            return got
        except Refused as exc:
            if exc.code == "replayed":
                raise Refused("replayed", "this decision already produced a permit for this action") from None
            raise
        except Exception as exc:
            raise Refused("unavailable", f"the permit ledger gave no answer ({type(exc).__name__})") from None

    def _check_approval(self, g: Grant, approval: Optional[Approval], verified: Verified, action: str, now: int) -> str:
        if approval is None:
            raise Refused("approval_required", "this action needs a person's approval and none was given")
        if approval.approver not in g.approvers:
            raise Refused("approval", "the approver is not one this grant names")
        if approval.approver in (verified.envelope.sender, g.requester):
            raise Refused("approval", "a party cannot approve its own action")
        if (approval.decision_id, approval.action, approval.subject_digest) != (
                verified.envelope.id, action, verified.subject["digest"]):
            raise Refused("approval", "the approval is for a different decision, action or document")
        if isinstance(approval.expires_at, bool) or not isinstance(approval.expires_at, int) or not (
                0 < approval.expires_at <= MAX_INT) or now >= approval.expires_at:
            raise Refused("approval", "the approval has expired")
        try:
            ok = crypto_backend.verify(public_of(approval.approver),
                                       _APPROVAL_TAG + subject_digest(approval.body()).encode("ascii"),
                                       bytes.fromhex(approval.sig))
        except ValueError:
            ok = False
        if not ok:
            raise Refused("approval", "the approval's signature does not verify as the approver")
        return approval.approver

    def _record(self, now: int, action: str, terms: Mapping[str, Any], verified: Verified, approver: str, outcome: str,
                grant: str) -> str:
        if not isinstance(terms, Mapping):
            terms = {}  # an audit entry is written for every outcome, including terms that were not even a mapping
        entry: Dict[str, Any] = {
            "at": now, "action": action, "outcome": outcome, "grant": grant, "capability": str(terms.get("capability")),
            "version": terms.get("version") if isinstance(terms.get("version"), int) else 0,
            "decider": str(terms.get("decider")), "requester": str(terms.get("requester")),
            "decision_id": verified.envelope.id, "subject_digest": verified.subject.get("digest", ""),
            "approver": approver, "terms_digest": verified.terms_digest,
            "retain_ms": next((g.retain_ms for g in self._grants.values() if g.id == grant), 0)}
        if self._sink is not None:
            self._last = self._sink.append(entry)  # one chain across every host; raises Refused('unavailable') on failure
            return self._last
        with self._lock:
            if self._audit is None:
                entry["prev"] = self._last
                self._last = subject_digest(entry)
                return self._last
            self._last = append_audit(self._audit, entry)
            return self._last


def append_audit(path: "os.PathLike[str] | str", entry: Dict[str, Any]) -> str:
    """Append one entry to a hash-chained audit file, under its lock, chained onto the REAL last entry, and return its
    digest. `GrantTable` writes every permit and refusal this way; a receiver uses it directly for a record that is not a
    permit decision, such as a start-up refusal (`clock_skew`, `unavailable`, `config`), so that a refusal to act leaves
    evidence in the same chain (RACE-02 I-07b). Refused('unavailable') when the file cannot be written."""
    try:
        import fcntl

        with open(path, "a+b") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)  # every writer, in any process, chains onto the REAL last entry
            entry["prev"] = _tail_digest(fh)
            digest = subject_digest(entry)
            fh.write((json.dumps({**entry, "digest": digest}, sort_keys=True) + "\n").encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as exc:
        raise Refused("unavailable", f"the audit record could not be written, so nothing is permitted "
                                     f"({type(exc).__name__})") from None
    return digest


def _tail_digest(fh: Any) -> str:
    """The digest of the last entry in an audit file opened for update (and locked); zeros if empty. A last line that
    is not a complete entry means the file is damaged: Refused('unavailable'), and nothing is written."""
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    if size == 0:
        return "0" * 64
    fh.seek(max(0, size - 65536))
    data = fh.read()
    if not data.endswith(b"\n"):
        raise Refused("unavailable", "the audit record ends in a partial entry; recover it before writing")
    try:
        return str(json.loads(data.splitlines()[-1].decode("utf-8"))["digest"])
    except (ValueError, KeyError, UnicodeDecodeError, TypeError, IndexError):
        raise Refused("unavailable", "the audit record's last entry cannot be read") from None


def _recover_audit(path: Path) -> str:
    """Set a damaged audit file aside, untouched, and start a new chain whose first entry names the damaged file and
    its SHA-256. This is an explicit operator action (`audit_recover=True`), never automatic."""
    import hashlib

    damaged = path.with_name(path.name + f".damaged.{int(time.time())}")
    data = path.read_bytes()
    os.replace(path, damaged)
    entry = {"at": now_ms(), "outcome": "audit_recovered", "damaged_file": damaged.name,
             "damaged_sha256": hashlib.sha256(data).hexdigest(), "prev": "0" * 64}
    digest = subject_digest(entry)
    with open(path, "wb") as fh:
        fh.write((json.dumps({**entry, "digest": digest}, sort_keys=True) + "\n").encode("utf-8"))
        fh.flush()
        os.fsync(fh.fileno())
    return digest


def verify_audit(path: "os.PathLike[str] | str") -> str:
    """Check an audit file's hash chain and return the digest of its last entry (64 zeros if empty). Refused
    ('unavailable') if any entry was edited, removed from the middle, or reordered."""
    last = "0" * 64
    p = Path(path)
    if not p.exists():
        return last
    for n, line in enumerate(p.read_bytes().splitlines(), 1):
        try:
            e = json.loads(line.decode("utf-8"))
            claimed = e.pop("digest")
            if e["prev"] != last or subject_digest(e) != claimed:
                raise ValueError("chain broken")
        except (ValueError, KeyError, UnicodeDecodeError, TypeError):
            raise Refused("unavailable", f"the audit record is damaged at entry {n}") from None
        last = claimed
    return last
