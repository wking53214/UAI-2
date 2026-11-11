"""revocation: signed statements that an identity, or an endorsement, must no longer be trusted, and that a key has
been replaced. The RECEIVER keeps them, in its own store, and decides what they mean to it.

WHY THIS EXISTS

Before this, revoking meant editing a set in the receiver's own policy: nothing a key's owner or an authority could
sign and send, nothing that survived a restart, and nothing that bounded how stale the receiver's view could be.

THE STATEMENT

A `revocation` envelope, body exactly:

    subject       an agent identity, or the 32-hex id of an endorsement
    action        "revoke" or "rotate"
    successor     for "rotate", the agent identity that replaces the subject; "" for "revoke"
    reason        text, for people
    effective_at  milliseconds; the statement binds once the receiver's clock reaches it (a past time binds at once)

Who may sign what:

    the subject itself   "revoke" (my key is dead or compromised) and "rotate" (use this key instead)
    an authority the receiver lists   "revoke" only, for any subject
    nobody else

A "revoke" only ever REDUCES trust, so a receiver can honor one from a signer it has verified without further
thought; the worst a forger of a key's own revocation could do is cut off a key it already holds. A "rotate" can ADD
trust (a successor), so it is never honored by default, and a compromised key can sign one: the receiver opts in per
policy (`TrustPolicy.follow_rotation`), and even then only a pinned predecessor's successor is admitted, never one
whose predecessor an authority revoked. Rotation also revokes the predecessor.

There is no un-revoke. A key that was declared dead stays dead for the receiver that stored the statement. An
authority's revoke of a key that already rotated also withdraws the successor that key named.

FRESHNESS

A receiver that has not heard recently cannot say nothing was revoked. The store records when the operator last
refreshed it from its sources (`mark_fresh`), and a `TrustPolicy` with `max_staleness_ms` refuses (`unavailable`)
when that is too old. This is a bound on how late a revocation can be, not a delivery mechanism: how statements
reach the store (polling an authority, a queue, a person) is the receiver's choice.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional

from .envelope import MAX_INT, Envelope, Refused, now_ms, open_envelope, seal
from .identity import Signer, is_agent_id

__all__ = ["Statement", "RevocationStore", "revoke", "rotate", "read_statement", "BODY_KEYS"]

BODY_KEYS = frozenset({"subject", "action", "successor", "reason", "effective_at"})
_HEX32 = re.compile(r"\A[0-9a-f]{32}\Z")


def revoke(signer: Signer, subject: str, *, reason: str, effective_at: Optional[int] = None,
           now: Optional[int] = None) -> Envelope:
    """`signer` declares `subject` (an identity, or an endorsement id) untrustworthy. No expiry: a revocation lasts."""
    t = now_ms() if now is None else now
    return seal(signer, "revocation", {"subject": subject, "action": "revoke", "successor": "", "reason": reason,
                                       "effective_at": t if effective_at is None else effective_at}, now=t)


def rotate(signer: Signer, successor: str, *, reason: str, effective_at: Optional[int] = None,
           now: Optional[int] = None) -> Envelope:
    """`signer` says its identity is replaced by `successor`, and that its own key must stop being trusted."""
    t = now_ms() if now is None else now
    return seal(signer, "revocation", {"subject": signer.agent, "action": "rotate", "successor": successor,
                                       "reason": reason, "effective_at": t if effective_at is None else effective_at},
                now=t)


@dataclass(frozen=True)
class Statement:
    subject: str
    action: str
    successor: str
    reason: str
    effective_at: int
    signer: str
    id: str
    envelope: Envelope


def read_statement(wire: Mapping[str, object], *, authorities: Iterable[str] = (),
                   now: Optional[int] = None) -> Statement:
    """Check a revocation completely: the envelope, the body, and that its signer may say it."""
    env = open_envelope(wire, now=now, kinds={"revocation"})
    b = env.body
    if set(b) != BODY_KEYS:
        raise Refused("malformed", "a revocation body has exactly: " + ", ".join(sorted(BODY_KEYS)))
    subject, action, successor, reason, eff = b["subject"], b["action"], b["successor"], b["reason"], b["effective_at"]
    if not isinstance(subject, str) or not (is_agent_id(subject) or _HEX32.match(subject)):
        raise Refused("malformed", "the subject is an agent identity or an endorsement id")
    if action not in ("revoke", "rotate") or not isinstance(reason, str):
        raise Refused("malformed", "action is revoke or rotate, and reason is text")
    if isinstance(eff, bool) or not isinstance(eff, int) or not 0 <= eff <= MAX_INT:
        raise Refused("malformed", "effective_at is a time in ms")
    if action == "revoke" and successor != "":
        raise Refused("malformed", "a revoke names no successor")
    if action == "rotate":
        if not is_agent_id(successor) or successor == subject or not is_agent_id(subject):
            raise Refused("malformed", "a rotate names another agent identity as its successor")
        if env.sender != subject:
            raise Refused("untrusted", "only an identity can rotate itself")
    if env.sender != subject and env.sender not in set(authorities):
        raise Refused("untrusted", "a revocation must come from the subject itself or an authority this receiver "
                                   "lists")
    return Statement(subject=subject, action=action, successor=successor, reason=reason, effective_at=eff,
                     signer=env.sender, id=env.id, envelope=env)


class RevocationStore:
    """This receiver's own record of revocation statements, in a SQLite file. Shared safely by processes on one host.
    Whatever it cannot read it reports as Refused('unavailable'): an unreadable store is not an empty one."""

    def __init__(self, path: "os.PathLike[str] | str", *, busy_ms: int = 5_000) -> None:
        self._path, self._busy = str(path), busy_ms
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._run("CREATE TABLE IF NOT EXISTS revoked (subject TEXT PRIMARY KEY, action TEXT NOT NULL, "
                  "successor TEXT NOT NULL, effective_at INTEGER NOT NULL, stored_at INTEGER NOT NULL, "
                  "signer TEXT NOT NULL, statement TEXT NOT NULL)")
        self._run("CREATE TABLE IF NOT EXISTS successors (successor TEXT PRIMARY KEY, predecessor TEXT NOT NULL)")
        self._run("CREATE TABLE IF NOT EXISTS fresh (k INTEGER PRIMARY KEY CHECK (k = 1), at INTEGER NOT NULL)")

    def _run(self, sql: str, args: tuple = ()) -> list:
        try:
            db = sqlite3.connect(self._path, timeout=self._busy / 1000, isolation_level=None)
            try:
                db.execute("PRAGMA synchronous=FULL")
                return db.execute(sql, args).fetchall()
            finally:
                db.close()
        except sqlite3.Error as exc:
            raise Refused("unavailable", f"the revocation store did not answer ({exc})") from None

    def accept(self, wire: Mapping[str, object], *, authorities: Iterable[str] = (),
               now: Optional[int] = None) -> Statement:
        """Verify a statement and store it. Storing the same statement twice changes nothing."""
        t = now_ms() if now is None else now
        st = read_statement(wire, authorities=authorities, now=t)
        try:
            db = sqlite3.connect(self._path, timeout=self._busy / 1000, isolation_level=None)
            try:
                db.execute("BEGIN IMMEDIATE")
                have = db.execute("SELECT action FROM revoked WHERE subject=?", (st.subject,)).fetchone()
                if have is not None and have[0] == "rotate" and st.action == "revoke" and st.signer != st.subject:
                    # An authority revoking a key that already named a successor: the key may have been compromised
                    # when it did, so the successor it named is no longer admitted.
                    db.execute("UPDATE revoked SET action='revoke', successor='', signer=?, statement=? "
                               "WHERE subject=?", (st.signer, json.dumps(st.envelope.to_wire(), sort_keys=True),
                                                   st.subject))
                    db.execute("DELETE FROM successors WHERE predecessor=?", (st.subject,))
                if have is None:
                    db.execute("INSERT INTO revoked VALUES (?,?,?,?,?,?,?)",
                               (st.subject, st.action, st.successor, st.effective_at, t, st.signer,
                                json.dumps(st.envelope.to_wire(), sort_keys=True)))
                    if st.action == "rotate":
                        db.execute("INSERT OR IGNORE INTO successors VALUES (?,?)", (st.successor, st.subject))
                db.execute("COMMIT")
            except BaseException:
                try:
                    db.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            finally:
                db.close()
        except sqlite3.Error as exc:
            raise Refused("unavailable", f"the revocation store did not answer ({exc})") from None
        return st

    def is_revoked(self, subject: str, now: Optional[int] = None) -> bool:
        """Whether `subject` is revoked as of `now`: a statement is stored, and its effective_at has come."""
        t = now_ms() if now is None else now
        rows = self._run("SELECT effective_at, stored_at FROM revoked WHERE subject=?", (subject,))
        return bool(rows) and t >= rows[0][0]

    def predecessor_of(self, agent: str) -> Optional[str]:
        rows = self._run("SELECT predecessor FROM successors WHERE successor=?", (agent,))
        return str(rows[0][0]) if rows else None

    def mark_fresh(self, now: Optional[int] = None) -> None:
        """The operator has just refreshed this store from every source it relies on."""
        self._run("INSERT INTO fresh VALUES (1, ?) ON CONFLICT(k) DO UPDATE SET at=excluded.at",
                  (now_ms() if now is None else now,))

    def age_ms(self, now: Optional[int] = None) -> Optional[int]:
        """Milliseconds since `mark_fresh`, or None if it never was."""
        rows = self._run("SELECT at FROM fresh WHERE k=1")
        return None if not rows else max(0, (now_ms() if now is None else now) - int(rows[0][0]))
