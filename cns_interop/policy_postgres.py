"""policy_postgres: the receiver's policy state and audit record in PostgreSQL, so several receiver hosts share them.

This is the RECEIVER'S storage. CNS holds no authority here: the receiver still writes its own grants, withdraws them, and
decides. What this module gives a deployment with more than one receiver host is one place to keep the three things a host-local
file cannot share:

  * WITHDRAWALS (`PostgresGrantStore`, the same `withdraw` / `is_withdrawn` as `grants.GrantStore`). A withdrawal committed by one
    host is seen by the next check on every other host. An unreachable database answers Refused('unavailable'), never "not
    withdrawn".
  * THE POLICY VERSION. Each host loads its grants from its own file. `policy_digest(grants)` fingerprints what a host loaded,
    `publish_policy(version, digest)` is an explicit operator action that moves the shared version forward by exactly one
    (compare-and-set: two operators publishing at once cannot both win), and `require_policy(digest)` makes a host whose file
    differs from the published one refuse to start rather than act on stale or conflicting grants.
  * THE AUDIT CHAIN (`PostgresAudit`). Entries are appended under a database lock, each carrying the digest of the one before,
    so any number of hosts extend ONE chain. `verify()` re-derives every digest and refuses a chain with an edited, removed
    (middle) or reordered entry.

WHAT THIS DOES NOT DO. It is not distributed consensus: it is as available and durable as the one PostgreSQL primary
(`require_sync_replication` demands quorum-durable commit; see ledger_postgres.py). A hash chain detects editing and middle
removal; it does not detect the newest entries being cut off, or the whole table being replaced by a consistent forgery, so a
receiver that needs that anchors the head digest (`audit.head()`) somewhere the database operator cannot write. A privileged
database administrator is inside the trust boundary of this store.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, Optional, Tuple

from cns.gate import subject_digest

from .envelope import Refused
from .ledger_postgres import _NAME, PgGuard

__all__ = ["PostgresGrantStore", "PostgresAudit", "policy_digest"]

_ZERO = "0" * 64
_HEX = re.compile(r"\A[0-9a-f]{64}\Z")


def policy_digest(grants: Iterable[Any]) -> str:
    """A fingerprint of a set of grants, independent of their order, so two hosts that loaded the same policy agree."""
    rows = [_fields(g) for g in grants]
    return subject_digest({"grants": sorted(rows, key=lambda r: json.dumps(r, sort_keys=True))})


def _fields(g: Any) -> Dict[str, Any]:
    import dataclasses
    return {k: (sorted(v) if isinstance(v, (set, frozenset)) else v) for k, v in dataclasses.asdict(g).items()}


class PostgresGrantStore(PgGuard):
    def __init__(self, dsn: str, *, prefix: str = "uai_policy", **kw: Any) -> None:
        if not _NAME.match(prefix):
            raise ValueError("prefix is a lowercase SQL identifier")
        super().__init__(dsn, **kw)
        self._w, self._p = prefix + "_withdrawn", prefix + "_version"
        self._guard(self._create)

    def _create(self, db: Any) -> None:
        db.execute("SELECT pg_advisory_xact_lock(7243002)")
        db.execute(f"CREATE TABLE IF NOT EXISTS {self._w} (grant_id text PRIMARY KEY, at bigint NOT NULL)")
        db.execute(f"CREATE TABLE IF NOT EXISTS {self._p} (version bigint PRIMARY KEY, digest text NOT NULL, at bigint NOT NULL)")

    # same surface as grants.GrantStore
    def withdraw(self, grant_id: str, now: Optional[int] = None) -> None:
        self._guard(lambda db: db.execute(
            f"INSERT INTO {self._w} VALUES (%s, (extract(epoch from clock_timestamp()) * 1000)::bigint) ON CONFLICT DO NOTHING",
            (grant_id,)))

    def is_withdrawn(self, grant_id: str) -> bool:
        return bool(self._guard(lambda db: db.execute(f"SELECT 1 FROM {self._w} WHERE grant_id = %s", (grant_id,)).fetchall()))

    # the shared policy version
    def current_policy(self) -> Tuple[int, str]:
        row = self._guard(lambda db: db.execute(f"SELECT version, digest FROM {self._p} ORDER BY version DESC LIMIT 1").fetchone())
        return (int(row[0]), str(row[1])) if row else (0, _ZERO)

    def publish_policy(self, version: int, digest: str) -> None:
        """Move the shared policy to `version`, which must be exactly the current version plus one. A concurrent publish of the
        same version loses (Refused 'conflict'): the operator re-reads and decides again. Nothing here edits a grant."""
        if not isinstance(version, int) or isinstance(version, bool) or version < 1 or not _HEX.match(digest):
            raise ValueError("a policy version is a positive integer and its digest is 64 hex characters")

        def run(db: Any) -> bool:
            db.execute("SELECT pg_advisory_xact_lock(7243003)")
            row = db.execute(f"SELECT max(version) FROM {self._p}").fetchone()
            if (row[0] or 0) + 1 != version:
                return False
            db.execute(f"INSERT INTO {self._p} VALUES (%s, %s, (extract(epoch from clock_timestamp()) * 1000)::bigint)",
                       (version, digest))
            return True
        if not self._guard(run):
            raise Refused("conflict", f"policy version {version} is not the next version; another operator published first")

    def require_policy(self, digest: str) -> int:
        """Return the published version if this host's grants are exactly the published ones; otherwise refuse. A host with
        stale or divergent grants must not act, because it would permit what the others no longer do."""
        version, published = self.current_policy()
        if version == 0:
            raise Refused("stale_policy", "no policy has been published to the shared store")
        if published != digest:
            raise Refused("stale_policy", f"this host's grants are not the published policy (version {version})")
        return version


class PostgresAudit(PgGuard):
    """The hash-chained audit record, one chain across every host. `append` returns the new entry's digest."""

    def __init__(self, dsn: str, *, prefix: str = "uai_audit", **kw: Any) -> None:
        if not _NAME.match(prefix):
            raise ValueError("prefix is a lowercase SQL identifier")
        super().__init__(dsn, **kw)
        self._t = prefix + "_chain"
        self._guard(self._create)

    def _create(self, db: Any) -> None:
        db.execute("SELECT pg_advisory_xact_lock(7243004)")
        db.execute(f"CREATE TABLE IF NOT EXISTS {self._t} (seq bigserial PRIMARY KEY, digest text NOT NULL UNIQUE, entry text NOT NULL)")

    def append(self, entry: Dict[str, Any]) -> str:
        def run(db: Any) -> str:
            db.execute(f"SELECT pg_advisory_xact_lock(hashtext('{self._t}'))")  # one writer at a time, on any host
            row = db.execute(f"SELECT digest FROM {self._t} ORDER BY seq DESC LIMIT 1").fetchone()
            body = {**entry, "prev": row[0] if row else _ZERO}
            digest = subject_digest(body)
            db.execute(f"INSERT INTO {self._t} (digest, entry) VALUES (%s, %s)",
                       (digest, json.dumps({**body, "digest": digest}, sort_keys=True)))
            return digest
        return str(self._guard(run))

    def head(self) -> str:
        row = self._guard(lambda db: db.execute(f"SELECT digest FROM {self._t} ORDER BY seq DESC LIMIT 1").fetchone())
        return str(row[0]) if row else _ZERO

    def verify(self) -> str:
        """Re-derive the whole chain and return the last digest; Refused('unavailable') if any entry was edited, removed from
        the middle or reordered."""
        rows = self._guard(lambda db: db.execute(f"SELECT digest, entry FROM {self._t} ORDER BY seq").fetchall())
        last = _ZERO
        for n, (stored, text) in enumerate(rows, 1):
            try:
                e = json.loads(text)
                claimed = e.pop("digest")
                if e["prev"] != last or subject_digest(e) != claimed or claimed != stored:
                    raise ValueError("chain broken")
            except (ValueError, KeyError, TypeError):
                raise Refused("unavailable", f"the audit record is damaged at entry {n}") from None
            last = claimed
        return last
