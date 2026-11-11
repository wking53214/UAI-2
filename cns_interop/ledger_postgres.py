"""ledger_postgres: a ledger whose truth lives in PostgreSQL, so several hosts share it.

WHAT IT GUARANTEES, AND WHAT IT NEEDS TO

  * One row per message `(sender, id)`. `reserve` and `spend` are a single `INSERT ... ON CONFLICT DO UPDATE ... WHERE`
    statement: the row lock makes it atomic, so of any number of concurrent callers on any number of hosts exactly one is
    granted. A lapsed lease is taken over by the same statement; a live lease or a committed message is `replayed`.
  * Time is the DATABASE's. Every lease is judged by the server's clock; the caller's clock is ignored unless a test
    stand-in is allowed to drive time (`allow_caller_time`). A host with a wrong clock cannot shorten anyone's lease.
  * A message that has expired by the server's clock is refused (`expired`) by `spend` and `reserve`, never granted. The
    ledger forgets a row `keep_ms` after its message expired, by the same clock, so a forgotten row is one no spend can
    take again whatever a receiver's own clock says (RACE-02 R2-C-01: a receiver whose clock lagged by more than `keep_ms`
    once redeemed an expired decision again after the purge). `TrustedClock` is the receiver-side half of the same rule.
  * Each grant draws a fence from a sequence, so it only ever grows (see fencing.FencedTarget).
  * Failure is refusal. A connection that cannot be made, a statement that times out (`statement_timeout`,
    `lock_timeout`, `tcp_user_timeout`), a dropped link, a server that is down or in recovery: `Refused("unavailable")`.
    An ambiguous commit (the server may have committed and the answer was lost) is also `unavailable`; the row may then be
    held until its lease lapses, which is the documented model (docs/interop/CONSISTENCY.md).

AND WHAT IT DOES NOT GUARANTEE BY ITSELF. A single PostgreSQL node is exactly as available and durable as that node.
Several hosts sharing it are safe from double redemption while it is up. HIGH AVAILABILITY needs a standby, and an
asynchronous standby can lose an acknowledged reservation on failover (measured with Redis in CONSISTENCY.md; PostgreSQL
behaves the same way). Pass `require_sync_replication=True` to make every write demand quorum-durable commit
(`synchronous_standby_names` set, `synchronous_commit` of `on` or stronger): the ledger then refuses to write unless the
server is configured that way, and a commit that the standby cannot confirm times out as `unavailable` instead of being
acknowledged. That is a configuration check plus a timeout; it is not a proof of the server's replication.

EXACTLY-ONCE EFFECTS. `commit_in(connection, reservation)` runs the commit on the CALLER's open transaction, so a business
write and the spend of the message happen together or not at all. That is the one place this ledger can support an
exactly-once effect; a target that is not in the same database gets at-least-once and the idempotency key.
"""

from __future__ import annotations

import re
import secrets
import threading
import time
from typing import Any, Callable, Optional, Tuple

from .envelope import MAX_INT, Refused, now_ms
from .ledger import Reservation, _check_lease

__all__ = ["PostgresLedger", "PgGuard", "TrustedClock"]

_NAME = re.compile(r"\A[a-z_][a-z0-9_]{0,40}\Z")
_NOW_MS = "(extract(epoch from clock_timestamp()) * 1000)::bigint"
#: 2000-01-01T00:00:00Z. A database that answers an earlier time (or a negative one) has no clock worth judging lifetimes by.
_EARLIEST_PLAUSIBLE_MS = 946_684_800_000


def _server_time(row: Any) -> int:
    """The database's answer to the time query as an integer, or Refused('unavailable') when it is not a plausible time in
    ms: no row, NULL, not an integer (a bool, text, a float), negative, before 2000, or beyond 2**53 - 1. A reference that
    cannot be read is no reference: the receiver does not act on it, and never treats it as a passing check (R2-C-09)."""
    value = row[0] if isinstance(row, (tuple, list)) and len(row) == 1 else None
    if isinstance(value, bool) or not isinstance(value, int) or not _EARLIEST_PLAUSIBLE_MS <= value <= MAX_INT:
        raise Refused("unavailable", "the ledger database did not answer the time query with a plausible time in ms, so "
                                     "message lifetimes cannot be judged")
    return value


class PgGuard:
    """One hardened way to talk to PostgreSQL, shared by the ledger and the receiver's policy and audit stores: bounded
    connect, statement, lock and TCP timeouts, an optional quorum-durable commit requirement, and every answer that is not
    definite turned into Refused('unavailable')."""

    def __init__(self, dsn: str, *, connect_timeout_s: int = 3, statement_timeout_ms: int = 3_000,
                 tcp_user_timeout_ms: int = 3_000, require_sync_replication: bool = False) -> None:
        try:
            import psycopg
        except ImportError:
            raise RuntimeError("PostgreSQL support needs the optional extra: pip install 'cns[postgres]'") from None
        self._pg, self._dsn = psycopg, dsn
        self._connect_kw: dict[str, Any] = {"connect_timeout": connect_timeout_s, "tcp_user_timeout": tcp_user_timeout_ms,
                            "options": f"-c statement_timeout={statement_timeout_ms} -c lock_timeout={statement_timeout_ms}"}
        self._sync = require_sync_replication
        self._commit_wait_s = statement_timeout_ms / 1000.0

    def _connect(self) -> Any:
        return self._pg.connect(self._dsn, autocommit=False, **self._connect_kw)

    def _guard(self, fn: Callable[[Any], Any]) -> Any:
        """Run `fn(connection)` in one transaction. Anything that is not a definite answer is Refused('unavailable')."""
        try:
            with self._connect() as db:
                notices: list = []
                db.add_notice_handler(lambda n: notices.append(str(getattr(n, "message_primary", n))))
                if self._sync:
                    self._require_quorum(db)
                out = fn(db)
                # statement_timeout does NOT interrupt a COMMIT that is waiting for the standby (measured: the backend
                # stays in SyncRep past it), so a watchdog cancels the wait from outside. The server then answers the
                # commit with success plus a notice, which is checked below and refused.
                watchdog = threading.Timer(self._commit_wait_s, db.cancel)
                watchdog.daemon = True
                watchdog.start()
                try:
                    db.commit()
                finally:
                    watchdog.cancel()
                # PostgreSQL answers a COMMIT whose wait for the standby was cancelled (statement_timeout, a cancel) with
                # SUCCESS and a warning: the transaction is committed on THIS node and may not exist anywhere else. Taking
                # that as "granted" is the acknowledged-write-lost failure, so it is refused, and the row stays held.
                if any("synchronous replication" in n for n in notices):
                    raise Refused("unavailable", "the commit was not confirmed by the standby, so it is not treated as "
                                                 "granted (it may be held on this node until its lease lapses)")
                return out
        except Refused:
            raise
        except self._pg.Error as exc:
            raise Refused("unavailable", f"the ledger database did not give a definite answer ({type(exc).__name__})") from None
        except OSError as exc:
            raise Refused("unavailable", f"the ledger database is unreachable ({type(exc).__name__})") from None

    def server_now_ms(self) -> int:
        """The database's clock, in ms: the clock every lease is judged by. An answer that is missing, malformed or
        implausible is Refused('unavailable'), never a number and never a crash."""
        return _server_time(self._guard(lambda db: db.execute(f"SELECT {_NOW_MS}").fetchone()))

    def _measure(self, max_skew_ms: int, clock: Optional[Callable[[], int]]) -> Tuple[int, int]:
        """(skew, server): this host's clock minus the database's, and the database's time. Refuses ('clock_skew') when the
        skew exceeds `max_skew_ms` plus half the round trip, which bounds what the measurement cannot know."""
        if isinstance(max_skew_ms, bool) or not isinstance(max_skew_ms, int) or max_skew_ms < 0:
            raise ValueError("max_skew_ms is a non-negative integer")
        read = clock or now_ms
        t0 = read()
        server = self.server_now_ms()
        t1 = read()
        skew, slack = round((t0 + t1) / 2 - server), -(-abs(t1 - t0) // 2)
        if abs(skew) > max_skew_ms + slack:
            raise Refused("clock_skew", f"this host's clock differs from the ledger database's by {skew} ms, more than the "
                                        f"{max_skew_ms} ms allowed, so message lifetimes cannot be judged")
        return skew, server

    def check_clock(self, max_skew_ms: int, *, clock: Optional[Callable[[], int]] = None) -> int:
        """Refuse ('clock_skew') when this host's clock and the database's disagree by more than `max_skew_ms`, plus half
        the round trip. A receiver calls this before judging message lifetimes, so a host clock set back or forward is
        caught instead of trusted. Returns the measured skew, host minus server. It compares with ONE reference: a database
        whose own clock is wrong passes or fails a correct host, so the database's clock must be disciplined too."""
        return self._measure(max_skew_ms, clock)[0]

    def _require_quorum(self, db: Any) -> None:
        names = db.execute("SHOW synchronous_standby_names").fetchone()[0]
        mode = db.execute("SHOW synchronous_commit").fetchone()[0]
        if not names or mode not in ("on", "remote_apply"):
            raise Refused("unavailable", "this ledger was told to require quorum-durable commits and the server is not "
                                         "configured for them (synchronous_standby_names and synchronous_commit)")
        db.execute("SET LOCAL synchronous_commit = 'remote_apply'")


class TrustedClock:
    """The ledger database's time, carried between readings by this host's MONOTONIC clock, for a receiver that judges
    message lifetimes by the database's time and not by its own wall clock (RACE-02 decision C).

    `sync()` reads the database's time and refuses: `clock_skew` when this host's wall clock and the database's disagree by
    more than `max_skew_ms` (plus half the round trip); `unavailable` when the database does not answer, times out, or
    answers with something that is not a plausible time. Construction raises ValueError (the runner's `config`) unless
    the tolerance is strictly below the ledger's retention window `keep_ms`: the ledger forgets a row `keep_ms` after its
    message expired, so every receiver within tolerance must already refuse that message as expired, or a forgotten row
    could be spent again. Calling the clock never touches the database and never raises: it answers the database's time
    at the last sync plus the monotonic time elapsed since, which a wall clock set back or forward does not move. A
    `RemoteDecisionGuard` given this clock syncs it on every `authorize`, so the check is per decision, not only at
    start-up. One reference: a database whose own clock is wrong by more than the tolerance is refused, not followed, and
    one wrong by less is followed; the database's clock must be disciplined too."""

    def __init__(self, guard: PgGuard, max_skew_ms: int, *, keep_ms: int, wall: Callable[[], int] = now_ms) -> None:
        if isinstance(max_skew_ms, bool) or not isinstance(max_skew_ms, int) or max_skew_ms < 0:
            raise ValueError("max_skew_ms is a non-negative integer")
        if isinstance(keep_ms, bool) or not isinstance(keep_ms, int) or max_skew_ms >= keep_ms:
            raise ValueError(f"the clock-skew tolerance ({max_skew_ms} ms) must be strictly below the ledger's retention "
                             f"window keep_ms ({keep_ms} ms): a row the ledger has forgotten must already be expired for "
                             "every receiver within tolerance")
        self._guard, self._max, self._wall = guard, max_skew_ms, wall
        self._server: Optional[int] = None
        self._mono = 0

    def sync(self) -> int:
        """Read the database's time now; refuse if it cannot be trusted. Returns the measured skew, host minus server."""
        skew, server = self._guard._measure(self._max, self._wall)
        self._server, self._mono = server, time.monotonic_ns()
        return skew

    def __call__(self) -> int:
        if self._server is None:
            raise ValueError("a TrustedClock answers only after sync()")
        return self._server + (time.monotonic_ns() - self._mono) // 1_000_000


class PostgresLedger(PgGuard):
    def __init__(self, dsn: str, *, table: str = "uai_spent", keep_ms: int = 120_000, connect_timeout_s: int = 3,
                 statement_timeout_ms: int = 3_000, tcp_user_timeout_ms: int = 3_000,
                 require_sync_replication: bool = False, allow_caller_time: bool = False) -> None:
        if not _NAME.match(table):
            raise ValueError("table is a lowercase SQL identifier")
        super().__init__(dsn, connect_timeout_s=connect_timeout_s, statement_timeout_ms=statement_timeout_ms,
                         tcp_user_timeout_ms=tcp_user_timeout_ms, require_sync_replication=require_sync_replication)
        self._t, self._keep = table, keep_ms
        self._caller_time = allow_caller_time
        self._guard(self._create)

    @property
    def keep_ms(self) -> int:
        """How long after its expiry a message's row is kept; a receiver's clock-skew tolerance must stay below it."""
        return self._keep

    def _create(self, db: Any) -> None:
        db.execute("SELECT pg_advisory_xact_lock(7243001)")  # two hosts creating the table at once must not race
        db.execute(f"CREATE TABLE IF NOT EXISTS {self._t} (sender text NOT NULL, id text NOT NULL, state text NOT NULL "
                   "CHECK (state IN ('leased','committed')), token text, lease_until bigint, expires_at bigint, "
                   "fence bigint NOT NULL DEFAULT 0, PRIMARY KEY (sender, id))")
        db.execute(f"CREATE INDEX IF NOT EXISTS {self._t}_exp ON {self._t} (expires_at)")
        db.execute(f"CREATE SEQUENCE IF NOT EXISTS {self._t}_fence")

    def _time(self, now: Optional[int]) -> tuple:
        if self._caller_time and now is not None:
            return "%s", (now,)
        return _NOW_MS, ()

    # ------------------------------------------------------------------------------------------------ the ledger
    def _grant(self, db: Any, sender: str, message_id: str, expires_at: Optional[int], state: str, token: Optional[str],
               lease_ms: int, now: Optional[int]) -> Optional[tuple]:
        t_sql, t_args = self._time(now)
        if not self._caller_time:
            _server_time(db.execute(f"SELECT {_NOW_MS}").fetchone())  # no usable database time: nothing is judged or written
        if expires_at is not None and db.execute(f"SELECT {t_sql} >= %s", (*t_args, expires_at)).fetchone()[0]:
            raise Refused("expired", "the message has expired by the ledger database's clock, so it is not spent")
        db.execute(f"DELETE FROM {self._t} WHERE expires_at IS NOT NULL AND expires_at <= {t_sql} - %s",
                   (*t_args, self._keep))
        lease = f"{t_sql} + %s" if state == "leased" else "NULL"
        lease_args = (*t_args, lease_ms) if state == "leased" else ()
        row = db.execute(
            f"INSERT INTO {self._t} (sender, id, state, token, lease_until, expires_at, fence) "
            f"VALUES (%s, %s, %s, %s, {lease}, %s, nextval('{self._t}_fence')) "
            f"ON CONFLICT (sender, id) DO UPDATE SET state = EXCLUDED.state, token = EXCLUDED.token, "
            f"lease_until = EXCLUDED.lease_until, expires_at = EXCLUDED.expires_at, fence = EXCLUDED.fence "
            f"WHERE {self._t}.state = 'leased' AND {self._t}.lease_until <= {t_sql} "
            f"RETURNING fence, lease_until",
            (sender, message_id, state, token, *lease_args, expires_at, *t_args)).fetchone()
        return row

    def spend(self, sender: str, message_id: str, expires_at: Optional[int], *, now: Optional[int] = None) -> None:
        row = self._guard(lambda db: self._grant(db, sender, message_id, expires_at, "committed", None, 0, now))
        if row is None:
            raise Refused("replayed", "this message was already accepted once or is being redeemed right now")

    def reserve(self, sender: str, message_id: str, expires_at: Optional[int], *, lease_ms: int,
                now: Optional[int] = None) -> Reservation:
        lease, token = _check_lease(lease_ms), secrets.token_hex(16)
        row = self._guard(lambda db: self._grant(db, sender, message_id, expires_at, "leased", token, lease, now))
        if row is None:
            raise Refused("replayed", "this message was already accepted once or is being redeemed right now")
        return Reservation(sender, message_id, expires_at, token, int(row[1]), int(row[0]))

    def _commit_sql(self, db: Any, r: Reservation) -> None:
        done = db.execute(f"UPDATE {self._t} SET state = 'committed', token = NULL, lease_until = NULL "
                          "WHERE sender = %s AND id = %s AND token = %s RETURNING 1",
                          (r.sender, r.message_id, r.token)).fetchone()
        if done is None:  # nothing of ours: forgotten after expiry (spend it now) or taken by someone else
            added = db.execute(f"INSERT INTO {self._t} (sender, id, state, expires_at, fence) "
                               f"VALUES (%s, %s, 'committed', %s, 0) ON CONFLICT DO NOTHING RETURNING 1",
                               (r.sender, r.message_id, r.expires_at)).fetchone()
            if added is None:
                raise Refused("lease_lost", "the message was taken by another redemption after this lease lapsed")

    def commit(self, reservation: Reservation, *, now: Optional[int] = None) -> None:
        self._guard(lambda db: self._commit_sql(db, reservation))

    def commit_in(self, connection: Any, reservation: Reservation) -> None:
        """Spend the message on the CALLER's open transaction, so a business write and this commit are one atomic unit:
        both persist or neither does (a client that dies before COMMIT leaves the lease to lapse and the message
        redeemable). The caller commits, and against a synchronous standby the caller must bound that COMMIT itself the
        way `_guard` does (a cancel timer, and a refusal if the server reports the wait was cancelled). Errors surface as Refused, as everywhere else in this ledger."""
        try:
            self._commit_sql(connection, reservation)
        except Refused:
            raise
        except self._pg.Error as exc:
            raise Refused("unavailable", f"the ledger database did not give a definite answer ({type(exc).__name__})") from None

    def release(self, reservation: Reservation, *, now: Optional[int] = None) -> None:
        def run(db: Any) -> None:
            gone = db.execute(f"DELETE FROM {self._t} WHERE sender = %s AND id = %s AND token = %s RETURNING 1",
                              (reservation.sender, reservation.message_id, reservation.token)).fetchone()
            if gone is None:
                other = db.execute(f"SELECT 1 FROM {self._t} WHERE sender = %s AND id = %s",
                                   (reservation.sender, reservation.message_id)).fetchone()
                if other is not None:
                    raise Refused("lease_lost", "only the holder of a lease can release it")
        self._guard(run)
