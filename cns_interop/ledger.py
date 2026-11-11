"""ledger: a receiver's memory of which messages it has already acted on, so none is acted on twice.

A signature proves a message is genuine; it cannot prove the message is new. Anyone who saw a signed decision can
send it again. The receiver therefore keeps a ledger of (sender, message id) pairs it has accepted, and `spend`
refuses a pair it has seen. Because every message the session layer accepts must expire, an entry only has to be
kept until its message would be refused as expired anyway.

WHAT EACH LEDGER GUARANTEES, AND WHAT IT DOES NOT

  MemoryLedger      one process. Lost on restart.
  FileLedger        many processes on ONE host, sharing one file under a POSIX lock. Not for network filesystems.
  SqliteLedger      many processes on ONE host, sharing one SQLite database (transactions, not hand-written locking).
  CoordinatedLedger many hosts, but ONLY if the `Coordinator` it is given is a linearizable store the receiver owns
                    (etcd, a SQL primary with a unique key, Redis with compare-and-set). A coordinator that cannot
                    answer makes the ledger refuse ("unavailable"). It never guesses. No coordinator ships here; the
                    in-memory one is a test stand-in, so cross-host behaviour is demonstrated against that stand-in.

Two hosts with two FileLedgers accept the same decision twice. That is not a defect in FileLedger, it is what a local
ledger is. A deployment with several hosts acting for one identity must use a coordinated ledger or send every
redemption to one host.

TWO PHASES

`spend` consumes a message at once. An action that can fail after the permission is checked wants the permission to
survive the failure: `reserve` takes a lease on the message (a second reserve is refused while the lease is live),
`commit` consumes it for good, `release` gives it back when the action did not happen. A holder that crashes loses
its lease when it lapses and the message can be reserved again. That makes the action at-least-once, so the action
must be idempotent on `Reservation.key`, the idempotency key it is handed.

`reserve`, `commit` and `release` are separate from `Ledger` on purpose: a ledger that only offers `spend` still works
everywhere it did.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, Dict, Iterator, List, Optional, Protocol, Tuple, runtime_checkable

from .envelope import Refused, now_ms

__all__ = ["Ledger", "TwoPhaseLedger", "Reservation", "MemoryLedger", "FileLedger", "SqliteLedger",
           "CoordinatedLedger", "Coordinator", "AmbiguousResult", "InMemoryCoordinator"]

MAX_LEASE_MS = 3600 * 1000


class Ledger(Protocol):
    def spend(self, sender: str, message_id: str, expires_at: Optional[int], *, now: Optional[int] = None) -> None: ...


@dataclass(frozen=True)
class Reservation:
    """A lease on one message. `key` is the idempotency key for whatever action the lease protects."""

    sender: str
    message_id: str
    expires_at: Optional[int]
    token: str
    lease_until: int
    #: A value that only grows across every reservation the ledger grants. A protected target that remembers the highest
    #: fence it has acted on and refuses a lower one (fencing.FencedTarget) rejects a stale holder whose lease lapsed
    #: and whose action arrives late. 0 means this ledger issues none (FileLedger), so such a target must not trust it.
    fence: int = 0

    @property
    def key(self) -> str:
        return f"{self.sender} {self.message_id}"


@runtime_checkable
class TwoPhaseLedger(Ledger, Protocol):
    def reserve(self, sender: str, message_id: str, expires_at: Optional[int], *, lease_ms: int,
                now: Optional[int] = None) -> Reservation: ...

    def commit(self, reservation: Reservation, *, now: Optional[int] = None) -> None: ...

    def release(self, reservation: Reservation, *, now: Optional[int] = None) -> None: ...


# ---- the one state machine every ledger runs. An entry is committed (spent for good) or reserved (leased). ----

def _check_lease(lease_ms: int) -> int:
    if isinstance(lease_ms, bool) or not isinstance(lease_ms, int) or not 0 < lease_ms <= MAX_LEASE_MS:
        raise ValueError(f"lease_ms is a positive integer, at most {MAX_LEASE_MS}")
    return lease_ms


def _is_entry(e: Any) -> bool:
    if not isinstance(e, dict) or not isinstance(e.get("sender"), str) or not isinstance(e.get("id"), str):
        return False
    exp = e.get("expires_at", "missing")
    if not (exp is None or (isinstance(exp, int) and not isinstance(exp, bool))):
        return False
    if set(e) == {"sender", "id", "expires_at"}:
        return True
    return (set(e) in ({"sender", "id", "expires_at", "lease_until", "token"},
                       {"sender", "id", "expires_at", "lease_until", "token", "fence"})
            and isinstance(e["token"], str)
            and isinstance(e["lease_until"], int) and not isinstance(e["lease_until"], bool))


def _forgotten(e: Dict[str, Any], cutoff: int, now: int) -> bool:
    """An entry that holds nothing any more: its message expired long enough ago, or its lease lapsed."""
    if e["expires_at"] is not None and e["expires_at"] <= cutoff:
        return True
    return "lease_until" in e and e["lease_until"] <= now


def _spend_step(cur: Optional[Dict[str, Any]], sender: str, message_id: str, expires_at: Optional[int],
                now: int) -> Dict[str, Any]:
    if cur is not None:
        raise Refused("replayed", "this message was already accepted once" if "lease_until" not in cur
                      else "this message is being redeemed right now")
    return {"sender": sender, "id": message_id, "expires_at": expires_at}


def _reserve_step(cur: Optional[Dict[str, Any]], sender: str, message_id: str, expires_at: Optional[int],
                  now: int, lease_ms: int, token: str, fence: int = 0) -> Dict[str, Any]:
    if cur is not None:
        raise Refused("replayed", "this message was already accepted once" if "lease_until" not in cur
                      else "this message is being redeemed right now")
    entry = {"sender": sender, "id": message_id, "expires_at": expires_at, "lease_until": now + lease_ms, "token": token}
    if fence:
        entry["fence"] = fence
    return entry


def _commit_step(cur: Optional[Dict[str, Any]], r: Reservation) -> Dict[str, Any]:
    if cur is not None and cur.get("token") != r.token:
        raise Refused("lease_lost", "the message was taken by another redemption after this lease lapsed")
    # cur is None when the lease lapsed and was forgotten with nobody else holding it: the action happened, so
    # the message is spent now. cur is this holder's reservation: promote it.
    return {"sender": r.sender, "id": r.message_id, "expires_at": r.expires_at}


def _release_step(cur: Optional[Dict[str, Any]], r: Reservation) -> Optional[Dict[str, Any]]:
    if cur is None:
        return None
    if cur.get("token") != r.token:
        raise Refused("lease_lost", "only the holder of a lease can release it")
    return None


class MemoryLedger:
    def __init__(self, *, keep_ms: int = 120_000) -> None:
        self._seen: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._keep_ms = keep_ms
        self._fence = 0

    def _next_fence(self) -> int:
        self._fence += 1  # called from a step, which runs under self._lock
        return self._fence

    def _mutate(self, sender: str, message_id: str, now: Optional[int],
                step: Callable[[Optional[Dict[str, Any]], int], Optional[Dict[str, Any]]]) -> Dict[str, Any]:
        with self._lock:
            t = now_ms() if now is None else now
            cutoff = _cutoff(now, self._keep_ms)  # an entry is kept until its message would be refused as expired
            self._seen = {k: e for k, e in self._seen.items() if not _forgotten(e, cutoff, t)}
            new = step(self._seen.get((sender, message_id)), t)
            if new is None:
                self._seen.pop((sender, message_id), None)
                return {}
            self._seen[(sender, message_id)] = new
            return dict(new)

    def spend(self, sender: str, message_id: str, expires_at: Optional[int], *, now: Optional[int] = None) -> None:
        self._mutate(sender, message_id, now, lambda cur, t: _spend_step(cur, sender, message_id, expires_at, t))

    def reserve(self, sender: str, message_id: str, expires_at: Optional[int], *, lease_ms: int,
                now: Optional[int] = None) -> Reservation:
        token, lease = secrets.token_hex(16), _check_lease(lease_ms)
        e = self._mutate(sender, message_id, now, lambda cur, t: _reserve_step(
            cur, sender, message_id, expires_at, t, lease, token, self._next_fence()))
        return Reservation(sender, message_id, expires_at, token, e["lease_until"], e.get("fence", 0))

    def commit(self, reservation: Reservation, *, now: Optional[int] = None) -> None:
        self._mutate(reservation.sender, reservation.message_id, now, lambda cur, t: _commit_step(cur, reservation))

    def release(self, reservation: Reservation, *, now: Optional[int] = None) -> None:
        self._mutate(reservation.sender, reservation.message_id, now, lambda cur, t: _release_step(cur, reservation))


def _refuse_single_host_under_production(kind: str) -> None:
    """Under the production profile a single-host ledger is refused at construction: a process that builds its own
    file or database ledger would spend a decision the shared ledger never saw (the spine's recorded gap). Use the
    shared PostgresLedger; this is the same rule interop/act.py applies to its command line."""
    from . import crypto_backend

    if crypto_backend.production():
        raise RuntimeError(f"the production profile does not accept a single-host {kind}; "
                           "use the shared PostgresLedger, so every process spends against one ledger")


class FileLedger:
    """Shared by every process on this host that opens the same path. POSIX file locks; not for network filesystems."""

    def __init__(self, path: os.PathLike | str, *, keep_ms: int = 120_000) -> None:
        _refuse_single_host_under_production("file ledger")
        try:
            import fcntl  # noqa: F401
        except ImportError:  # pragma: no cover - there is no POSIX lock to share
            raise RuntimeError("FileLedger needs POSIX file locks (fcntl); use one process with MemoryLedger") from None
        self._path = Path(path)
        self._keep_ms = keep_ms
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.touch(exist_ok=True)

    def spend(self, sender: str, message_id: str, expires_at: Optional[int], *, now: Optional[int] = None) -> None:
        self._mutate(sender, message_id, expires_at, now, lambda cur, t: _spend_step(cur, sender, message_id,
                                                                                    expires_at, t))

    def reserve(self, sender: str, message_id: str, expires_at: Optional[int], *, lease_ms: int,
                now: Optional[int] = None) -> "Reservation":
        token = secrets.token_hex(16)
        lease = _check_lease(lease_ms)
        entry = self._mutate(sender, message_id, expires_at, now, lambda cur, t: _reserve_step(
            cur, sender, message_id, expires_at, t, lease, token))
        return Reservation(sender, message_id, expires_at, token, entry["lease_until"])

    def commit(self, reservation: "Reservation", *, now: Optional[int] = None) -> None:
        self._mutate(reservation.sender, reservation.message_id, reservation.expires_at, now,
                     lambda cur, t: _commit_step(cur, reservation))

    def release(self, reservation: "Reservation", *, now: Optional[int] = None) -> None:
        self._mutate(reservation.sender, reservation.message_id, reservation.expires_at, now,
                     lambda cur, t: _release_step(cur, reservation))

    def _mutate(self, sender: str, message_id: str, expires_at: Optional[int], now: Optional[int],
                step: Callable[[Optional[Dict[str, Any]], int], Optional[Dict[str, Any]]]) -> Dict[str, Any]:
        """Read the file, let `step` turn this key's entry into its next entry (or None to delete it), and write the
        result, all under the one lock. An entry that has expired, or a reservation whose lease lapsed, is forgotten."""
        with self._locked() as fh:
            fd = fh.fileno()
            t = now_ms() if now is None else now
            entries = self._read(fd, fh.read())
            cutoff = _cutoff(now, self._keep_ms)
            live = [e for e in entries if not _forgotten(e, cutoff, t)]
            key = (sender, message_id)
            cur = next((e for e in live if (e["sender"], e["id"]) == key), None)
            new = step(cur, t)
            rest = [e for e in live if (e["sender"], e["id"]) != key]
            result = dict(new) if new is not None else {}
            if len(live) == len(entries) and cur is None and new is not None:
                self._append(fd, _line(new))
            elif len(live) != len(entries) or cur != new:
                self._compact([*rest, *([new] if new is not None else [])])
            return result

    @staticmethod
    def _read(fd: int, raw: bytes) -> List[Dict[str, Any]]:
        """The entries in the file, or Refused('unavailable') when the file cannot be trusted to be complete.

        A final line with no newline is a write a killed process never finished. `spend` returns only after the line
        and its newline are durable, so that fragment was never acknowledged to anyone and is cut off. Any other line
        that does not read as an entry means the file was damaged some other way, and a ledger that cannot be read
        cannot say a message is new: it refuses and spends nothing, rather than guess."""
        torn = bool(raw) and not raw.endswith(b"\n")
        lines = raw.split(b"\n")
        tail = lines.pop() if torn else None
        entries: List[Dict[str, Any]] = []
        for number, ln in enumerate(lines, 1):
            if not ln.strip():
                continue
            try:
                e = json.loads(ln.decode("utf-8"))
                if not _is_entry(e):
                    raise ValueError("not a ledger entry")
            except (ValueError, UnicodeDecodeError):
                raise Refused("unavailable", f"the ledger file is damaged at line {number}; no message can be "
                                             "judged new until it is repaired") from None
            entries.append(e)
        if tail is not None:
            os.ftruncate(fd, len(raw) - len(tail))
            os.fsync(fd)
        return entries

    @contextmanager
    def _locked(self) -> Iterator[BinaryIO]:
        """The ledger file, open and exclusively locked. Compaction replaces the file, so a lock taken on a file that
        was replaced while this process waited is on the wrong file: it is dropped and the current file locked."""
        import fcntl

        while True:
            fh = open(self._path, "r+b", buffering=0)
            try:
                fcntl.flock(fh, fcntl.LOCK_EX)
                try:
                    current = os.stat(self._path).st_ino == os.fstat(fh.fileno()).st_ino
                except FileNotFoundError:  # pragma: no cover - replaced between the open and the stat
                    current = False
                if current:
                    yield fh
                    return
            finally:
                fh.close()

    @staticmethod
    def _append(fd: int, data: bytes) -> None:
        """Add one line at the end and make it durable. The earlier entries are never rewritten, so a failure cannot
        lose them; a failure partway through is undone so no torn line is left for the next reader."""
        end = os.lseek(fd, 0, os.SEEK_END)
        try:
            _write_all(fd, data)
            os.fsync(fd)
        except BaseException:
            try:
                os.ftruncate(fd, end)
            except OSError:  # pragma: no cover - best effort; the original failure is the one that matters
                pass
            raise

    def _compact(self, entries: List[Dict[str, Any]]) -> None:
        """Replace the file with `entries`, all or nothing: write a temp file beside it, flush it to disk, rename it
        over the ledger, then flush the directory so the rename itself survives a crash."""
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix=self._path.name + ".", suffix=".tmp")
        try:
            try:
                _write_all(fd, b"".join(_line(e) for e in entries))
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, self._path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        dir_fd = os.open(self._path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


class SqliteLedger:
    """Shared by every process on this host that opens the same database. SQLite does the locking and the crash
    recovery (a write is whole or absent), which is why this is the better local ledger when many processes share it.
    Still one host: do not put the database on a network filesystem."""

    def __init__(self, path: os.PathLike | str, *, keep_ms: int = 120_000, busy_ms: int = 5_000) -> None:
        _refuse_single_host_under_production("SQLite ledger")
        self._path, self._keep_ms, self._busy_ms = str(path), keep_ms, busy_ms
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        try:
            with self._connect() as db:
                db.execute("CREATE TABLE IF NOT EXISTS spent (sender TEXT NOT NULL, id TEXT NOT NULL, "
                           "expires_at INTEGER, lease_until INTEGER, token TEXT, PRIMARY KEY (sender, id))")
        except sqlite3.DatabaseError as exc:
            raise Refused("unavailable", f"the ledger database cannot be opened ({exc})") from None

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self._path, timeout=self._busy_ms / 1000, isolation_level=None)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def _mutate(self, sender: str, message_id: str, now: Optional[int],
                step: Callable[[Optional[Dict[str, Any]], int], Optional[Dict[str, Any]]]) -> Dict[str, Any]:
        t = now_ms() if now is None else now
        cutoff = _cutoff(now, self._keep_ms)
        try:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")  # the write lock is taken here: check and write are one step
                db.execute("DELETE FROM spent WHERE (expires_at IS NOT NULL AND expires_at <= ?) OR "
                           "(lease_until IS NOT NULL AND lease_until <= ?)", (cutoff, t))
                row = db.execute("SELECT expires_at, lease_until, token FROM spent WHERE sender=? AND id=?",
                                 (sender, message_id)).fetchone()
                cur: Optional[Dict[str, Any]] = None
                if row is not None:
                    cur = {"sender": sender, "id": message_id, "expires_at": row[0]}
                    if row[1] is not None:
                        cur.update(lease_until=row[1], token=row[2])
                new = step(cur, t)
                db.execute("DELETE FROM spent WHERE sender=? AND id=?", (sender, message_id))
                if new is not None:
                    db.execute("INSERT INTO spent VALUES (?,?,?,?,?)", (sender, message_id, new["expires_at"],
                                                                         new.get("lease_until"), new.get("token")))
                db.execute("COMMIT")
                return dict(new) if new is not None else {}
            except BaseException:
                try:
                    db.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            finally:
                db.close()
        except sqlite3.Error as exc:  # busy past the timeout, corrupt, disk full: no answer, so no permission
            raise Refused("unavailable", f"the ledger database did not answer ({exc})") from None

    def spend(self, sender: str, message_id: str, expires_at: Optional[int], *, now: Optional[int] = None) -> None:
        self._mutate(sender, message_id, now, lambda cur, t: _spend_step(cur, sender, message_id, expires_at, t))

    def reserve(self, sender: str, message_id: str, expires_at: Optional[int], *, lease_ms: int,
                now: Optional[int] = None) -> Reservation:
        token, lease = secrets.token_hex(16), _check_lease(lease_ms)
        e = self._mutate(sender, message_id, now, lambda cur, t: _reserve_step(
            cur, sender, message_id, expires_at, t, lease, token))
        return Reservation(sender, message_id, expires_at, token, e["lease_until"])

    def commit(self, reservation: Reservation, *, now: Optional[int] = None) -> None:
        self._mutate(reservation.sender, reservation.message_id, now, lambda cur, t: _commit_step(cur, reservation))

    def release(self, reservation: Reservation, *, now: Optional[int] = None) -> None:
        self._mutate(reservation.sender, reservation.message_id, now, lambda cur, t: _release_step(cur, reservation))


class AmbiguousResult(Exception):
    """A coordinator could not tell whether its write took effect (a timeout after the request left)."""


class Coordinator(Protocol):
    """What a many-host ledger needs from a store the receiver owns. `cas` MUST be linearizable: of all concurrent
    callers that pass the same `expected`, exactly one gets True. `expected=None` means the key must be absent;
    `new=None` deletes. etcd transactions, a SQL `INSERT ... ON CONFLICT DO NOTHING` plus a conditional UPDATE, and
    Redis with a script all qualify. A cache that can lose keys, or a store that reads from replicas, does not."""

    def get(self, key: str) -> Optional[Dict[str, Any]]: ...

    def cas(self, key: str, expected: Optional[Dict[str, Any]], new: Optional[Dict[str, Any]]) -> bool: ...

    def now(self) -> int:
        """The coordinator's own clock, in milliseconds. Every lease is judged by THIS clock and never by a caller's, so
        a host whose clock is wrong cannot shorten or lengthen anyone's lease. A SQL store answers `now()`; etcd answers
        with a lease TTL; a store that cannot give one cannot be a coordinator."""

    def next_fence(self) -> int:
        """A linearizable counter that only grows (a sequence, an etcd revision). Handed out with each reservation."""


class InMemoryCoordinator:
    """A single-process stand-in, linearizable by a lock. It exists so the semantics can be tested, including with
    injected faults. It is NOT evidence that any real distributed store behaves this way."""

    def __init__(self, *, clock: Callable[[], int] = now_ms) -> None:
        self._data: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._clock = clock
        self._fence = 0

    def now(self) -> int:
        return self._clock()

    def next_fence(self) -> int:
        with self._lock:
            self._fence += 1
            return self._fence

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            v = self._data.get(key)
            return dict(v) if v is not None else None

    def cas(self, key: str, expected: Optional[Dict[str, Any]], new: Optional[Dict[str, Any]]) -> bool:
        with self._lock:
            if self._data.get(key) != expected:
                return False
            if new is None:
                self._data.pop(key, None)
            else:
                self._data[key] = dict(new)
            return True


class CoordinatedLedger:
    """A ledger whose truth lives in a `Coordinator`, so several hosts share it. Every failure to get a definite
    answer from the coordinator (an exception, a timeout, an ambiguous write) is Refused('unavailable'): no
    authoritative state, no permission. Entries are never pruned here; give the coordinator a TTL from `expires_at`."""

    def __init__(self, coordinator: Coordinator, *, attempts: int = 3, allow_caller_time: bool = False) -> None:
        if not all(callable(getattr(coordinator, m, None)) for m in ("get", "cas", "now", "next_fence")):
            raise ValueError("a coordinator needs get, cas, now and next_fence (see ledger.Coordinator)")
        self._c, self._attempts, self._caller_time = coordinator, attempts, allow_caller_time

    def _run(self, sender: str, message_id: str, now: Optional[int],
             step: Callable[[Optional[Dict[str, Any]], int], Optional[Dict[str, Any]]]) -> Dict[str, Any]:
        key = f"{sender} {message_id}"
        try:
            # Time comes from the COORDINATOR, not from the caller, unless a test stand-in is explicitly allowed to drive
            # it: a host with a wrong clock must not be able to shorten another host's lease.
            t = now if (self._caller_time and now is not None) else self._c.now()
            for _ in range(self._attempts):
                cur = self._c.get(key)
                if cur is not None and _forgotten(cur, t - 1, t) and "lease_until" in cur:
                    cur_for_step: Optional[Dict[str, Any]] = None  # a lapsed lease holds nothing
                else:
                    cur_for_step = cur
                new = step(cur_for_step, t)
                if self._c.cas(key, cur, new):
                    return dict(new) if new is not None else {}
        except Refused:
            raise
        except Exception as exc:  # includes AmbiguousResult, timeouts, connection loss
            raise Refused("unavailable", "the coordinator gave no definite answer, so no authoritative state "
                                         f"can be established ({type(exc).__name__})") from None
        raise Refused("unavailable", "the coordinator stayed contended; no authoritative state was established")

    def spend(self, sender: str, message_id: str, expires_at: Optional[int], *, now: Optional[int] = None) -> None:
        self._run(sender, message_id, now, lambda cur, t: _spend_step(cur, sender, message_id, expires_at, t))

    def reserve(self, sender: str, message_id: str, expires_at: Optional[int], *, lease_ms: int,
                now: Optional[int] = None) -> Reservation:
        token, lease = secrets.token_hex(16), _check_lease(lease_ms)
        e = self._run(sender, message_id, now, lambda cur, t: _reserve_step(
            cur, sender, message_id, expires_at, t, lease, token, self._c.next_fence()))
        return Reservation(sender, message_id, expires_at, token, e["lease_until"], e.get("fence", 0))

    def commit(self, reservation: Reservation, *, now: Optional[int] = None) -> None:
        self._run(reservation.sender, reservation.message_id, now, lambda cur, t: _commit_step(cur, reservation))

    def release(self, reservation: Reservation, *, now: Optional[int] = None) -> None:
        self._run(reservation.sender, reservation.message_id, now, lambda cur, t: _release_step(cur, reservation))


def _cutoff(now: Optional[int], keep_ms: int) -> int:
    """Entries that expired before this are forgotten. It is taken from the EARLIER of the verifier's clock and this
    host's clock, so a verifier whose clock runs behind never finds a message it still accepts already forgotten."""
    wall = now_ms()
    return (wall if now is None else min(now, wall)) - keep_ms


def _line(entry: Dict[str, Any]) -> bytes:
    return (json.dumps(entry, sort_keys=True) + "\n").encode("utf-8")


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]
