"""soak.py: a long mixed-traffic run against the REAL PostgreSQL ledger, with failures injected, then every invariant checked.

    python interop/soak.py --seconds 600 --workers 8 --ids 40 --seed 1

What runs (nothing is mocked: a throwaway PostgreSQL cluster, real worker processes, the real `PostgresLedger` and the real
hash-chained audit writer):

* Workers race for a small pool of message ids, so the same message is contended all the time. Each worker reserves a
  message, writes the audit entry (the receiver audits a permit BEFORE acting), then does the business write and the
  ledger commit on ONE transaction (`commit_in`), and chooses at random to finish normally, release, stall past its lease,
  abandon the lease, or SIGKILL itself just before COMMIT.
* A chaos loop kills the database server without a clean shutdown (`pg_ctl -m immediate`) and restarts it, and SIGKILLs
  random workers, which the supervisor replaces.

Invariants checked after the run (a failure is a finding, printed with the evidence, and the exit status is 1):

1. EXACTLY ONCE: no message has more than one business effect.
2. SPENT MEANS EFFECT: the messages the ledger holds as committed are exactly the messages that have an effect (the effect
   and the spend are one transaction, so neither can exist without the other).
3. DURABLE: every commit a worker was TOLD succeeded is present afterwards, including across a server kill.
4. AUDIT AHEAD OF ACTION: every effect has an audit entry, and the audit chain verifies end to end after workers were
   SIGKILLed while writing it.
5. NOTHING STUCK: after the leases lapse, no message is still leased forever; a leftover lease is only ever one that can be
   retaken.

A commit whose answer was lost because the server died is AMBIGUOUS (it may or may not have happened). The workers log it as
ambiguous and the checks accept either outcome for it; the other invariants still bind it.

`--mid-commit P` aims at exactly that window. With probability P a worker, at the moment it sends COMMIT, starts a timer that
SIGKILLs its own database backend a few milliseconds later, so the kill lands while the COMMIT is in flight (the server then
runs crash recovery). The report counts how many such commits ended up committed and how many rolled back, so a run shows
that BOTH outcomes of the window were reached, and every invariant is still checked afterwards.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import random
import signal
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "cns_interop" / "tests"))

import psycopg  # noqa: E402
from pg_cluster import Cluster  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.envelope import Refused  # noqa: E402
from cns_interop.grants import append_audit, verify_audit  # noqa: E402
from cns_interop.ledger_postgres import PostgresLedger  # noqa: E402

SENDER = "uai:ed25519:" + "b" * 64


def _log(fh: Any, kind: str, mid: str = "") -> None:
    fh.write(f"{kind} {mid}\n")


def _kill_backend_soon(pid: int, delay_s: float) -> threading.Event:
    """SIGKILL one database backend after `delay_s`, unless the returned event is set first (the commit already returned)."""
    cancelled = threading.Event()

    def fire() -> None:
        if not cancelled.wait(delay_s):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

    threading.Thread(target=fire, daemon=True).start()
    return cancelled


def worker(dsn: str, table: str, audit: str, seed: int, ids: int, deadline: float, outdir: str, wid: int,
           mid_commit: float = 0.0) -> None:
    """One worker process. It is killed at random by the chaos loop and by itself, and it never finishes cleanly on purpose."""
    rnd = random.Random(seed)
    log = open(os.path.join(outdir, f"w{wid}-{seed}.log"), "a", buffering=1)
    led = None
    while time.time() < deadline:
        try:
            if led is None:
                led = PostgresLedger(dsn, table=table, connect_timeout_s=1, statement_timeout_ms=2_000)
            mid = f"m{int(time.time() // 3)}-{rnd.randrange(ids)}"  # a fresh pool every 3 s, so contention never runs dry
            try:
                r = led.reserve(SENDER, mid, None, lease_ms=rnd.choice([250, 700, 1500]))
            except Refused as exc:
                _log(log, "reserve-" + exc.code)
                time.sleep(0.01 if exc.code == "replayed" else 0.3)
                continue
            _log(log, "reserved", mid)
            roll = rnd.random()
            if roll >= 0.60 and roll < 0.70:
                led.release(r)
                _log(log, "released", mid)
                continue
            if roll >= 0.70 and roll < 0.78:
                _log(log, "abandoned", mid)  # the lease is left to lapse
                continue
            try:
                append_audit(audit, {"at": int(time.time() * 1000), "outcome": "permitted", "decision_id": mid,
                                     "worker": wid})
            except Refused as exc:
                _log(log, "audit-" + exc.code, mid)
                continue
            if 0.78 <= roll < 0.86:
                time.sleep(2.0)  # stall past the longest lease (1.5 s), then try to commit late
            db = psycopg.connect(dsn, connect_timeout=1)
            try:
                db.execute("INSERT INTO " + table + "_effects (key, n) VALUES (%s, 1) "
                           "ON CONFLICT (key) DO UPDATE SET n = " + table + "_effects.n + 1", (mid,))
                led.commit_in(db, r)
                if roll >= 0.86 and roll < 0.93:
                    os.kill(os.getpid(), signal.SIGKILL)  # dies before COMMIT: neither the effect nor the spend may exist
                cancel = None
                if mid_commit > 0 and rnd.random() < mid_commit:
                    cancel = _kill_backend_soon(db.info.backend_pid, rnd.uniform(0.0, 0.002))
                try:
                    db.commit()
                    if cancel is not None:
                        cancel.set()
                except psycopg.Error:
                    if cancel is not None:
                        _log(log, "mid-commit-cut", mid)
                    _log(log, "ambiguous", mid)  # the server went away during COMMIT: it may or may not have happened
                    continue
                _log(log, "committed", mid)
            except Refused as exc:
                db.rollback()
                _log(log, "commit-" + exc.code, mid)
            except psycopg.Error:
                _log(log, "db-error", mid)
            finally:
                try:
                    db.close()
                except Exception:
                    pass
        except Refused as exc:
            _log(log, "unavailable-" + exc.code)
            led = None
            time.sleep(0.3)
        except psycopg.Error:
            _log(log, "db-error")
            led = None
            time.sleep(0.3)


def run(seconds: float = 60.0, workers: int = 6, ids: int = 30, seed: int = 1, server_kills: int = -1,
        verbose: bool = True, mid_commit: float = 0.0) -> Dict[str, Any]:
    rnd = random.Random(seed)
    work = tempfile.mkdtemp(prefix="uai-soak-")
    audit = os.path.join(work, "audit.jsonl")
    table = "soak_" + uuid.uuid4().hex[:10]
    cluster = Cluster().start()
    report: Dict[str, Any] = {"seconds": seconds, "workers": workers, "ids": ids, "seed": seed, "mid_commit": mid_commit,
                              "findings": []}
    try:
        cluster.wait_ready()
        PostgresLedger(cluster.dsn, table=table)
        with psycopg.connect(cluster.dsn, autocommit=True) as db:
            db.execute(f"CREATE TABLE {table}_effects (key text PRIMARY KEY, n int NOT NULL)")
        deadline = time.time() + seconds
        procs: Dict[int, mp.Process] = {}
        counter = [0]

        def spawn(slot: int) -> None:
            counter[0] += 1
            p = mp.Process(target=worker, args=(cluster.dsn, table, audit, rnd.randrange(1 << 30), ids, deadline, work, slot, mid_commit))
            p.start()
            procs[slot] = p

        for slot in range(workers):
            spawn(slot)
        kills = {"server": 0, "worker": 0}
        next_chaos = time.time() + 3
        while time.time() < deadline:
            time.sleep(0.25)
            for slot, p in list(procs.items()):
                if not p.is_alive() and time.time() < deadline - 1:
                    spawn(slot)
            if time.time() >= next_chaos:
                next_chaos = time.time() + rnd.uniform(3, 8)
                if rnd.random() < 0.5 and (server_kills < 0 or kills["server"] < server_kills):
                    cluster.kill()
                    kills["server"] += 1
                    time.sleep(rnd.uniform(0.5, 2.0))
                    cluster.start()
                    cluster.wait_ready()
                else:
                    victim = rnd.choice(list(procs.values()))
                    if victim.is_alive() and victim.pid:
                        os.kill(victim.pid, signal.SIGKILL)
                        kills["worker"] += 1
        for p in procs.values():
            p.join(timeout=30)
            if p.is_alive():
                p.kill()
        report["kills"] = kills
        time.sleep(2.0)  # let every lease lapse
        report.update(check(cluster.dsn, table, audit, work))
    finally:
        cluster.cleanup()
    if verbose:
        print(json.dumps(report, indent=1, sort_keys=True))
    return report


def check(dsn: str, table: str, audit: str, work: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"findings": []}
    findings: List[str] = out["findings"]
    with psycopg.connect(dsn, autocommit=True) as db:
        effects = {k: n for k, n in db.execute(f"SELECT key, n FROM {table}_effects").fetchall()}
        ledger = {i: s for i, s in db.execute(f"SELECT id, state FROM {table}").fetchall()}
        stuck = db.execute(f"SELECT count(*) FROM {table} WHERE state = 'leased' AND lease_until > "
                           "(extract(epoch from now()) * 1000)::bigint").fetchone()[0]
    committed = {i for i, s in ledger.items() if s == "committed"}
    told, ambiguous, tally = set(), set(), {}
    for name in os.listdir(work):
        if not name.endswith(".log"):
            continue
        for line in open(os.path.join(work, name)):
            parts = line.split()
            if not parts:
                continue
            tally[parts[0]] = tally.get(parts[0], 0) + 1
            if parts[0] == "committed":
                told.add(parts[1])
            elif parts[0] == "ambiguous":
                ambiguous.add(parts[1])
    twice = {k: n for k, n in effects.items() if n != 1}
    if twice:
        findings.append(f"EXACTLY ONCE broken: {twice}")
    if set(effects) != committed:
        findings.append("SPENT MEANS EFFECT broken: effect without spend "
                        f"{sorted(set(effects) - committed)[:5]}, spend without effect {sorted(committed - set(effects))[:5]}")
    lost = told - set(effects)
    if lost:
        findings.append(f"DURABLE broken: workers were told these committed but they are gone: {sorted(lost)[:5]}")
    try:
        verify_audit(audit)
        entries = [json.loads(line) for line in open(audit, "rb")] if os.path.exists(audit) else []
    except Refused as exc:
        findings.append(f"AUDIT CHAIN broken after kills: {exc}")
        entries = []
    audited = {e.get("decision_id") for e in entries}
    unaudited = set(effects) - audited
    if unaudited:
        findings.append(f"AUDIT AHEAD OF ACTION broken: effects with no audit entry {sorted(unaudited)[:5]}")
    if stuck:
        findings.append(f"NOTHING STUCK broken: {stuck} message(s) still hold a live lease after everything stopped")
    out.update({"effects": len(effects), "ledger_committed": len(committed), "told_committed": len(told),
                "ambiguous": len(ambiguous), "ambiguous_committed": len(ambiguous & committed),
                "ambiguous_rolled_back": len(ambiguous - committed), "audit_entries": len(entries), "tally": dict(sorted(tally.items())),
                "ok": not findings})
    return out


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--ids", type=int, default=30, help="size of the message pool; smaller means more contention")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--server-kills", type=int, default=-1, help="at most this many server kills (default: no limit)")
    ap.add_argument("--mid-commit", type=float, default=0.0,
                    help="chance (0 to 1) that a worker's database backend is killed while its COMMIT is in flight")
    ap.add_argument("--out", default="", help="write the JSON report here")
    opts = ap.parse_args(argv)
    rep = run(opts.seconds, opts.workers, opts.ids, opts.seed, opts.server_kills, mid_commit=opts.mid_commit)
    if opts.out:
        Path(opts.out).write_text(json.dumps(rep, indent=1, sort_keys=True) + "\n")
    return 0 if rep.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
