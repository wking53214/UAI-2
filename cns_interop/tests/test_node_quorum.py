"""Quorum-durable commit and the atomic business-write commit in the Node PostgreSQL ledger, against real servers the tests start.

Node honours the same synchronous-replication requirement as Python's `_require_quorum`: with `requireSyncReplication` it
refuses (`unavailable`, the same reason text) to write to a server that has no synchronous standby configured, and a commit
the standby cannot confirm is never reported as granted. Shown against a single node (the refusal) AND against a real
streaming standby started by pg_basebackup on this machine (the success path, a partition that makes the ledger refuse, and a
failover that loses nothing anyone was told). The standby is a second server process on the same host behind a TCP proxy that
can drop traffic: it is a real replica, but it is NOT a second machine. Not shown: a standby on another host, a real network,
or a managed service. `commitIn` is the Node shape of Python's `commit_in` (psql keeps no caller transaction, so the caller's
SQL runs in the SAME psql transaction as the commit).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
from typing import Any

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import psycopg  # noqa: E402
from pg_cluster import Cluster, make_standby, promote  # type: ignore[import-not-found]  # noqa: E402
from test_ledger_postgres import Proxy  # type: ignore[import-not-found]  # noqa: E402
from test_node_postgres import DRIVER, codes, node  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.envelope import Refused  # noqa: E402
from cns_interop.ledger_postgres import PostgresLedger  # noqa: E402

S = "uai:ed25519:" + "d" * 64
FAR = 10**13


@pytest.fixture(scope="module")
def cluster():
    c = Cluster().start()
    c.wait_ready()
    yield c
    c.cleanup()


def run(dsn: str, tbl: str, ops: list, *, opts: Any = None) -> list:  # type: ignore[type-arg]
    """node_pg_driver.mjs with PostgresLedger options (`opts`) passed through."""
    job = {"dsn_env": "LEDGER_DSN", "table": tbl, "ops": ops, **({"opts": opts} if opts else {})}
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LEDGER_DSN": dsn}
    done = subprocess.run([node(), str(DRIVER)], input=json.dumps(job), capture_output=True, text=True, env=env, timeout=180)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)  # type: ignore[no-any-return]


def table() -> str:
    return "t_" + uuid.uuid4().hex[:12]


def py_code(fn: Any, *a: Any, **k: Any) -> str:
    try:
        fn(*a, **k)
    except Refused as exc:
        return exc.code  # type: ignore[no-any-return]
    return "ok"


def test_node_refuses_to_write_when_quorum_is_required_and_the_server_has_no_synchronous_standby(cluster):
    t = table()
    py_reason = ""
    try:
        PostgresLedger(cluster.dsn, table=t, require_sync_replication=True)
    except Refused as exc:
        py_code_, py_reason = exc.code, exc.reason
        assert py_code_ == "unavailable"
    r = run(cluster.dsn, t, [["reserve", S, "m", FAR, 30000]], opts={"requireSyncReplication": True})
    assert codes(r) == ["unavailable"] and r[0]["reason"] == py_reason and "quorum-durable" in r[0]["reason"]
    # the flag is opt-in: without it a single node is the primary's guarantee, as in Python, and nothing was written above
    assert codes(run(cluster.dsn, t, [["reserve", S, "m", FAR, 30000]])) == ["ok"]


def test_commit_in_spends_with_the_callers_sql_in_one_transaction_and_refuses_a_lost_lease_without_running_it(cluster):
    t = table()
    led = PostgresLedger(cluster.dsn, table=t)
    with psycopg.connect(cluster.dsn, autocommit=True) as db:
        db.execute(f"CREATE TABLE {t}_effects (key text PRIMARY KEY, n int)")
    sql = f"INSERT INTO {t}_effects VALUES (:'k', :'n'::int)"
    r = run(cluster.dsn, t, [["reserve", S, "job", FAR, 30000], ["commit_in", 0, sql, {"k": "job-1", "n": "1"}], ["spend", S, "job", FAR]])
    assert codes(r) == ["ok", "ok", "replayed"]
    with psycopg.connect(cluster.dsn, autocommit=True) as db:
        assert db.execute(f"SELECT n FROM {t}_effects WHERE key = 'job-1'").fetchone()[0] == 1
    # a stranger's lease: nothing of the caller's runs, and the answer is lease_lost
    assert py_code(led.reserve, S, "held", FAR, lease_ms=30000) == "ok"
    stale = run(cluster.dsn, t, [["reserve", S, "taken", FAR, 500], ["sleep", 900], ["reserve", S, "taken", FAR, 30000],
                                 ["commit_in", 0, sql, {"k": "stale", "n": "1"}]])
    assert codes(stale) == ["ok", "ok", "ok", "lease_lost"]
    with psycopg.connect(cluster.dsn, autocommit=True) as db:
        assert db.execute(f"SELECT count(*) FROM {t}_effects WHERE key = 'stale'").fetchone()[0] == 0
    # a failing business statement rolls the spend back too: the lease lapses and the message is redeemable again
    bad = run(cluster.dsn, t, [["reserve", S, "boom", FAR, 800], ["commit_in", 0, "INSERT INTO no_such_table VALUES (1)", {}],
                               ["spend", S, "boom", FAR], ["sleep", 1100], ["spend", S, "boom", FAR]])
    assert codes(bad) == ["ok", "unavailable", "replayed", "ok", "ok"]
    # reserved names and odd names are caller errors
    odd = run(cluster.dsn, t, [["reserve", S, "x", FAR, 30000], ["commit_in", 0, "SELECT 1", {"cns_won": "1"}],
                               ["commit_in", 0, "SELECT 1", {"a b": "1"}]])
    assert codes(odd) == ["ok", "caller_error", "caller_error"]


def test_a_synchronous_standby_success_path_a_partition_and_a_failover_with_the_node_ledger():
    primary = Cluster(hba_replication=True).start()
    standby = None
    try:
        primary.wait_ready()
        repl = Proxy(primary.port)
        standby = make_standby(primary, repl.port).start()
        standby.wait_ready()
        with psycopg.connect(primary.dsn, autocommit=True) as db:
            db.execute("ALTER SYSTEM SET synchronous_standby_names = 'standby1'")
            db.execute("SELECT pg_reload_conf()")
            for _ in range(50):
                if db.execute("SELECT count(*) FROM pg_stat_replication WHERE sync_state = 'sync'").fetchone()[0] == 1:
                    break
                time.sleep(0.2)
            else:
                raise AssertionError("the standby never became synchronous")
        t = table()
        quorum = {"requireSyncReplication": True, "statementTimeoutMs": 2000}
        before = run(primary.dsn, t, [["reserve", S, "before", FAR, 600000]], opts=quorum)       # confirmed by the standby
        assert codes(before) == ["ok"]
        with psycopg.connect(standby.dsn, autocommit=True) as sb:
            assert sb.execute(f"SELECT count(*) FROM {t} WHERE id = 'before'").fetchone()[0] == 1
        repl.block.set()                                                                          # the standby is partitioned away
        started = time.time()
        during = run(primary.dsn, t, [["reserve", S, "during", FAR, 600000]], opts=quorum)
        assert codes(during) == ["unavailable"] and time.time() - started < 20
        with psycopg.connect(primary.dsn, autocommit=True) as db:                                  # the primary DID commit it locally
            for _ in range(30):      # once the killed call's wait is cancelled from outside (Python cancels from inside, so no wait)
                if db.execute(f"SELECT count(*) FROM {t} WHERE id = 'during'").fetchone()[0] == 1:
                    break
                time.sleep(0.2)
            else:
                raise AssertionError("the primary never committed the unconfirmed write locally")
        assert codes(run(primary.dsn, t, [["reserve", S, "someone-else", FAR, 1000]], opts={**quorum, "statementTimeoutMs": 1500})) == ["unavailable"]
        primary.kill()
        promote(standby)
        repl.block.clear()
        survivor = run(standby.dsn, t, [["reserve", S, "before", FAR, 1000], ["reserve", S, "during", FAR, 30000]])
        assert codes(survivor) == ["replayed", "ok"]                      # the acknowledged one survived; the unacknowledged can be granted
    finally:
        if standby is not None:
            standby.cleanup()
        primary.cleanup()


def test_act_mjs_require_sync_replication_refuses_at_start_on_a_single_node_as_act_py_does(cluster, tmp_path):
    from test_act_policy import grants_file  # type: ignore[import-not-found]
    from test_node_policy_version import args_for, receiver  # type: ignore[import-not-found]
    from test_session import act_job  # type: ignore[import-not-found]
    g = grants_file(tmp_path / "grants.json")
    outs = {}
    for impl in ("py", "node"):
        args = args_for(tmp_path, "q_" + uuid.uuid4().hex[:8], g, "--require-sync-replication")
        rc, out, _ = receiver(impl, cluster.dsn, args, act_job())
        outs[impl] = (rc, out["refused"]["code"], "quorum-durable" in out["refused"]["reason"])
    assert outs == {"py": (2, "unavailable", True), "node": (2, "unavailable", True)}
    # and the flag belongs to the postgres backend in both
    for impl in ("py", "node"):
        rc, out, _ = receiver(impl, cluster.dsn, ["--acting-for", "uai:ed25519:" + "1" * 64, "--capability", "income-screen",
                                                  "--capability-version", "1", "--trust", "uai:ed25519:" + "2" * 64,
                                                  "--ledger-backend", "sqlite", "--ledger", str(tmp_path / f"{impl}.db"),
                                                  "--decision-only", "--require-sync-replication"], {})
        assert (rc, out["refused"]["code"]) == (2, "config"), impl


def test_a_network_partition_between_node_and_the_database_is_unavailable_in_bounded_time_and_never_grants(cluster):
    """The Node twin of test_ledger_postgres's partition test: a TCP proxy drops the bytes; the call fails closed within the
    child bound (psql has no tcp_user_timeout, so the bound is the whole-call kill) and whatever happened to the lost request,
    no other host is granted the message while it is held. One machine; a proxy, not a real network."""
    proxy = Proxy(cluster.port)
    t = table()
    via = cluster.dsn_via(proxy.port)
    opts = {"statementTimeoutMs": 1500, "connectTimeoutS": 2}
    assert codes(run(via, t, [["reserve", S, "before", FAR, 30000]], opts=opts)) == ["ok"]
    proxy.block.set()
    started = time.time()
    assert codes(run(via, t, [["reserve", S, "during", FAR, 30000]], opts=opts)) == ["unavailable"]
    assert time.time() - started < 15
    proxy.block.clear()
    state = py_code(PostgresLedger(cluster.dsn, table=t).reserve, S, "during", FAR, lease_ms=1000)
    assert state in ("replayed", "ok")                       # held by the lost request, or it never arrived
