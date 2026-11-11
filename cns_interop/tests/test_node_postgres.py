"""The Node PostgresLedger (interop/node/pg.mjs) against a REAL PostgreSQL server that the tests start themselves.

Shown: the ledger rules (spend, replay, reserve, commit, release, lease_lost), lease takeover judged by the SERVER's clock, a
growing fence, Python and Node sharing ONE table in both directions, exactly one winner when Node and Python processes race
for the same message, an unreachable database refused as 'unavailable', a connection option it cannot map refused, and the
connection string never on a command line. Not shown: a multi-HOST deployment (one machine; separate processes stand in for
hosts), or a managed service.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from pg_cluster import Cluster  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.envelope import Refused  # noqa: E402
from cns_interop.ledger_postgres import PostgresLedger  # noqa: E402

HERE = Path(__file__).parent
DRIVER = HERE / "node_pg_driver.mjs"
S = "uai:ed25519:" + "c" * 64
FAR = 10**13


def node() -> str:
    found = shutil.which("node")
    assert found, "Node.js is not installed (need node 22 or later)"
    return found


@pytest.fixture(scope="module")
def cluster():
    c = Cluster().start()
    c.wait_ready()
    yield c
    c.cleanup()


def table() -> str:
    return "t_" + uuid.uuid4().hex[:12]


def run(dsn: str, tbl: str, ops: list, *, psql: str | None = None, allow_caller_time: bool = False) -> list:
    job = {"dsn_env": "LEDGER_DSN", "table": tbl, "ops": ops, **({"psql": psql} if psql else {}),
           **({"allow_caller_time": True} if allow_caller_time else {})}
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LEDGER_DSN": dsn}
    done = subprocess.run([node(), str(DRIVER)], input=json.dumps(job), capture_output=True, text=True, env=env, timeout=120)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def codes(results: list) -> list:
    return [r.get("code", "ok") for r in results]


def py_code(fn, *a, **k) -> str:
    try:
        fn(*a, **k)
    except Refused as exc:
        return exc.code
    return "ok"


def test_node_spends_once_and_refuses_the_replay(cluster):
    assert codes(run(cluster.dsn, table(), [["spend", S, "m1", FAR], ["spend", S, "m1", FAR], ["spend", S, "m2", None]])) == \
        ["ok", "replayed", "ok"]


def test_node_reserve_commit_release_and_lease_lost_follow_the_python_rules(cluster):
    r = run(cluster.dsn, table(), [
        ["reserve", S, "a", FAR, 30000],   # 0: granted
        ["reserve", S, "a", FAR, 30000],   # 1: held by 0
        ["release", 0, True],              # 2: a stranger's token cannot release it
        ["commit", 0],                     # 3: the holder commits
        ["spend", S, "a", FAR],            # 4: committed: replayed
        ["reserve", S, "b", FAR, 30000],   # 5
        ["release", 5],                    # 6: the holder releases
        ["spend", S, "b", FAR],            # 7: released, so it can be spent
    ])
    assert codes(r) == ["ok", "replayed", "lease_lost", "ok", "replayed", "ok", "ok", "ok"]


def test_a_lapsed_lease_is_taken_over_on_the_servers_clock_and_the_old_holder_loses_it(cluster):
    r = run(cluster.dsn, table(), [
        ["reserve", S, "x", FAR, 1500],    # 0
        ["sleep", 2000],                   # the lease lapses on the SERVER's clock
        ["reserve", S, "x", FAR, 30000],   # 2: taken over
        ["commit", 0],                     # 3: the first holder's commit is refused
        ["commit", 2],                     # 4: the new holder's commit stands
    ])
    assert codes(r) == ["ok", "ok", "ok", "lease_lost", "ok"]
    assert r[2]["ok"]["fence"] > r[0]["ok"]["fence"]                        # the fence only grows


def test_python_and_node_share_one_table_in_both_directions(cluster):
    t = table()
    py = PostgresLedger(cluster.dsn, table=t)
    py.spend(S, "from-python", FAR)
    assert codes(run(cluster.dsn, t, [["spend", S, "from-python", FAR], ["spend", S, "from-node", FAR],
                                      ["reserve", S, "held-by-node", FAR, 30000]])) == ["replayed", "ok", "ok"]
    assert py_code(py.spend, S, "from-node", FAR) == "replayed"
    assert py_code(py.reserve, S, "held-by-node", FAR, lease_ms=30000) == "replayed"
    res = py.reserve(S, "held-by-python", FAR, lease_ms=30000)
    assert codes(run(cluster.dsn, t, [["reserve", S, "held-by-python", FAR, 30000]])) == ["replayed"]
    py.commit(res)
    assert codes(run(cluster.dsn, t, [["spend", S, "held-by-python", FAR]])) == ["replayed"]


def test_exactly_one_winner_when_node_and_python_processes_race_for_one_message(cluster):
    t = table()
    PostgresLedger(cluster.dsn, table=t)                                   # create the table once, before the race
    script = ("import sys, json; sys.path.insert(0, %r)\n"
              "from cns_interop.ledger_postgres import PostgresLedger\nfrom cns_interop.envelope import Refused\n"
              "try:\n    PostgresLedger(%r, table=%r).reserve(%r, 'race', %d, lease_ms=30000); print('ok')\n"
              "except Refused as e:\n    print(e.code)\n") % (str(HERE.parents[1]), cluster.dsn, t, S, FAR)

    def py_one(_):
        return subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=120).stdout.strip()

    def node_one(_):
        return codes(run(cluster.dsn, t, [["reserve", S, "race", FAR, 30000]]))[0]

    with ThreadPoolExecutor(max_workers=16) as pool:
        got = list(pool.map(node_one, range(8))) + list(pool.map(py_one, range(8)))
    assert got.count("ok") == 1 and got.count("replayed") == 15, got


def test_an_unreachable_database_is_refused_as_unavailable_never_as_granted(cluster):
    dead = cluster.dsn_via(1)
    assert run(dead, table(), [])[0]["code"] == "unavailable"


def test_a_connection_option_it_cannot_map_is_refused_not_dropped(cluster):
    r = run(cluster.dsn + " krbsrvname=x", table(), [])
    assert r[0]["code"] == "config" and "krbsrvname" in r[0]["reason"]


def test_the_connection_string_and_password_never_reach_a_command_line(cluster, tmp_path):
    log = tmp_path / "argv.log"
    shim = tmp_path / "psql"
    real = shutil.which("psql")
    assert real, "the psql client is not installed (postgresql-client)"
    shim.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" >> {log}\nexec {real} "$@"\n')
    shim.chmod(0o755)
    secret = "pw-" + uuid.uuid4().hex
    dsn = cluster.dsn + f" password={secret}"                               # trust auth: the password is carried, not checked
    assert codes(run(dsn, table(), [["spend", S, "p", FAR]], psql=str(shim))) == ["ok"]
    argv = log.read_text()
    assert "--version" in argv and secret not in argv and "dbname=" not in argv and "host=" not in argv


def test_the_server_clock_is_what_node_reads(cluster):
    before = int(time.time() * 1000)
    got = run(cluster.dsn, table(), [["server_now"]])[0]["ok"]
    assert abs(got - before) < 10_000
