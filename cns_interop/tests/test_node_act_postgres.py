"""interop/node/act.mjs on the SHARED backend: the Node receiver and the Python receiver against one real PostgreSQL server.

Shown: the Node receiver spends decisions and permits in the same tables as act.py (rows inspected); a decision redeemed by
either language is refused as a replay by the other, in both directions; an unreachable or unconfigured database is a
refusal with no fallback to a file; the backend options are checked; the DSN never appears in output. Each receiver keeps its
own grant store and audit file, as on two hosts. Not shown: two machines (separate processes stand in for hosts).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import psycopg  # noqa: E402
from pg_cluster import Cluster  # type: ignore[import-not-found]  # noqa: E402
from test_act_policy import grants_file  # type: ignore[import-not-found]  # noqa: E402
from test_session import ACT_PY, DEC, REQ, act_job  # type: ignore[import-not-found]  # noqa: E402

ROOT = ACT_PY.parents[1]
ACT_MJS = ROOT / "interop" / "node" / "act.mjs"


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


def prefix() -> str:
    return "t_" + uuid.uuid4().hex[:10]


def act(impl: str, home: Path, job, pre: str, dsn: str, *, extra=(), backend=("--ledger-backend", "postgres")):
    """One receiver run. Each language gets its own directory for grants, grant store and audit, as a separate host would."""
    home.mkdir(exist_ok=True)
    grants_file(home / "grants.json")
    common = ["--acting-for", REQ.agent, "--capability", "income-screen", "--capability-version", "1", "--trust", DEC.agent,
              *backend, "--ledger-dsn-env", "RECEIVER_DSN", "--ledger-prefix", pre, "--grants", str(home / "grants.json"),
              "--grant-store", str(home / "grants.db"), "--action", "release-funds", "--audit", str(home / "audit.jsonl"), *extra]
    cmd = [sys.executable, str(ACT_PY), *common] if impl == "py" else [node(), str(ACT_MJS), *common]
    env = {"PYTHONPATH": str(ROOT), "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "RECEIVER_DSN": dsn}
    return subprocess.run(cmd, input=json.dumps(job), capture_output=True, text=True, env=env, timeout=90)


def outcome(done) -> str:
    out = json.loads(done.stdout)
    return ("refused:" + out["refused"]["code"]) if "refused" in out else ("permitted" if out["permitted"] else "not-permitted")


def test_the_node_receiver_spends_in_the_shared_tables(cluster, tmp_path):
    pre = prefix()
    done = act("node", tmp_path / "node", act_job(), pre, cluster.dsn)
    assert done.returncode == 0, done.stderr
    assert outcome(done) == "permitted" and "permit" in json.loads(done.stdout)
    with psycopg.connect(cluster.dsn) as db:
        assert db.execute(f"select count(*) from {pre}_decisions").fetchone()[0] == 1
        assert db.execute(f"select count(*) from {pre}_permits").fetchone()[0] == 1
    assert not list((tmp_path / "node").glob("*.db.permits"))
    assert cluster.dsn not in done.stdout and cluster.dsn not in done.stderr


@pytest.mark.parametrize("first,second", [("py", "node"), ("node", "py"), ("node", "node")])
def test_a_decision_redeemed_by_one_receiver_is_a_replay_for_the_other(cluster, tmp_path, first, second):
    job, pre = act_job(), prefix()
    assert outcome(act(first, tmp_path / "a", job, pre, cluster.dsn)) == "permitted"
    assert outcome(act(second, tmp_path / "b", job, pre, cluster.dsn)) == "refused:replayed"


def test_an_unreachable_database_is_refused_and_nothing_is_written_locally(cluster, tmp_path):
    down = Cluster()  # never started: nothing listens on its port
    try:
        done = act("node", tmp_path / "n", act_job(), prefix(), down.dsn)
        assert done.returncode == 2 and outcome(done) == "refused:unavailable"
        assert not list((tmp_path / "n").glob("*.db.permits")) and not (tmp_path / "n" / "spent.db").exists()
    finally:
        shutil.rmtree(down.dir, ignore_errors=True)
        shutil.rmtree(down.sock, ignore_errors=True)


def test_no_dsn_or_a_bad_option_combination_refuses_and_never_falls_back_to_a_file(cluster, tmp_path):
    missing = act("node", tmp_path / "m", act_job(), prefix(), "")
    assert missing.returncode == 2 and "no fallback" in json.loads(missing.stdout)["refused"]["reason"]
    mixed = act("node", tmp_path / "x", act_job(), prefix(), cluster.dsn, extra=["--ledger", str(tmp_path / "spent.db")])
    assert mixed.returncode == 2 and outcome(mixed) == "refused:config"
    assert not (tmp_path / "spent.db").exists()
    sqlite_with_dsn = act("node", tmp_path / "s", act_job(), prefix(), cluster.dsn, backend=("--ledger", str(tmp_path / "s.db")))
    assert sqlite_with_dsn.returncode == 2 and outcome(sqlite_with_dsn) == "refused:config"
    unknown = act("node", tmp_path / "u", act_job(), prefix(), cluster.dsn, backend=("--ledger-backend", "redis"))
    assert unknown.returncode == 2 and outcome(unknown) == "refused:config"
