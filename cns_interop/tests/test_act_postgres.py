"""interop/act.py on the DISTRIBUTED backend: the real action runner, as its own process, against a real PostgreSQL server.

Shown: decisions and permits are spent in PostgreSQL (rows are inspected), a second process on the same database is refused as
a replay (a separate process stands in for a second host; this is ONE machine), a restarted server remembers, an unreachable or
unconfigured database is a refusal with no fallback to a file, the production profile refuses the file backend, the DSN never
appears on a command line or in output, and `--diagnostics` names the backend in force. Not shown: a multi-host deployment.
"""

from __future__ import annotations

import json
import os
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

ROOT = str(ACT_PY.parents[1])


@pytest.fixture(scope="module")
def cluster():
    c = Cluster().start()
    c.wait_ready()
    yield c
    c.cleanup()


def act(tmp, cluster, job, prefix, *, extra=(), env_extra=None, dsn=None, diagnostics=False):
    args = [sys.executable, str(ACT_PY), "--acting-for", REQ.agent, "--capability", "income-screen", "--capability-version", "1",
            "--trust", DEC.agent, "--ledger-backend", "postgres", "--ledger-dsn-env", "RECEIVER_DSN", "--ledger-prefix", prefix,
            "--grants", str(grants_file(tmp / "grants.json")), "--action", "release-funds", *extra]
    if "--policy-backend" not in extra:
        args += ["--grant-store", str(tmp / "grants.db"), "--audit", str(tmp / "audit.jsonl")]
    if diagnostics:
        args.append("--diagnostics")
    env = {"PYTHONPATH": ROOT, "PATH": "/usr/bin:/bin", "RECEIVER_DSN": cluster.dsn if dsn is None else dsn, **(env_extra or {})}
    done = subprocess.run(args, input=json.dumps(job), capture_output=True, text=True, env=env, timeout=90)
    return done


def prefix() -> str:
    return "t_" + uuid.uuid4().hex[:10]


def test_the_action_runner_spends_decisions_and_permits_in_postgres_and_a_second_process_is_refused(cluster, tmp_path):
    job, pre = act_job(), prefix()
    first = act(tmp_path, cluster, job, pre)
    assert first.returncode == 0, first.stderr
    assert json.loads(first.stdout)["permitted"] is True
    with psycopg.connect(cluster.dsn) as db:
        decisions = db.execute(f"select count(*) from {pre}_decisions").fetchone()[0]
        permits = db.execute(f"select count(*) from {pre}_permits").fetchone()[0]
    assert (decisions, permits) == (1, 1)                                  # the shared tables, not a local file
    assert not list(tmp_path.glob("*.jsonl.permits")) and not (tmp_path / "spent.jsonl").exists()
    again = act(tmp_path, cluster, job, pre)                               # a new process, as a second host would be
    assert json.loads(again.stdout)["refused"]["code"] == "replayed"


def test_a_restarted_server_still_refuses_the_replay(cluster, tmp_path):
    job, pre = act_job(), prefix()
    assert json.loads(act(tmp_path, cluster, job, pre).stdout)["permitted"] is True
    cluster.stop()
    down = act(tmp_path, cluster, job, pre)
    assert down.returncode == 2 and json.loads(down.stdout)["refused"]["code"] == "unavailable"   # fails closed
    cluster.start()
    cluster.wait_ready()
    assert json.loads(act(tmp_path, cluster, job, pre).stdout)["refused"]["code"] == "replayed"


def test_no_dsn_or_a_bad_option_combination_refuses_and_never_falls_back_to_a_file(cluster, tmp_path):
    job = act_job()
    missing = act(tmp_path, cluster, job, prefix(), dsn="")
    assert missing.returncode == 2 and "no fallback" in json.loads(missing.stdout)["refused"]["reason"]
    mixed = act(tmp_path, cluster, job, prefix(), extra=["--ledger", str(tmp_path / "spent.jsonl")])
    assert mixed.returncode == 2 and json.loads(mixed.stdout)["refused"]["code"] == "config"
    assert not (tmp_path / "spent.jsonl").exists()


def test_the_production_profile_refuses_the_single_host_file_backend(tmp_path):
    args = [sys.executable, str(ACT_PY), "--acting-for", REQ.agent, "--capability", "income-screen", "--capability-version", "1",
            "--trust", DEC.agent, "--ledger", str(tmp_path / "spent.jsonl"), "--decision-only"]
    env = {"PYTHONPATH": ROOT, "PATH": "/usr/bin:/bin", "UAI_PROFILE": "production", "UAI_CRYPTO_BACKEND": "cryptography"}
    done = subprocess.run(args, input="{}", capture_output=True, text=True, env=env, timeout=60)
    assert done.returncode == 2 and "production profile" in json.loads(done.stdout)["refused"]["reason"]


def test_diagnostics_name_the_backend_in_force_connect_for_real_and_never_print_the_dsn(cluster, tmp_path):
    done = act(tmp_path, cluster, {}, prefix(), diagnostics=True, extra=["--policy-backend", "postgres"],
               env_extra={"UAI_PROFILE": "production", "UAI_CRYPTO_BACKEND": "cryptography"})
    assert done.returncode == 0, done.stdout + done.stderr
    d = json.loads(done.stdout)
    assert d["ledger_backend"] == "postgres" and d["decision_ledger"] == "PostgresLedger" and d["permit_ledger"] == "PostgresLedger"
    assert d["policy_backend"] == "postgres"
    assert d["crypto"]["backend"] == "cryptography" and d["crypto"]["profile"] == "production" and d["crypto"]["frozen"] is True
    assert cluster.dsn not in done.stdout and str(cluster.port) not in done.stdout
    down = Cluster()  # never started: nothing listens on its port
    refused = act(tmp_path, cluster, {}, prefix(), diagnostics=True, dsn=down.dsn)
    assert refused.returncode == 2 and json.loads(refused.stdout)["refused"]["code"] == "unavailable"
    os.system(f"rm -rf {down.dir} {down.sock}")
