"""RACE-02 I-07a (R2-C-02, R2-C-03): clock validation is mandatory in the production profile, in Python and in Node, and the
Node receiver enforces the production profile exactly as act.py does, before it creates any state.

Shown against a real PostgreSQL server: act.py under UAI_PROFILE=production refuses to start (`config`, exit 2) without
--max-clock-skew-ms and acts with it; act.mjs under the same profile refuses the SQLite ledger, host-local withdrawals and
audit, the unimplemented --policy-backend postgres, and a missing clock tolerance, each as `config`, exit 2, leaving no grant
store, ledger or audit file behind; a clock-skew refusal in Node now precedes the grant store's creation (it used to create
grants.db first); and a trusted clock is re-read for every decision, so a database that drifts away after start-up is caught
at `authorize` in both languages (library level; interop/node/clock.test.mjs has the Node unit). The development opt-out is
the default profile (UAI_PROFILE unset) without the flag; every other test that runs the receivers without --max-clock-skew-ms
uses it.
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
import pg_testclock  # type: ignore[import-not-found]  # noqa: E402
from pg_cluster import Cluster  # type: ignore[import-not-found]  # noqa: E402
from test_act_policy import grants_file  # type: ignore[import-not-found]  # noqa: E402
from test_clock_trust import ACT_MJS, HOUR, ROOT, shims  # type: ignore[import-not-found]  # noqa: E402
from test_session import ACT_PY, DEC, GUARD_CAP, REQ, act_job, pair, run  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.decision import RemoteDecisionGuard  # noqa: E402
from cns_interop.envelope import Refused, now_ms  # noqa: E402
from cns_interop.ledger import MemoryLedger  # noqa: E402
from cns_interop.ledger_postgres import PostgresLedger, TrustedClock  # noqa: E402
from cns_interop.trust import TrustPolicy  # noqa: E402

PRODUCTION = {"UAI_PROFILE": "production", "UAI_CRYPTO_BACKEND": "cryptography"}
BASE = ["--acting-for", REQ.agent, "--capability", "income-screen", "--capability-version", "1", "--trust", DEC.agent]


@pytest.fixture(scope="module")
def cluster():
    c = Cluster().start()
    c.wait_ready()
    pg_testclock.install(c.dsn)
    yield c
    c.cleanup()


@pytest.fixture(autouse=True)
def real_db_clock(cluster):
    yield
    pg_testclock.set_clock(cluster.dsn)


def prefix() -> str:
    return "p_" + uuid.uuid4().hex[:10]


def run_receiver(impl: str, home: Path, args: list, job, dsn: str, *, env_extra=None, shift_ms: int = 0):
    """One real receiver process. Returns (exit status, the JSON it printed, stderr)."""
    home.mkdir(parents=True, exist_ok=True)
    sh = shims(home)
    node = shutil.which("node")
    assert node, "Node.js is not installed (need node 22 or later)"
    cmd = ([sys.executable, str(ACT_PY), *args] if impl == "py"
           else [node, "--import", (sh / "shift.mjs").as_uri(), str(ACT_MJS), *args])
    env = {"PYTHONPATH": f"{sh}{os.pathsep}{ROOT}", "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home),
           "RECEIVER_DSN": dsn, "UAI_TEST_CLOCK_SHIFT_MS": str(shift_ms), "PYTHONDONTWRITEBYTECODE": "1", **(env_extra or {})}
    done = subprocess.run(cmd, input=json.dumps(job), capture_output=True, text=True, env=env, timeout=120)
    assert done.stdout, done.stderr
    return done.returncode, json.loads(done.stdout.splitlines()[-1]), done.stderr


def refused(result) -> tuple:
    rc, out, _ = result
    return rc, out.get("refused", {}).get("code")


def shared_policy_args(home: Path, pre: str) -> list:
    home.mkdir(parents=True, exist_ok=True)
    grants_file(home / "grants.json")
    return [*BASE, "--ledger-backend", "postgres", "--ledger-dsn-env", "RECEIVER_DSN", "--ledger-prefix", pre,
            "--policy-backend", "postgres", "--grants", str(home / "grants.json"), "--action", "release-funds"]


def publish(cluster, home: Path, pre: str) -> None:
    rc, out, err = run_receiver("py", home, [*shared_policy_args(home, pre), "--publish-policy", "1", "--max-clock-skew-ms", "5000"],
                                {}, cluster.dsn, env_extra=PRODUCTION)
    assert rc == 0 and out["published"]["version"] == 1, (out, err)


# ------------------------------------------------------------------------------------------------------------- Python

def test_python_production_requires_the_clock_check_and_acts_with_it(cluster, tmp_path):
    pre = prefix()
    publish(cluster, tmp_path, pre)
    without = run_receiver("py", tmp_path, shared_policy_args(tmp_path, pre), act_job(), cluster.dsn, env_extra=PRODUCTION)
    assert refused(without) == (2, "config") and "--max-clock-skew-ms" in without[1]["refused"]["reason"]
    with_flag = run_receiver("py", tmp_path, [*shared_policy_args(tmp_path, pre), "--max-clock-skew-ms", "5000"], act_job(),
                             cluster.dsn, env_extra=PRODUCTION)
    assert with_flag[0] == 0 and with_flag[1]["permitted"] is True, with_flag
    skewed = run_receiver("py", tmp_path, [*shared_policy_args(tmp_path, pre), "--max-clock-skew-ms", "5000"], act_job(),
                          cluster.dsn, env_extra=PRODUCTION, shift_ms=-HOUR)
    assert refused(skewed) == (2, "clock_skew")
    too_wide = run_receiver("py", tmp_path, [*shared_policy_args(tmp_path, pre), "--max-clock-skew-ms", "120000"], act_job(),
                            cluster.dsn, env_extra=PRODUCTION)
    assert refused(too_wide) == (2, "config") and "keep_ms" in too_wide[1]["refused"]["reason"]


def test_python_default_profile_keeps_the_opt_out_and_diagnostics_name_the_clock_source(cluster, tmp_path):
    pre = prefix()
    grants_file(tmp_path / "grants.json")
    local = [*BASE, "--ledger-backend", "postgres", "--ledger-dsn-env", "RECEIVER_DSN", "--ledger-prefix", pre, "--grants",
             str(tmp_path / "grants.json"), "--grant-store", str(tmp_path / "grants.db"), "--action", "release-funds",
             "--audit", str(tmp_path / "audit.jsonl")]
    rc, out, _ = run_receiver("py", tmp_path, local, act_job(), cluster.dsn)          # UAI_PROFILE unset: the host's clock
    assert rc == 0 and out["permitted"] is True
    rc, out, _ = run_receiver("py", tmp_path, [*local, "--diagnostics"], {}, cluster.dsn)
    assert rc == 0 and out["clock"] == {"source": "host"}
    rc, out, _ = run_receiver("py", tmp_path, [*local, "--diagnostics", "--max-clock-skew-ms", "7000"], {}, cluster.dsn)
    assert rc == 0 and out["clock"] == {"source": "database", "max_skew_ms": 7000}
    publish(cluster, tmp_path / "shared", pre)
    rc, out, _ = run_receiver("py", tmp_path / "shared", [*shared_policy_args(tmp_path / "shared", pre), "--diagnostics"], {},
                              cluster.dsn, env_extra=PRODUCTION)                        # diagnostics acts on nothing: it runs, and says so
    assert rc == 0 and out["clock"] == {"source": "host"} and out["crypto"]["profile"] == "production"


# --------------------------------------------------------------------------------------------------------------- Node

def node_local_args(home: Path, backend: list) -> list:
    home.mkdir(parents=True, exist_ok=True)
    grants_file(home / "grants.json")
    return [*BASE, *backend, "--grants", str(home / "grants.json"), "--grant-store", str(home / "grants.db"),
            "--action", "release-funds", "--audit", str(home / "audit.jsonl")]


def no_state(home: Path) -> bool:
    return not any((home / f).exists() for f in ("grants.db", "spent.db", "spent.db.permits"))


def test_node_enforces_the_production_profile_as_python_does_and_creates_no_state_before_the_checks_pass(cluster, tmp_path):
    pg = ["--ledger-backend", "postgres", "--ledger-dsn-env", "RECEIVER_DSN", "--ledger-prefix", prefix()]
    sqlite = run_receiver("node", tmp_path / "a", node_local_args(tmp_path / "a", ["--ledger", str(tmp_path / "a" / "spent.db")]),
                          act_job(), cluster.dsn, env_extra=PRODUCTION)
    assert refused(sqlite) == (2, "config") and "single-host ledger" in sqlite[1]["refused"]["reason"] and no_state(tmp_path / "a")
    local_policy = run_receiver("node", tmp_path / "b", node_local_args(tmp_path / "b", pg), act_job(), cluster.dsn, env_extra=PRODUCTION)
    assert refused(local_policy) == (2, "config") and "host-local" in local_policy[1]["refused"]["reason"] and no_state(tmp_path / "b")
    pg_policy = run_receiver("node", tmp_path / "c", [*node_local_args(tmp_path / "c", pg), "--policy-backend", "postgres"], act_job(),
                             cluster.dsn, env_extra=PRODUCTION)
    assert refused(pg_policy) == (2, "config") and "do not give --grant-store or --audit" in pg_policy[1]["refused"]["reason"] and no_state(tmp_path / "c")
    no_clock = run_receiver("node", tmp_path / "d", [*BASE, *pg, "--decision-only"], act_job(), cluster.dsn, env_extra=PRODUCTION)
    assert refused(no_clock) == (2, "config") and "--max-clock-skew-ms" in no_clock[1]["refused"]["reason"]
    ok = run_receiver("node", tmp_path / "e", [*BASE, *pg, "--decision-only", "--max-clock-skew-ms", "5000"], act_job(), cluster.dsn,
                      env_extra=PRODUCTION)
    assert ok[0] == 0 and ok[1] == {"permitted": True}, ok
    skewed = run_receiver("node", tmp_path / "f", [*BASE, *pg, "--decision-only", "--max-clock-skew-ms", "5000"], act_job(), cluster.dsn,
                          env_extra=PRODUCTION, shift_ms=-HOUR)
    assert refused(skewed) == (2, "clock_skew")
    # the same refusals in Python, word for word where both can reach them
    py_sqlite = run_receiver("py", tmp_path / "g", [*node_local_args(tmp_path / "g", ["--ledger-backend", "sqlite", "--ledger",
                             str(tmp_path / "g" / "spent.db")]), "--max-clock-skew-ms", "5000"], act_job(), cluster.dsn, env_extra=PRODUCTION)
    assert refused(py_sqlite) == (2, "config") and "host-local" in py_sqlite[1]["refused"]["reason"]


def test_a_node_clock_skew_refusal_leaves_no_grant_store_or_permit_ledger_behind(cluster, tmp_path):
    """R2-C-05: act.mjs created grants.db before it checked the clock. The check now comes first, in both profiles."""
    home = tmp_path / "skew"
    args = [*node_local_args(home, ["--ledger-backend", "postgres", "--ledger-dsn-env", "RECEIVER_DSN", "--ledger-prefix", prefix()]),
            "--max-clock-skew-ms", "5000"]
    assert refused(run_receiver("node", home, args, act_job(), cluster.dsn, shift_ms=-HOUR)) == (2, "clock_skew")
    assert no_state(home), sorted(p.name for p in home.iterdir())


def test_node_without_the_profile_keeps_the_sqlite_and_local_opt_out(cluster, tmp_path):
    home = tmp_path / "dev"
    rc, out, _ = run_receiver("node", home, node_local_args(home, ["--ledger", str(home / "spent.db")]), act_job(), cluster.dsn)
    assert rc == 0 and out["permitted"] is True
    bad = run_receiver("node", home, [*node_local_args(home, ["--ledger", str(home / "spent.db")]), "--policy-backend", "redis"], act_job(), cluster.dsn)
    assert refused(bad) == (2, "config")


# ------------------------------------------------------------------------------------------------- per-decision sync

def test_a_trusted_clock_is_re_read_for_every_decision_so_a_database_that_drifts_after_startup_is_caught_at_authorize(cluster):
    led = PostgresLedger(cluster.dsn, table="t_" + uuid.uuid4().hex[:12])
    clock = TrustedClock(led, 5_000, keep_ms=led.keep_ms)
    clock.sync()                                                             # start-up: the clocks agree
    dec, req, _ = pair(clock=now_ms)
    _, offer, accept, decision = run(dec, req)
    terms = offer.body["terms"]
    guard = RemoteDecisionGuard(lambda a: tuple(a), acting_for=REQ.agent, capability=GUARD_CAP,
                                trust=TrustPolicy(pinned=frozenset({DEC.agent})), ledger=led, clock=clock)
    pg_testclock.set_clock(cluster.dsn, shift_ms=HOUR)                        # the database's clock jumps an hour after start-up
    with pytest.raises(Refused) as e:
        guard.authorize(decision.to_wire(), terms=terms, accept_digest=accept.digest)
    assert e.value.code == "clock_skew"
    pg_testclock.set_clock(cluster.dsn)
    assert guard.authorize(decision.to_wire(), terms=terms, accept_digest=accept.digest).allowed   # agreed again: the decision was never spent


def test_a_clock_whose_sync_refuses_closes_authorize_before_anything_is_verified_or_spent():
    class Sync:
        calls = 0

        def sync(self) -> None:
            self.calls += 1
            raise Refused("unavailable", "no reference")

        def __call__(self) -> int:
            raise AssertionError("the clock must not be read when its sync refused")
    dec, req, _ = pair(clock=now_ms)
    _, offer, accept, decision = run(dec, req)
    ledger, sync = MemoryLedger(), Sync()
    guard = RemoteDecisionGuard(lambda a: tuple(a), acting_for=REQ.agent, capability=GUARD_CAP,
                                trust=TrustPolicy(pinned=frozenset({DEC.agent})), ledger=ledger, clock=sync)
    with pytest.raises(Refused) as e:
        guard.authorize(decision.to_wire(), terms=offer.body["terms"], accept_digest=accept.digest)
    assert e.value.code == "unavailable" and sync.calls == 1
    assert ledger._seen == {} and guard(("loan-app-17", offer.body["terms"]["subject"]["digest"])) is False
