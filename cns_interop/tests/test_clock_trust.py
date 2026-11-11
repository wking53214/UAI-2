"""Clock trust: a receiver that checks its own clock against the ledger database's before judging message lifetimes.

test_adversarial_r4 asserts the gap: a receiver whose clock is set BACK accepts a decision that has expired. That stays true
for a receiver on a single-host ledger that does not check. Shown here: `check_clock` in Python and `checkClock` in Node
refuse a host clock that is set back or forward against a real PostgreSQL server; and, end to end, the real action runners
(act.py and act.mjs) started with their process clock set back two hours are REFUSED the expired decision by the PostgreSQL
ledger (RACE-02 I-06: the ledger judges expiry by the database's clock) and REFUSE to act at all with `--max-clock-skew-ms`.
The process clock is shifted by a test-only start-up shim (sitecustomize for Python, --import for Node), which changes
nothing in the programs. A database whose own clock is wrong is covered in test_expiry_purge_replay (pg_testclock moves
the database's SQL clock); skew between two machines is not shown (one machine).
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
from pg_cluster import Cluster  # type: ignore[import-not-found]  # noqa: E402
from test_act_policy import grants_file  # type: ignore[import-not-found]  # noqa: E402
from test_node_postgres import run as node_run  # type: ignore[import-not-found]  # noqa: E402
from test_session import ACT_PY, DEC, REQ, pair, run  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.envelope import Refused, now_ms  # noqa: E402
from cns_interop.ledger_postgres import PostgresLedger  # noqa: E402

ROOT = ACT_PY.parents[1]
ACT_MJS = ROOT / "interop" / "node" / "act.mjs"
HOUR = 3_600_000


@pytest.fixture(scope="module")
def cluster():
    c = Cluster().start()
    c.wait_ready()
    yield c
    c.cleanup()


def table() -> str:
    return "t_" + uuid.uuid4().hex[:12]


def test_python_check_clock_passes_a_correct_clock_and_refuses_one_set_back_or_forward(cluster):
    ledger = PostgresLedger(cluster.dsn, table=table())
    assert abs(ledger.check_clock(5_000)) < 5_000
    for shift in (-HOUR, HOUR):
        with pytest.raises(Refused) as e:
            ledger.check_clock(5_000, clock=lambda s=shift: now_ms() + s)
        assert e.value.code == "clock_skew"
    with pytest.raises(ValueError):
        ledger.check_clock(-1)


def test_node_check_clock_passes_a_correct_clock_and_refuses_one_set_back_or_forward(cluster):
    r = node_run(cluster.dsn, table(), [["check_clock", 5000, 0], ["check_clock", 5000, -HOUR], ["check_clock", 5000, HOUR],
                                        ["check_clock", -1, 0]])
    assert "ok" in r[0] and abs(r[0]["ok"]) < 5000
    assert [x.get("code") for x in r[1:]] == ["clock_skew", "clock_skew", "error"]


def expired_job() -> dict:
    """A real decision issued two hours ago; its lifetime (at most ten minutes) ended long before now."""
    dec, req, _ = pair(clock=lambda: now_ms() - 2 * HOUR)
    _, offer, accept, decision = run(dec, req)
    terms = offer.body["terms"]
    assert decision.expires_at < now_ms() - HOUR
    return {"decision": decision.to_wire(), "terms": terms, "accept_digest": accept.digest,
            "artifact": ["loan-app-17", terms["subject"]["digest"]]}


def shims(d: Path) -> Path:
    """Start-up shims that set a process's clock back by UAI_TEST_CLOCK_SHIFT_MS. Test-only; not part of either program."""
    (d / "sitecustomize.py").write_text(
        "import os, time\n_s = int(os.environ.get('UAI_TEST_CLOCK_SHIFT_MS', '0'))\n_t, _n = time.time, time.time_ns\n"
        "time.time = lambda: _t() + _s / 1000\ntime.time_ns = lambda: _n() + _s * 1_000_000\n")
    (d / "shift.mjs").write_text("const s = Number(process.env.UAI_TEST_CLOCK_SHIFT_MS ?? 0), real = Date.now;\n"
                                 "Date.now = () => real() + s;\n")
    return d


def act(impl: str, home: Path, job: dict, pre: str, dsn: str, *, skew_flag: bool, shift_ms: int):
    home.mkdir(exist_ok=True)
    grants_file(home / "grants.json")
    sh = shims(home)
    args = ["--acting-for", REQ.agent, "--capability", "income-screen", "--capability-version", "1", "--trust", DEC.agent,
            "--ledger-backend", "postgres", "--ledger-dsn-env", "RECEIVER_DSN", "--ledger-prefix", pre,
            "--grants", str(home / "grants.json"), "--grant-store", str(home / "grants.db"), "--action", "release-funds",
            "--audit", str(home / "audit.jsonl"), *(["--max-clock-skew-ms", "5000"] if skew_flag else [])]
    node = shutil.which("node")
    assert node, "Node.js is not installed (need node 22 or later)"
    cmd = ([sys.executable, str(ACT_PY), *args] if impl == "py"
           else [node, "--import", (sh / "shift.mjs").as_uri(), str(ACT_MJS), *args])
    env = {"PYTHONPATH": f"{sh}{os.pathsep}{ROOT}", "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home),
           "RECEIVER_DSN": dsn, "UAI_TEST_CLOCK_SHIFT_MS": str(shift_ms)}
    done = subprocess.run(cmd, input=json.dumps(job), capture_output=True, text=True, env=env, timeout=90)
    out = json.loads(done.stdout)
    return done.returncode, ("refused:" + out["refused"]["code"]) if "refused" in out else ("permitted" if out["permitted"] else "not-permitted")


@pytest.mark.parametrize("impl", ["py", "node"])
def test_a_receiver_with_its_clock_set_back_is_refused_the_expired_decision_by_the_ledger_and_refuses_to_act_when_it_checks_its_clock(cluster, tmp_path, impl):
    job = expired_job()
    # a correct clock refuses the expired decision
    assert act(impl, tmp_path / "ok", job, "t_" + uuid.uuid4().hex[:10], cluster.dsn, skew_flag=False, shift_ms=0)[1] == "refused:expired"
    # the former gap (RACE-02 R2-C-01), end to end: the same program with its clock set back two hours is now refused by the
    # PostgreSQL ledger, which judges expiry by the database's clock (test_expiry_purge_replay has the full matrix)
    assert act(impl, tmp_path / "gap", job, "t_" + uuid.uuid4().hex[:10], cluster.dsn, skew_flag=False, shift_ms=-2 * HOUR)[1] == "refused:expired"
    # with the check, the set-back host refuses to act at all, before the job is judged
    assert act(impl, tmp_path / "chk", job, "t_" + uuid.uuid4().hex[:10], cluster.dsn, skew_flag=True, shift_ms=-2 * HOUR) == (2, "refused:clock_skew")
    # and a correct clock with the check still refuses the expired decision for what it is
    assert act(impl, tmp_path / "ok2", job, "t_" + uuid.uuid4().hex[:10], cluster.dsn, skew_flag=True, shift_ms=0)[1] == "refused:expired"


@pytest.mark.parametrize("impl", ["py", "node"])
def test_the_clock_check_is_refused_as_config_without_the_postgres_backend_or_with_a_negative_bound(tmp_path, impl):
    node = shutil.which("node")
    assert node, "Node.js is not installed (need node 22 or later)"
    grants_file(tmp_path / "grants.json")
    base = ["--acting-for", REQ.agent, "--capability", "income-screen", "--capability-version", "1", "--trust", DEC.agent,
            "--ledger", str(tmp_path / "spent.db"), "--grants", str(tmp_path / "grants.json"), "--grant-store",
            str(tmp_path / "grants.db"), "--action", "release-funds", "--audit", str(tmp_path / "audit.jsonl"),
            "--max-clock-skew-ms", "5000"]
    cmd = ([sys.executable, str(ACT_PY), "--ledger-backend", "sqlite", *base] if impl == "py" else [node, str(ACT_MJS), *base])
    done = subprocess.run(cmd, input="{}", capture_output=True, text=True, timeout=60,
                          env={"PYTHONPATH": str(ROOT), "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(tmp_path)})
    assert done.returncode == 2 and json.loads(done.stdout)["refused"]["code"] == "config"
    assert not (tmp_path / "spent.db").exists()
