"""RACE-02 I-06 (R2-C-01): the expired-decision replay hole on the shared PostgreSQL ledger, closed in both languages.

The hole: the PostgreSQL ledger purged rows by the DATABASE's clock (`expires_at <= now_db - keep_ms`) while each receiver
judged a decision's lifetime by its OWN clock. A receiver whose clock lagged by more than `keep_ms` still saw an expired
decision as live, and once the row was purged it redeemed the decision again; the baseline probe redeemed one expired
decision three to four times across Python and Node receivers sharing one ledger.

Closed per decision C: (1) the PostgreSQL ledger itself refuses (`expired`) a message that has expired by the database's
clock, so a purged row can never be spent again whatever any receiver's clock says; (2) a receiver that checks its clock
(`--max-clock-skew-ms`) judges every lifetime by the database's time carried on its monotonic clock (`TrustedClock`), not by
its wall clock; (3) the tolerance must be strictly below the ledger's retention window `keep_ms`, refused at start-up as
`config`. Every scenario here runs the real runners (act.py and act.mjs) or the real ledgers against one real PostgreSQL
server; receiver clocks are moved by the start-up shims from test_clock_trust and the database's clock by pg_testclock.
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
from test_clock_trust import ACT_MJS, HOUR, ROOT, expired_job, shims  # type: ignore[import-not-found]  # noqa: E402
from test_node_postgres import codes, run as node_run  # type: ignore[import-not-found]  # noqa: E402
from test_session import ACT_PY, DEC, REQ, act_job, pair, run  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.envelope import Refused, now_ms, open_envelope  # noqa: E402
from cns_interop.ledger_postgres import PostgresLedger  # noqa: E402

KEEP = 120_000  # PostgresLedger's default retention window; act.py and act.mjs use it


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


def table() -> str:
    return "t_" + uuid.uuid4().hex[:12]


def prefix() -> str:
    return "e_" + uuid.uuid4().hex[:10]


def py_code(fn, *a, **k) -> str:
    try:
        fn(*a, **k)
    except Refused as exc:
        return exc.code
    return "ok"


def act(impl: str, home: Path, job: dict, pre: str, dsn: str, *, skew_ms=None, shift_ms: int = 0, env_extra=None):
    """One real receiver run with its process clock shifted by `shift_ms`. Returns (exit status, outcome, stderr)."""
    home.mkdir(exist_ok=True)
    grants_file(home / "grants.json")
    sh = shims(home)
    args = ["--acting-for", REQ.agent, "--capability", "income-screen", "--capability-version", "1", "--trust", DEC.agent,
            "--ledger-backend", "postgres", "--ledger-dsn-env", "RECEIVER_DSN", "--ledger-prefix", pre,
            "--grants", str(home / "grants.json"), "--grant-store", str(home / "grants.db"), "--action", "release-funds",
            "--audit", str(home / "audit.jsonl"), *([] if skew_ms is None else ["--max-clock-skew-ms", str(skew_ms)])]
    node = shutil.which("node")
    assert node, "Node.js is not installed (need node 22 or later)"
    cmd = ([sys.executable, str(ACT_PY), *args] if impl == "py"
           else [node, "--import", (sh / "shift.mjs").as_uri(), str(ACT_MJS), *args])
    env = {"PYTHONPATH": f"{sh}{os.pathsep}{ROOT}", "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home),
           "RECEIVER_DSN": dsn, "UAI_TEST_CLOCK_SHIFT_MS": str(shift_ms), "PYTHONDONTWRITEBYTECODE": "1", **(env_extra or {})}
    done = subprocess.run(cmd, input=json.dumps(job), capture_output=True, text=True, env=env, timeout=120)
    assert done.stdout, done.stderr
    out = json.loads(done.stdout.splitlines()[-1])
    outcome = ("refused:" + out["refused"]["code"]) if "refused" in out else ("permitted" if out["permitted"] else "not-permitted")
    return done.returncode, outcome, done.stderr


def decision_expired_ms_ago(ms: int) -> dict:
    """A real decision whose lifetime ended `ms` milliseconds ago on the real clock."""
    dec, req, _ = pair(clock=now_ms)
    _, offer, accept, d0 = run(dec, req)
    ttl = d0.expires_at - d0.issued_at
    dec, req, _ = pair(clock=lambda: now_ms() - ttl - ms)
    _, offer, accept, d = run(dec, req)
    assert 0 < now_ms() - d.expires_at < ms + 5_000
    terms = offer.body["terms"]
    return {"decision": d.to_wire(), "terms": terms, "accept_digest": accept.digest, "artifact": ["loan-app-17", terms["subject"]["digest"]]}


# ------------------------------------------------------------------------------------------------------------ the ledger

def test_the_postgres_ledger_refuses_a_message_expired_by_the_databases_clock_in_both_languages_so_a_purged_row_is_never_respent(cluster):
    """Baseline probe P1: the second spend of a message expired more than keep_ms ago was GRANTED AGAIN (the purge had
    forgotten it). Now the first spend is already refused as expired, by the database's clock, in Python and in Node."""
    t = table()
    led = PostgresLedger(cluster.dsn, table=t)
    dbnow = led.server_now_ms()
    assert py_code(led.spend, "S", "long-expired", dbnow - KEEP - 10_000) == "expired"
    assert py_code(led.spend, "S", "long-expired", dbnow - KEEP - 10_000) == "expired"            # and again, never replayed-then-granted
    assert py_code(led.spend, "S", "just-expired", dbnow - 1) == "expired"                         # expired, but not yet purged
    assert py_code(led.reserve, "S", "long-expired", dbnow - KEEP - 10_000, lease_ms=30_000) == "expired"
    assert py_code(led.spend, "S", "live", dbnow + 60_000) == "ok"
    assert py_code(led.spend, "S", "live", dbnow + 60_000) == "replayed"
    assert py_code(led.spend, "S", "never-expires", None) == "ok"
    assert codes(node_run(cluster.dsn, t, [["spend", "S", "n-long-expired", dbnow - KEEP - 10_000],
                                           ["spend", "S", "n-long-expired", dbnow - KEEP - 10_000],
                                           ["reserve", "S", "n-long-expired", dbnow - KEEP - 10_000, 30000],
                                           ["spend", "S", "n-live", dbnow + 60_000], ["spend", "S", "n-live", dbnow + 60_000],
                                           ["spend", "S", "live", dbnow + 60_000]])) == \
        ["expired", "expired", "expired", "ok", "replayed", "replayed"]


def test_the_exact_expiry_boundary_is_expired_in_both_languages_now_equal_to_expires_at(cluster):
    """now == expires_at is expired (UAI-1 section 2 step 4), judged by the database's time: with the caller driving time (the
    conformance stand-in), with the database's clock frozen at the instant, and at the envelope layer."""
    t = table()
    led = PostgresLedger(cluster.dsn, table=t, allow_caller_time=True)
    x = 1_900_000_000_000
    assert py_code(led.spend, "S", "b0", x, now=x) == "expired"
    assert py_code(led.spend, "S", "b1", x, now=x - 1) == "ok"
    assert codes(node_run(cluster.dsn, t, [["spend", "S", "n0", x, x], ["spend", "S", "n1", x, x - 1]], allow_caller_time=True)) == \
        ["expired", "ok"]
    frozen = pg_testclock.real_now_ms(cluster.dsn) + 30_000
    pg_testclock.set_clock(cluster.dsn, frozen_ms=frozen)                   # the database's clock stands still at `frozen`
    real = PostgresLedger(cluster.dsn, table=table())
    assert real.server_now_ms() == frozen
    assert py_code(real.spend, "S", "f0", frozen) == "expired"
    assert py_code(real.spend, "S", "f1", frozen + 1) == "ok"
    assert codes(node_run(cluster.dsn, real._t, [["spend", "S", "g0", frozen], ["spend", "S", "g1", frozen + 1]])) == ["expired", "ok"]
    dec, req, _ = pair(clock=now_ms)
    _, offer, accept, d = run(dec, req)
    assert py_code(open_envelope, d.to_wire(), now=d.expires_at) == "expired"
    assert open_envelope(d.to_wire(), now=d.expires_at - 1).id == d.id


def test_the_file_and_sqlite_ledgers_already_forget_by_the_earlier_of_the_two_clocks_and_are_unchanged(tmp_path):
    """One host, one wall clock: `_cutoff` takes the EARLIER of the verifier's `now` and the wall clock, so a verifier running
    behind never finds a message it still accepts forgotten by a clock ahead of its own. The flaw needs a purge clock ahead
    of the judging clock; these ledgers never purge by one. Unchanged by I-06."""
    from cns_interop.ledger import FileLedger, SqliteLedger
    for led in (FileLedger(tmp_path / "f.jsonl"), SqliteLedger(tmp_path / "s.db")):
        behind = now_ms() - 2 * HOUR
        led.spend("S", "m", behind + 60_000, now=behind)                      # a verifier two hours behind: its view is live
        assert py_code(led.spend, "S", "m", behind + 60_000, now=behind) == "replayed"
        assert py_code(led.spend, "S", "m", behind + 60_000, now=behind - 30_000) == "replayed"   # one further behind: still held


# ----------------------------------------------------------------------------------------------------------- the receivers

def test_receivers_lagging_beyond_keep_ms_cannot_redeem_an_expired_decision_on_one_shared_ledger_in_either_language(cluster, tmp_path):
    """Baseline probe 2: a decision expired 180 s ago, four receivers (py, node, py, node) 240 s behind, keep_ms 120 s: PERMITTED
    four times with --max-clock-skew-ms 300000, three times without any check. Now: refused every time, in every mode."""
    job = decision_expired_ms_ago(180_000)
    pre = prefix()
    no_check = [act(impl, tmp_path / f"n{i}", job, pre, cluster.dsn, shift_ms=-240_000)[1] for i, impl in enumerate(["py", "node", "py", "node"])]
    assert no_check == ["refused:expired"] * 4, no_check               # the ledger judges by the database's clock
    wide = [act(impl, tmp_path / f"w{i}", job, pre, cluster.dsn, skew_ms=300_000, shift_ms=-240_000) for i, impl in enumerate(["py", "node"])]
    assert [(rc, o) for rc, o, _ in wide] == [(2, "refused:config")] * 2   # a tolerance >= keep_ms is not a configuration
    checked = [act(impl, tmp_path / f"c{i}", job, pre, cluster.dsn, skew_ms=5_000, shift_ms=-240_000) for i, impl in enumerate(["py", "node"])]
    assert [(rc, o) for rc, o, _ in checked] == [(2, "refused:clock_skew")] * 2


def test_receivers_two_hours_behind_sharing_one_ledger_refuse_the_expired_decision_every_time(cluster, tmp_path):
    """Baseline probe P2 (py, node, py with clocks two hours back, no check): permitted, then permitted or replayed. Now refused
    as expired by every receiver, and a fresh decision still lands once and is a replay for the other language."""
    job, pre = expired_job(), prefix()
    seq = [act(impl, tmp_path / f"h{i}", job, pre, cluster.dsn, shift_ms=-2 * HOUR)[1] for i, impl in enumerate(["py", "node", "py"])]
    assert seq == ["refused:expired"] * 3, seq
    fresh, pre2 = act_job(), prefix()
    assert act("py", tmp_path / "g0", fresh, pre2, cluster.dsn)[1] == "permitted"
    assert act("node", tmp_path / "g1", fresh, pre2, cluster.dsn)[1] == "refused:replayed"


@pytest.mark.parametrize("impl", ["py", "node"])
def test_a_checked_receiver_judges_the_lifetime_by_the_databases_time_not_its_own(cluster, tmp_path, impl):
    """The database's clock stands still exactly at the decision's expires_at while the receiver's own clock says the decision
    has half a minute left: refused as expired (now == expires_at by the database). The same decision with the database's
    real clock, well before its expiry, is permitted; the tolerance stays satisfied throughout."""
    dec, req, _ = pair(clock=now_ms)
    _, offer, accept, d = run(dec, req, max_ttl_ms=90_000)                   # a 90 s life keeps the frozen instant within tolerance
    terms = offer.body["terms"]
    job = {"decision": d.to_wire(), "terms": terms, "accept_digest": accept.digest, "artifact": ["loan-app-17", terms["subject"]["digest"]]}
    expires_at = job["decision"]["expires_at"]
    assert now_ms() + 60_000 < expires_at < now_ms() + KEEP - 10_000
    pg_testclock.set_clock(cluster.dsn, frozen_ms=expires_at)
    assert act(impl, tmp_path / "frozen", job, prefix(), cluster.dsn, skew_ms=KEEP - 1)[1] == "refused:expired"
    pg_testclock.set_clock(cluster.dsn)
    assert act(impl, tmp_path / "real", job, prefix(), cluster.dsn, skew_ms=KEEP - 1)[1] == "permitted"


@pytest.mark.parametrize("impl", ["py", "node"])
def test_skew_just_below_the_tolerance_acts_and_just_above_it_refuses_before_reading_the_job(cluster, tmp_path, impl):
    for shift in (4_000, -4_000):
        assert act(impl, tmp_path / f"in{shift}", act_job(), prefix(), cluster.dsn, skew_ms=5_000, shift_ms=shift)[1] == "permitted"
    for shift in (6_500, -6_500):
        assert act(impl, tmp_path / f"out{shift}", act_job(), prefix(), cluster.dsn, skew_ms=5_000, shift_ms=shift)[:2] == (2, "refused:clock_skew")


@pytest.mark.parametrize("impl", ["py", "node"])
def test_a_tolerance_at_or_above_keep_ms_is_refused_at_startup_as_config_and_just_below_it_is_accepted(cluster, tmp_path, impl):
    for bad in (KEEP, KEEP + 1, 10 * KEEP):
        rc, outcome, _ = act(impl, tmp_path / f"bad{bad}", act_job(), prefix(), cluster.dsn, skew_ms=bad)
        assert (rc, outcome) == (2, "refused:config")
    assert act(impl, tmp_path / "edge", act_job(), prefix(), cluster.dsn, skew_ms=KEEP - 1)[1] == "permitted"


def test_the_trusted_clock_in_both_languages_carries_the_databases_time_and_refuses_beyond_the_tolerance_or_at_keep_ms(cluster):
    from cns_interop.ledger_postgres import TrustedClock
    led = PostgresLedger(cluster.dsn, table=table())
    for off in (4_000, -4_000):
        clock = TrustedClock(led, 5_000, keep_ms=KEEP, wall=lambda d=off: now_ms() + d)
        clock.sync()
        assert abs(clock() - now_ms()) < 2_000                               # the database's time, not the shifted wall clock
    for off in (6_500, -6_500):
        with pytest.raises(Refused) as e:
            TrustedClock(led, 5_000, keep_ms=KEEP, wall=lambda d=off: now_ms() + d).sync()
        assert e.value.code == "clock_skew"
    for bad in (KEEP, KEEP + 1):
        with pytest.raises(ValueError):
            TrustedClock(led, bad, keep_ms=KEEP)
    TrustedClock(led, KEEP - 1, keep_ms=KEEP).sync()
    r = node_run(cluster.dsn, led._t, [["trusted", 5000, 4000], ["trusted", 5000, -4000], ["trusted", 5000, 6500],
                                      ["trusted", 5000, -6500], ["trusted", KEEP, 0], ["trusted", KEEP - 1, 0]])
    assert [x.get("code", "ok") for x in r] == ["ok", "ok", "clock_skew", "clock_skew", "error", "ok"]
    assert all(x["ok"] < 2000 for x in r if "ok" in x)
