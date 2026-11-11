"""RACE-02 I-07c (R2-C-07): the adversarial clock and database matrix, run through the real receivers (act.py and act.mjs)
against one real PostgreSQL server, in both languages.

Where each scenario of the matrix is proved (this file unless another is named):
  receiver clock back and forward ........ test_receiver_clock_*, and test_expiry_purge_replay (+-4 s in, +-6.5 s out)
  database clock back and forward ......... test_database_clock_*
  the database clock moved by less than the tolerance bounds what is accepted ... test_a_database_clock_behind_*
  database unavailable (server stopped) ... test_database_down_*, test_python_production_with_the_database_down_*
  query timeout ........................... test_a_database_that_answers_too_slowly_*
  malformed / missing / non-finite / negative / implausible reference ... test_clock_fail_closed.py
  expired decision ........................ test_expiry_purge_replay.py, and the boundary tests below
  exact expiry boundary ................... test_the_exact_expiry_boundary_*  (now == expires_at is expired, by database time)
  skew just below / just above tolerance .. test_database_clock_*, test_expiry_purge_replay.py
  tolerance >= keep_ms refused at start-up  test_expiry_purge_replay.py (and test_clock_fail_closed.py: audited)
  restart with a previously issued decision test_a_restarted_receiver_*

How the database's clock is moved: pg_testclock shadows clock_timestamp() inside the test server, so what the DATABASE says
the time is can be set forward or back, frozen, delayed past the statement timeout, or made to answer NULL. It is not the
operating-system clock of the database host: on this machine there is one clock, and PostgreSQL has no setting that
shifts it. A scenario in which the database host's own wall clock is wrong is therefore the same one run here (the server
answers a wrong time), and nothing stronger is claimed. Multiple hosts are not proved: separate processes stand in.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import pg_testclock  # type: ignore[import-not-found]  # noqa: E402
from pg_cluster import Cluster  # type: ignore[import-not-found]  # noqa: E402
from test_clock_fail_closed import audit_line  # type: ignore[import-not-found]  # noqa: E402
from test_clock_trust import HOUR  # type: ignore[import-not-found]  # noqa: E402
from test_clock_trust_production import PRODUCTION, publish, refused, run_receiver, shared_policy_args  # type: ignore[import-not-found]  # noqa: E402
from test_expiry_purge_replay import KEEP, act, decision_expired_ms_ago, prefix  # type: ignore[import-not-found]  # noqa: E402
from test_session import act_job, pair, run  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.envelope import now_ms  # noqa: E402

IMPLS = ["py", "node"]
TOL = 5_000


@pytest.fixture(scope="module")
def cluster():
    c = Cluster().start()
    c.wait_ready()
    pg_testclock.install(c.dsn)
    yield c
    c.cleanup()


@pytest.fixture(autouse=True)
def real_db_clock(cluster):
    pg_testclock.set_clock(cluster.dsn)
    yield
    pg_testclock.set_clock(cluster.dsn)


def restart_database(cluster: Cluster) -> None:
    cluster.stop()
    cluster.start()
    cluster.wait_ready()


def job_expiring_in_ms(window_ms: int) -> dict:
    """A real decision that expires `window_ms` from now on the real clock (its life is `window_ms`, give or take a second)."""
    dec, req, _ = pair(clock=now_ms)
    _, offer, accept, d = run(dec, req, max_ttl_ms=window_ms)
    terms = offer.body["terms"]
    return {"decision": d.to_wire(), "terms": terms, "accept_digest": accept.digest, "artifact": ["loan-app-17", terms["subject"]["digest"]]}


# ------------------------------------------------------------------------------------------- receiver clock

@pytest.mark.parametrize("impl", IMPLS)
@pytest.mark.parametrize("shift", [HOUR, -HOUR, 6_500, -6_500])
def test_receiver_clock_forward_and_back_beyond_the_tolerance_refuses_to_act_and_says_so(cluster, tmp_path, impl, shift):
    rc, outcome, err = act(impl, tmp_path / "r", act_job(), prefix(), cluster.dsn, skew_ms=TOL, shift_ms=shift)
    assert (rc, outcome) == (2, "refused:clock_skew")
    line = audit_line(err)
    assert (line["outcome"], line["stage"], line["recorded"]) == ("clock_skew", "startup", "file")


# ------------------------------------------------------------------------------------------- database clock

@pytest.mark.parametrize("impl", IMPLS)
@pytest.mark.parametrize("shift,expected", [(4_000, "permitted"), (-4_000, "permitted"), (6_500, "refused:clock_skew"),
                                            (-6_500, "refused:clock_skew"), (HOUR, "refused:clock_skew"), (-HOUR, "refused:clock_skew")])
def test_database_clock_back_and_forward_is_judged_against_the_tolerance(cluster, tmp_path, impl, shift, expected):
    pg_testclock.set_clock(cluster.dsn, shift_ms=shift)
    rc, outcome, _ = act(impl, tmp_path / "d", act_job(), prefix(), cluster.dsn, skew_ms=TOL)
    assert outcome == expected and rc == (0 if expected == "permitted" else 2)


@pytest.mark.parametrize("impl", IMPLS)
def test_a_database_clock_behind_by_less_than_the_tolerance_bounds_what_is_accepted_and_never_allows_a_second_redemption(cluster, tmp_path, impl):
    """The tolerance has a price, and it is bounded: with the database 4 s behind, a decision that expired 2 s ago by the real
    clock is still live by the database's, so it is honoured ONCE (the documented cost of a tolerance); a decision that
    expired 8 s ago is not; and the honoured one is never honoured twice, because the ledger keeps its row for keep_ms (120 s),
    far longer than the tolerance, so a receiver within tolerance cannot find it forgotten."""
    pg_testclock.set_clock(cluster.dsn, shift_ms=-4_000)
    pre = prefix()
    just_expired = decision_expired_ms_ago(2_000)
    assert act(impl, tmp_path / "a", just_expired, pre, cluster.dsn, skew_ms=TOL)[1] == "permitted"
    for i, again in enumerate(IMPLS):
        assert act(again, tmp_path / f"b{i}", just_expired, pre, cluster.dsn, skew_ms=TOL)[1] == "refused:replayed"
    assert act(impl, tmp_path / "c", decision_expired_ms_ago(8_000), prefix(), cluster.dsn, skew_ms=TOL)[1] == "refused:expired"


@pytest.mark.parametrize("impl", IMPLS)
def test_a_database_clock_ahead_by_less_than_the_tolerance_refuses_a_decision_the_database_already_holds_expired(cluster, tmp_path, impl):
    pg_testclock.set_clock(cluster.dsn, shift_ms=4_000)
    assert act(impl, tmp_path / "a", decision_expired_ms_ago(2_000), prefix(), cluster.dsn, skew_ms=TOL)[1] == "refused:expired"
    assert act(impl, tmp_path / "b", act_job(), prefix(), cluster.dsn, skew_ms=TOL)[1] == "permitted"


@pytest.mark.parametrize("impl", IMPLS)
def test_the_exact_expiry_boundary_is_expired_by_the_databases_time(cluster, tmp_path, impl):
    """now == expires_at is expired, and one ms after is too. The database's clock stands still at the instant. One ms BEFORE
    it cannot be shown through a whole receiver process: the receiver carries the database's time forward on its monotonic
    clock, so a clock frozen 1 ms short is past the boundary a few ms later; that edge (expires_at - 1 is live, expires_at
    is expired) is proved at the ledger and envelope in test_expiry_purge_replay.py. Here the live side is 5 s before."""
    job = job_expiring_in_ms(90_000)
    expires_at = job["decision"]["expires_at"]
    assert now_ms() + 60_000 < expires_at < now_ms() + KEEP - 10_000
    for n, (at, expected) in enumerate([(expires_at - 5_000, "permitted"), (expires_at, "refused:expired"), (expires_at + 1, "refused:expired")]):
        pg_testclock.set_clock(cluster.dsn, frozen_ms=at)
        assert act(impl, tmp_path / f"e{n}", job, prefix(), cluster.dsn, skew_ms=KEEP - 1)[1] == expected, (at - expires_at, expected)


# ------------------------------------------------------------------------------------------- database down, slow

@pytest.mark.parametrize("impl", IMPLS)
def test_database_down_refuses_unavailable_audited_and_the_decision_is_not_spent(cluster, tmp_path, impl):
    job, pre = act_job(), prefix()
    assert act(impl, tmp_path / "up", act_job(), pre, cluster.dsn, skew_ms=TOL)[1] == "permitted"      # the ledger exists and works
    cluster.stop()
    try:
        started = time.monotonic()
        rc, outcome, err = act(impl, tmp_path / "down", job, pre, cluster.dsn, skew_ms=TOL)
        took = time.monotonic() - started
    finally:
        cluster.start()
        cluster.wait_ready()
    assert (rc, outcome) == (2, "refused:unavailable") and took < 30, (rc, outcome, took)
    line = audit_line(err)
    assert (line["outcome"], line["stage"], line["recorded"]) == ("unavailable", "startup", "file")
    assert not (tmp_path / "down" / "grants.db").exists()
    assert act(impl, tmp_path / "back", job, pre, cluster.dsn, skew_ms=TOL)[1] == "permitted"          # never consumed


@pytest.mark.parametrize("impl", IMPLS)
def test_a_database_that_answers_too_slowly_is_unavailable_within_the_statement_timeout_and_the_decision_is_not_spent(cluster, tmp_path, impl):
    """The server's clock sleeps 5 s on every reading; the statement timeout is 3 s."""
    job, pre = act_job(), prefix()
    pg_testclock.set_clock(cluster.dsn, delay_ms=5_000)
    started = time.monotonic()
    rc, outcome, _ = act(impl, tmp_path / "slow", job, pre, cluster.dsn, skew_ms=TOL)
    took = time.monotonic() - started
    assert (rc, outcome) == (2, "refused:unavailable") and took < 25, (rc, outcome, took)
    pg_testclock.set_clock(cluster.dsn)
    assert act(impl, tmp_path / "fast", job, pre, cluster.dsn, skew_ms=TOL)[1] == "permitted"


# ------------------------------------------------------------------------------------------- restart

@pytest.mark.parametrize("first,second", [("py", "py"), ("py", "node"), ("node", "py"), ("node", "node")])
def test_a_restarted_receiver_cannot_redeem_a_decision_that_was_already_honoured_even_after_the_database_restarts(cluster, tmp_path, first, second):
    """Restart = a new process with no local state, on the same shared ledger. Then the database server itself restarts
    (its ledger is durable), and a third process, in the other language, is refused again."""
    job, pre = act_job(), prefix()
    assert act(first, tmp_path / "one", job, pre, cluster.dsn, skew_ms=TOL)[1] == "permitted"
    assert act(second, tmp_path / "two", job, pre, cluster.dsn, skew_ms=TOL)[1] == "refused:replayed"
    restart_database(cluster)
    other = "node" if second == "py" else "py"
    assert act(other, tmp_path / "three", job, pre, cluster.dsn, skew_ms=TOL)[1] == "refused:replayed"
    assert act(first, tmp_path / "one", job, pre, cluster.dsn, skew_ms=TOL)[1] == "refused:replayed"      # the very same home, too


def test_python_production_with_the_database_down_cannot_record_in_the_database_and_says_so(cluster, tmp_path):
    """The production audit sink is the shared database. When the database is what is down, the refusal cannot be recorded
    there: it is still refused (`unavailable`, exit 2) and still one structured line on stderr, with `recorded: null` and the
    reason it could not be recorded. Nothing is swallowed, and nothing claims a record that does not exist."""
    pre = prefix()
    publish(cluster, tmp_path, pre)
    cluster.stop()
    try:
        result = run_receiver("py", tmp_path, [*shared_policy_args(tmp_path, pre), "--max-clock-skew-ms", str(TOL)], act_job(),
                              cluster.dsn, env_extra=PRODUCTION)
    finally:
        cluster.start()
        cluster.wait_ready()
    assert refused(result) == (2, "unavailable")
    line = audit_line(result[2])
    assert line["recorded"] is None and line["audit_error"] and line["outcome"] == "unavailable", line
