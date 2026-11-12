"""A grant withdrawn while an action is in flight: what the receiver's policy (cns_interop.grants) does, pinned down.

The rule, as GrantTable.withdraw documents it: a withdrawal is checked when a permit is ISSUED. A permit issued before
the withdrawal is the receiver's own earlier yes; the action it covers may finish and be completed once. Refusing at
`complete()` would come after the action already happened and would only make the record disagree with the world.
What a withdrawal must stop is every permit issued after it, including the second try at an action whose first permit
was aborted or whose lease lapsed. These tests hold that, in one process and across processes sharing a GrantStore.
"""

from __future__ import annotations

import multiprocessing as mp
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cns_interop" / "tests"))
from test_grants_enforced import grant, verified_decision  # type: ignore[import-not-found]  # noqa: E402
from test_session import code_of  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.envelope import Refused  # noqa: E402
from cns_interop.grants import GrantStore, GrantTable  # noqa: E402


def test_a_permit_issued_before_the_withdrawal_completes_once_and_nothing_after_it_is_permitted():
    got, terms, now = verified_decision()
    table = GrantTable([grant()])
    held = table.permit("release-funds", got, terms, now=now)
    table.withdraw("g")
    held.complete()                                                                  # the earlier yes is honored once
    assert code_of(table.permit, "release-funds", got, terms, now=now) == "withdrawn"
    assert code_of(table.check_terms, terms, now=now) == "withdrawn"


def test_an_in_flight_action_that_is_aborted_after_the_withdrawal_cannot_be_taken_again():
    got, terms, now = verified_decision()
    table = GrantTable([grant()])
    held = table.permit("release-funds", got, terms, now=now)
    table.withdraw("g")
    held.abort()                                                                     # the lease is given back...
    assert code_of(table.permit, "release-funds", got, terms, now=now) == "withdrawn"  # ...and cannot be retaken


def test_an_in_flight_action_whose_lease_lapses_after_the_withdrawal_cannot_be_retried():
    got, terms, now = verified_decision()
    table = GrantTable([grant()], permit_lease_ms=1_000)
    table.permit("release-funds", got, terms, now=now)                               # never completed nor aborted
    table.withdraw("g")
    assert code_of(table.permit, "release-funds", got, terms, now=now + 1_001) == "withdrawn"


def test_without_a_withdrawal_the_same_lapsed_lease_can_be_retried():
    # the control for the test above: only the withdrawal changes, and the answer changes with it
    got, terms, now = verified_decision()
    table = GrantTable([grant()], permit_lease_ms=1_000)
    table.permit("release-funds", got, terms, now=now)
    assert table.permit("release-funds", got, terms, now=now + 1_001)


ACTIONS = tuple(f"act-{i}" for i in range(5_000))


def _permitter(store_path, go, issued, q):
    """Ask for permits on fresh actions, one after another, and report when each request STARTED and how it ended.
    Keeps asking until it has seen the withdrawal several times, so every child is on both sides of it."""
    got, terms, now = verified_decision()
    table = GrantTable([grant(actions=frozenset(ACTIONS))], store=GrantStore(store_path))
    go.wait(30)
    out, refused = [], 0
    for action in ACTIONS:
        started = time.time_ns()
        try:
            table.permit(action, got, terms, now=now)
            outcome = "permitted"
            with issued.get_lock():
                issued.value += 1
        except Refused as exc:
            outcome = exc.code
            refused += 1
        out.append((started, outcome))
        if refused >= 20:
            break
    q.put(out)


def test_across_processes_no_permit_that_starts_after_a_withdrawal_returns_is_issued(tmp_path):
    store_path, go, issued, q = tmp_path / "grants.db", mp.Event(), mp.Value("i", 0), mp.Queue()
    ps = [mp.Process(target=_permitter, args=(store_path, go, issued, q)) for _ in range(4)]
    for p in ps:
        p.start()
    go.set()
    deadline = time.time() + 60
    while issued.value < 40 and time.time() < deadline:                             # withdraw mid-stream
        time.sleep(0.001)
    GrantTable([grant(actions=frozenset(ACTIONS))], store=GrantStore(store_path)).withdraw("g")
    withdrawn_at = time.time_ns()                                                    # the withdrawal has RETURNED here
    results = [r for _ in ps for r in q.get(timeout=120)]                            # a crashed child fails, not hangs
    for p in ps:
        p.join()
    late = [(t, outcome) for t, outcome in results if t > withdrawn_at and outcome == "permitted"]
    assert late == []                                                                # nothing started later got a yes
    outcomes = {outcome for _, outcome in results}
    assert outcomes <= {"permitted", "withdrawn"}                                    # no other way to fail
    assert "withdrawn" in outcomes and "permitted" in outcomes                       # the race really happened
    assert len(results) < 4 * len(ACTIONS)                                           # every child saw it and stopped
