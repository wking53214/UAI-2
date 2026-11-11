"""Redeeming a remote decision: leases, crash recovery, idempotency, and failing closed when the ledger cannot answer.

What this shows and what it does not: the two-phase behaviour and the refusal on a failed ledger are exercised against
every shipped ledger and against a coordinator stand-in with injected faults. It is not evidence about a real
distributed store, which must pass the conformance suite itself (ledger_conformance.py) and its own partition tests.
"""

from __future__ import annotations

import multiprocessing as mp
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_session import DEC_ONLY, GUARD_CAP, REQ, code_of, pair, run  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.decision import RemoteDecisionGuard  # noqa: E402
from cns_interop.envelope import Refused, now_ms  # noqa: E402
from cns_interop.ledger import (AmbiguousResult, CoordinatedLedger, InMemoryCoordinator, MemoryLedger,  # noqa: E402
                                SqliteLedger)

def passing_decision():
    dec, req, clock = pair()
    _, offer, accept, decision = run(dec, req)
    return decision.to_wire(), offer.body["terms"], accept.digest, clock


def guard_for(ledger, clock):
    return RemoteDecisionGuard(lambda a: a, acting_for=REQ.agent, capability=GUARD_CAP, trust=DEC_ONLY,
                               ledger=ledger, clock=clock)


def test_a_leased_decision_is_committed_by_complete_and_then_stays_spent():
    wire, terms, accept, clock = passing_decision()
    ledger = MemoryLedger()
    g = guard_for(ledger, clock)
    got = g.authorize(wire, terms=terms, accept_digest=accept, lease_ms=30_000)
    assert got.reservation is not None and g.idempotency_key == got.reservation.key
    assert g(("loan-app-17", terms["subject"]["digest"])) is True
    g.complete()
    assert code_of(guard_for(ledger, clock).authorize, wire, terms=terms, accept_digest=accept,
                   lease_ms=30_000) == "replayed"


def test_a_crash_between_permission_and_commit_lets_a_retry_redeem_once_after_the_lease_lapses():
    wire, terms, accept, clock = passing_decision()
    ledger = MemoryLedger()
    first = guard_for(ledger, clock)
    first.authorize(wire, terms=terms, accept_digest=accept, lease_ms=10_000)
    assert first(("loan-app-17", terms["subject"]["digest"])) is True   # ... and then the process dies
    # while the lease is live nobody else may redeem
    assert code_of(guard_for(ledger, clock).authorize, wire, terms=terms, accept_digest=accept,
                   lease_ms=10_000) == "replayed"
    clock.t += 10_001                                                   # the lease lapses
    retry = guard_for(ledger, clock)
    retry.authorize(wire, terms=terms, accept_digest=accept, lease_ms=10_000)
    assert retry.idempotency_key == first.idempotency_key               # the action can dedupe on this
    assert retry(("loan-app-17", terms["subject"]["digest"])) is True
    retry.complete()
    assert code_of(guard_for(ledger, clock).authorize, wire, terms=terms, accept_digest=accept,
                   lease_ms=10_000) == "replayed"


def test_abort_gives_the_decision_back_and_the_aborting_guard_never_permits_again():
    wire, terms, accept, clock = passing_decision()
    ledger = MemoryLedger()
    g = guard_for(ledger, clock)
    g.authorize(wire, terms=terms, accept_digest=accept, lease_ms=30_000)
    g.abort()
    assert g(("loan-app-17", terms["subject"]["digest"])) is False
    h = guard_for(ledger, clock)
    h.authorize(wire, terms=terms, accept_digest=accept, lease_ms=30_000)
    assert h(("loan-app-17", terms["subject"]["digest"])) is True


def test_complete_without_a_lease_or_a_permitted_call_is_a_caller_error():
    wire, terms, accept, clock = passing_decision()
    g = guard_for(MemoryLedger(), clock)
    g.authorize(wire, terms=terms, accept_digest=accept)
    with pytest.raises(ValueError):
        g.complete()
    assert g.idempotency_key is None


def test_a_ledger_without_leases_cannot_be_asked_for_one():
    class SpendOnly:
        def spend(self, sender, message_id, expires_at, *, now=None):
            pass

    wire, terms, accept, clock = passing_decision()
    with pytest.raises(ValueError):
        guard_for(SpendOnly(), clock).authorize(wire, terms=terms, accept_digest=accept, lease_ms=1_000)


class Flaky:
    """Wraps a coordinator and fails the way a network does."""

    def __init__(self, inner, fail=None):
        self.inner, self.fail = inner, fail or {}

    def now(self):
        return self.inner.now()

    def next_fence(self):
        return self.inner.next_fence()

    def get(self, key):
        if self.fail.get("get"):
            raise self.fail["get"]
        return self.inner.get(key)

    def cas(self, key, expected, new):
        if self.fail.get("cas_before"):
            raise self.fail["cas_before"]
        ok = self.inner.cas(key, expected, new)
        if self.fail.get("cas_after"):
            raise self.fail["cas_after"]   # the write landed, the answer was lost
        return ok


@pytest.mark.parametrize("fault", [{"get": TimeoutError("partition")}, {"cas_before": ConnectionError("reset")},
                                   {"cas_after": AmbiguousResult("timeout after send")}],
                         ids=["partition-on-read", "reset-before-write", "ambiguous-write"])
def test_a_coordinator_that_cannot_answer_means_no_permission_for_spend_and_for_lease(fault):
    wire, terms, accept, clock = passing_decision()
    for kw in ({}, {"lease_ms": 10_000}):
        g = guard_for(CoordinatedLedger(Flaky(InMemoryCoordinator(), fault)), clock)
        assert code_of(g.authorize, wire, terms=terms, accept_digest=accept, **kw) == "unavailable"
        assert g(("loan-app-17", terms["subject"]["digest"])) is False   # never opened


def test_an_ambiguous_write_never_lets_the_decision_through_even_after_the_partition_heals():
    """The write landed but the answer was lost: the key is held, so a retry is refused, not silently accepted."""
    wire, terms, accept, clock = passing_decision()
    c = InMemoryCoordinator()
    g = guard_for(CoordinatedLedger(Flaky(c, {"cas_after": AmbiguousResult("lost")})), clock)
    assert code_of(g.authorize, wire, terms=terms, accept_digest=accept) == "unavailable"
    healed = guard_for(CoordinatedLedger(c), clock)
    assert code_of(healed.authorize, wire, terms=terms, accept_digest=accept) == "replayed"


def test_two_hosts_sharing_a_coordinator_redeem_one_decision_once_and_two_local_ledgers_do_not():
    wire, terms, accept, clock = passing_decision()
    c = InMemoryCoordinator()
    h1, h2 = guard_for(CoordinatedLedger(c), clock), guard_for(CoordinatedLedger(c), clock)
    h1.authorize(wire, terms=terms, accept_digest=accept)
    assert code_of(h2.authorize, wire, terms=terms, accept_digest=accept) == "replayed"
    # The contrast, kept as a test so the limit of a local ledger stays visible: two MemoryLedgers both accept.
    l1, l2 = guard_for(MemoryLedger(), clock), guard_for(MemoryLedger(), clock)
    l1.authorize(wire, terms=terms, accept_digest=accept)
    l2.authorize(wire, terms=terms, accept_digest=accept)


def test_a_ledger_that_raises_anything_but_a_refusal_is_unavailable_never_an_escape():
    class Broken:
        def spend(self, *a, **k):
            raise OSError("disk gone")

    wire, terms, accept, clock = passing_decision()
    assert code_of(guard_for(Broken(), clock).authorize, wire, terms=terms, accept_digest=accept) == "unavailable"


def test_a_ledger_written_before_spend_took_the_clock_still_works():
    class Old:
        def __init__(self):
            self.seen = set()

        def spend(self, sender, message_id, expires_at):
            if (sender, message_id) in self.seen:
                raise Refused("replayed", "again")
            self.seen.add((sender, message_id))

    wire, terms, accept, clock = passing_decision()
    old = Old()
    guard_for(old, clock).authorize(wire, terms=terms, accept_digest=accept)
    assert code_of(guard_for(old, clock).authorize, wire, terms=terms, accept_digest=accept) == "replayed"


def _redeem_in_process(path, q):
    try:
        SqliteLedger(path).reserve("s", "same", now_ms() + 60_000, lease_ms=30_000)
        q.put("won")
    except Refused as exc:
        q.put(exc.code)


def test_eight_processes_sharing_a_sqlite_ledger_redeem_one_message_once(tmp_path):
    q = mp.Queue()
    ps = [mp.Process(target=_redeem_in_process, args=(str(tmp_path / "s.db"), q)) for _ in range(8)]
    for p in ps:
        p.start()
    for p in ps:
        p.join()
    got = sorted(q.get() for _ in ps)
    assert got == ["replayed"] * 7 + ["won"]


def test_a_damaged_sqlite_file_refuses_and_a_missing_directory_is_created(tmp_path):
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"this is not a database" * 100)
    with pytest.raises(Refused) as exc:
        SqliteLedger(bad).spend("s", "m", now_ms() + 60_000)
    assert exc.value.code == "unavailable"
    SqliteLedger(tmp_path / "new" / "dir" / "s.db").spend("s", "m", now_ms() + 60_000)
