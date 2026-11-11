"""The consistency model, tested: a lease is judged by the coordinator's clock, a holder that was taken over is fenced, and
the claims stop where the guarantees stop.

What this shows: with a coordinator that is linearizable and keeps the time, two hosts cannot both hold a message however
wrong their clocks are, and a stale holder can be rejected by a target that checks the fence. What it does NOT show:
that any real store is linearizable under partition (see ledger_postgres tests and docs/interop/CONSISTENCY.md), or
exactly-once effects for a target that cannot check the fence.
"""

from __future__ import annotations

import threading

import pytest

from cns_interop.envelope import Refused, now_ms
from cns_interop.fencing import FencedTarget
from cns_interop.ledger import CoordinatedLedger, InMemoryCoordinator, MemoryLedger

S = "uai:ed25519:" + "a" * 64


def code(fn, *a, **k):
    try:
        fn(*a, **k)
    except Refused as exc:
        return exc.code
    return "accepted"


# --------------------------------------------------------------------------------------------------- clock authority
def test_p_l1_a_host_with_a_wrong_clock_cannot_take_a_live_lease_because_the_coordinators_clock_decides():
    """Reproduced before the change: host B, 61 s ahead, reserved a message host A held under a 60 s lease."""
    clock = [1_000_000]
    c = InMemoryCoordinator(clock=lambda: clock[0])
    a, b = CoordinatedLedger(c), CoordinatedLedger(c)
    exp = clock[0] + 600_000
    a.reserve(S, "m", exp, lease_ms=60_000, now=clock[0])                              # A's own clock agrees
    assert code(b.reserve, S, "m", exp, lease_ms=60_000, now=clock[0] + 61_000) == "replayed"   # B lies about the time
    assert code(b.reserve, S, "m", exp, lease_ms=60_000, now=clock[0] - 10 ** 9) == "replayed"
    clock[0] += 60_001                                                                 # the COORDINATOR's clock moves on
    assert b.reserve(S, "m", exp, lease_ms=60_000).fence > 0                           # now the lease really lapsed


def test_a_clock_skewed_either_way_by_ten_minutes_never_double_reserves_across_many_hosts():
    clock = [5_000_000]
    c = InMemoryCoordinator(clock=lambda: clock[0])
    hosts = [CoordinatedLedger(c) for _ in range(8)]
    wins = []
    gate = threading.Barrier(8)

    def go(i):
        gate.wait()
        skew = (i - 4) * 150_000                                                       # hosts disagree by up to +-10 min
        try:
            hosts[i].reserve(S, "race", clock[0] + 600_000, lease_ms=30_000, now=clock[0] + skew)
            wins.append(i)
        except Refused:
            pass

    ts = [threading.Thread(target=go, args=(i,)) for i in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(wins) == 1


def test_the_test_stand_in_can_drive_time_only_when_that_is_asked_for_explicitly():
    c = InMemoryCoordinator(clock=lambda: 1_000)
    default, driven = CoordinatedLedger(c), CoordinatedLedger(c, allow_caller_time=True)
    r = default.reserve(S, "x", None, lease_ms=500, now=10 ** 12)                      # the caller's `now` is ignored
    assert r.lease_until == 1_500
    assert driven.reserve(S, "y", None, lease_ms=500, now=7_000).lease_until == 7_500


def test_a_coordinator_that_cannot_keep_time_or_count_is_not_a_coordinator():
    class NoClock:
        def get(self, key): ...
        def cas(self, key, expected, new): ...
    with pytest.raises(ValueError):
        CoordinatedLedger(NoClock())


# --------------------------------------------------------------------------------------------------- fencing
def test_every_reservation_a_ledger_grants_carries_a_larger_fence_and_a_takeover_gets_a_larger_one_still():
    clock = [1_000]
    for ledger in (CoordinatedLedger(InMemoryCoordinator(clock=lambda: clock[0])), MemoryLedger()):
        t = now_ms() if isinstance(ledger, MemoryLedger) else clock[0]
        first = ledger.reserve(S, "a", t + 10 ** 6, lease_ms=1_000, now=t)
        other = ledger.reserve(S, "b", t + 10 ** 6, lease_ms=1_000, now=t)
        assert 0 < first.fence < other.fence
        if isinstance(ledger, MemoryLedger):
            taken = ledger.reserve(S, "a", t + 10 ** 6, lease_ms=1_000, now=t + 2_000)  # a's lease lapsed
        else:
            clock[0] += 2_000
            taken = ledger.reserve(S, "a", t + 10 ** 6, lease_ms=1_000)
        assert taken.fence > other.fence > first.fence


def test_a_stale_holder_whose_lease_was_taken_over_is_rejected_by_a_fenced_target_and_the_new_holder_is_not():
    clock = [1_000]
    ledger = CoordinatedLedger(InMemoryCoordinator(clock=lambda: clock[0]))
    stale = ledger.reserve(S, "m", None, lease_ms=1_000)
    clock[0] += 1_001                                                                  # the stale holder stalls past its lease
    fresh = ledger.reserve(S, "m", None, lease_ms=1_000)
    target = FencedTarget()
    target.check("ledger-account-7", fresh.fence)                                      # the new holder acts first
    assert code(target.check, "ledger-account-7", stale.fence) == "fenced"             # the stale holder arrives late
    target.check("ledger-account-7", fresh.fence)                                      # the same holder may act again
    target.check("a-different-resource", stale.fence)                                  # fences are per protected resource


def test_a_fenced_target_does_not_trust_a_ledger_that_issues_no_fence_unless_told_to():
    assert code(FencedTarget().check, "r", 0) == "fenced"
    FencedTarget(require_fence=False).check("r", 0)
    for bad in (-1, True, 1.5, "3", None):
        assert code(FencedTarget().check, "r", bad) == "fenced"


def test_two_holders_cannot_both_get_the_action_through_a_fenced_target_whatever_order_they_arrive_in():
    clock = [1_000]
    ledger = CoordinatedLedger(InMemoryCoordinator(clock=lambda: clock[0]))
    a = ledger.reserve(S, "m", None, lease_ms=500)
    clock[0] += 501
    b = ledger.reserve(S, "m", None, lease_ms=500)
    for first, second in ((a, b), (b, a)):
        t = FencedTarget()
        outcomes = [code(t.check, "r", first.fence), code(t.check, "r", second.fence)]
        assert outcomes in (["accepted", "accepted"], ["accepted", "fenced"])
        if first is b:
            assert outcomes[1] == "fenced"                                            # the newer holder fences the older
