"""ledger_conformance: the properties any ledger must have before a guard may rely on it.

A backend (a SQL store, etcd, Redis) passes `check_all(new_state)`. `new_state()` returns a function `open_handle()`
that makes a NEW ledger object onto ONE fresh shared state each time it is called (two handles are two hosts, or two
processes). Each property raises AssertionError naming itself. Nothing here skips: a ledger without the two-phase
methods fails, it is not excused. Thread races run across two handles. Passing proves these properties for these
cases against the backend's own behaviour; it does not prove a distributed store linearizable under partition.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, List

from .envelope import Refused, now_ms

__all__ = ["check_all", "PROPERTIES"]

S = "uai:ed25519:" + "a" * 64
Handle = Callable[[], Any]


def _refused(code: str, fn: Callable[[], object], what: str) -> None:
    try:
        fn()
    except Refused as exc:
        assert exc.code == code, f"{what}: refused as {exc.code!r}, expected {code!r}"
        return
    raise AssertionError(f"{what}: was not refused")


def spend_once(open_handle: Handle) -> None:
    a, b = open_handle(), open_handle()
    exp = now_ms() + 60_000
    a.spend(S, "m1", exp)
    _refused("replayed", lambda: a.spend(S, "m1", exp), "second spend, same handle")
    _refused("replayed", lambda: b.spend(S, "m1", exp), "second spend, other handle")
    b.spend(S, "m2", exp)


def reserve_excludes_everyone_while_leased(open_handle: Handle) -> None:
    a, b = open_handle(), open_handle()
    exp = now_ms() + 60_000
    r = a.reserve(S, "m", exp, lease_ms=30_000)
    _refused("replayed", lambda: b.reserve(S, "m", exp, lease_ms=30_000), "reserve under a live lease")
    _refused("replayed", lambda: b.spend(S, "m", exp), "spend under a live lease")
    assert r.key == f"{S} m"


def commit_is_permanent(open_handle: Handle) -> None:
    a, b = open_handle(), open_handle()
    exp = now_ms() + 60_000
    a.commit(a.reserve(S, "m", exp, lease_ms=30_000))
    _refused("replayed", lambda: b.reserve(S, "m", exp, lease_ms=30_000), "reserve after commit")
    _refused("replayed", lambda: b.spend(S, "m", exp), "spend after commit")


def release_makes_it_redeemable_again(open_handle: Handle) -> None:
    a, b = open_handle(), open_handle()
    exp = now_ms() + 60_000
    a.release(a.reserve(S, "m", exp, lease_ms=30_000))
    b.commit(b.reserve(S, "m", exp, lease_ms=30_000))


def a_lapsed_lease_can_be_taken_and_the_old_holder_cannot_commit_over_it(open_handle: Handle) -> None:
    a, b = open_handle(), open_handle()
    t = now_ms()
    exp = t + 600_000
    old = a.reserve(S, "m", exp, lease_ms=1_000, now=t)
    new = b.reserve(S, "m", exp, lease_ms=30_000, now=t + 2_000)   # the first lease lapsed at t + 1000
    _refused("lease_lost", lambda: a.commit(old, now=t + 2_500), "commit by a holder whose lease was taken")
    _refused("lease_lost", lambda: a.release(old, now=t + 2_500), "release by a holder whose lease was taken")
    b.commit(new, now=t + 3_000)
    _refused("replayed", lambda: a.spend(S, "m", exp, now=t + 4_000), "spend after the new holder committed")


def a_holder_whose_lease_lapsed_with_nobody_else_can_still_commit(open_handle: Handle) -> None:
    a, b = open_handle(), open_handle()
    t = now_ms()
    exp = t + 600_000
    r = a.reserve(S, "m", exp, lease_ms=1_000, now=t)
    a.commit(r, now=t + 5_000)  # the action happened; it must count
    _refused("replayed", lambda: b.reserve(S, "m", exp, lease_ms=1_000, now=t + 6_000), "reserve after late commit")


def exactly_one_of_many_concurrent_reserves_wins(open_handle: Handle) -> None:
    handles = [open_handle() for _ in range(2)]
    exp = now_ms() + 60_000
    wins: List[str] = []
    codes: List[str] = []
    gate = threading.Barrier(16)

    def go(i: int) -> None:
        gate.wait()
        try:
            handles[i % 2].reserve(S, "race", exp, lease_ms=30_000)
            wins.append("won")
        except Refused as exc:
            codes.append(exc.code)

    ts = [threading.Thread(target=go, args=(i,)) for i in range(16)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(wins) == 1, f"{len(wins)} concurrent reserves won, expected exactly 1 (refusals: {sorted(set(codes))})"
    assert set(codes) <= {"replayed"}, f"unexpected refusal codes {sorted(set(codes))}"


def a_bad_lease_is_a_caller_error(open_handle: Handle) -> None:
    h = open_handle()
    for bad in (0, -1, True, 1.5, 10 ** 12):
        try:
            h.reserve(S, "m", None, lease_ms=bad)
        except ValueError:
            continue
        raise AssertionError(f"lease_ms={bad!r} was accepted")


PROPERTIES = (spend_once, reserve_excludes_everyone_while_leased, commit_is_permanent,
              release_makes_it_redeemable_again, a_lapsed_lease_can_be_taken_and_the_old_holder_cannot_commit_over_it,
              a_holder_whose_lease_lapsed_with_nobody_else_can_still_commit,
              exactly_one_of_many_concurrent_reserves_wins, a_bad_lease_is_a_caller_error)


def check_all(new_state: Callable[[], Handle]) -> None:
    """Run every property, each against a fresh shared state."""
    for prop in PROPERTIES:
        prop(new_state())
