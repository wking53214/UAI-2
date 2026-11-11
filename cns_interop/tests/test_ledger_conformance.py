"""Every shipped ledger passes the same conformance properties, one test per (ledger, property).

MemoryLedger is one process, so its two handles are the same object: it is held to the properties that make sense
for one process by sharing the object. The others share real state across handles."""

from __future__ import annotations

import pytest

from cns_interop import ledger_conformance as lc
from cns_interop.ledger import CoordinatedLedger, FileLedger, InMemoryCoordinator, MemoryLedger, SqliteLedger


def _memory(tmp_path):
    one = MemoryLedger()
    return lambda: one


def _file(tmp_path):
    p = tmp_path / "f.jsonl"
    return lambda: FileLedger(p)


def _sqlite(tmp_path):
    p = tmp_path / "s.db"
    return lambda: SqliteLedger(p)


def _coordinated(tmp_path):
    c = InMemoryCoordinator()
    return lambda: CoordinatedLedger(c, allow_caller_time=True)  # the generic properties drive time with now=


BACKENDS = {"memory": _memory, "file": _file, "sqlite": _sqlite, "coordinated": _coordinated}


@pytest.mark.parametrize("prop", lc.PROPERTIES, ids=lambda f: f.__name__)
@pytest.mark.parametrize("backend", sorted(BACKENDS))
def test_every_ledger_passes_every_property(backend, prop, tmp_path):
    prop(BACKENDS[backend](tmp_path))


def test_a_ledger_without_the_two_phase_methods_fails_the_suite_it_is_not_excused():
    class SpendOnly:
        def spend(self, sender, message_id, expires_at, *, now=None):
            pass

    with pytest.raises(AttributeError):
        lc.reserve_excludes_everyone_while_leased(lambda: SpendOnly())


def test_the_suite_catches_a_ledger_that_lets_two_reserves_both_win():
    class Broken(MemoryLedger):
        def _mutate(self, sender, message_id, now, step):  # forgets everything: every reserve wins
            self._seen = {}
            return super()._mutate(sender, message_id, now, step)

    with pytest.raises(AssertionError):
        lc.check_all(lambda: (lambda one=Broken(): one))
