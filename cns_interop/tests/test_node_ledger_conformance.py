"""The Node PostgresLedger (interop/node/pg.mjs) passes the SAME conformance properties as every other ledger
(cns_interop/ledger_conformance.py), one test per property, against a real PostgreSQL server the test starts.

Node is driven through a subprocess adapter (node_ledger_adapter.mjs), one operation per process, so two handles are two
processes sharing one table, as the other cross tests do. A mixed pair (one Python handle, one Node handle on one table) runs
the same properties too, which is what a Python and a Node receiver on two hosts are. Not shown: a multi-host deployment.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import uuid
from typing import Any, Optional

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from pg_cluster import Cluster  # type: ignore[import-not-found]  # noqa: E402

from cns_interop import ledger_conformance as lc  # noqa: E402
from cns_interop.envelope import Refused  # noqa: E402
from cns_interop.ledger import Reservation  # noqa: E402
from cns_interop.ledger_postgres import PostgresLedger  # noqa: E402

ADAPTER = os.path.join(os.path.dirname(__file__), "node_ledger_adapter.mjs")


@pytest.fixture(scope="module")
def cluster():
    c = Cluster().start()
    c.wait_ready()
    yield c
    c.cleanup()


class NodeHandle:
    """A ledger handle whose every operation runs in a fresh Node process against the shared table."""

    def __init__(self, dsn: str, table: str) -> None:
        self._dsn, self._table = dsn, table

    def _call(self, op: str, **a: Any) -> Any:
        node = shutil.which("node")
        assert node, "Node.js is not installed (need node 22 or later)"
        job = {"dsn_env": "LEDGER_DSN", "table": self._table, "op": op, "a": a}
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LEDGER_DSN": self._dsn}
        done = subprocess.run([node, ADAPTER], input=json.dumps(job), capture_output=True, text=True, env=env, timeout=120)
        assert done.returncode == 0, done.stderr
        out = json.loads(done.stdout)
        if "caller_error" in out:
            raise ValueError(out["caller_error"])
        if "code" in out:
            raise Refused(out["code"], out["reason"])
        return out["ok"]

    def spend(self, sender: str, message_id: str, expires_at: Optional[int], *, now: Optional[int] = None) -> None:
        self._call("spend", sender=sender, id=message_id, expires_at=expires_at, now=now)

    def reserve(self, sender: str, message_id: str, expires_at: Optional[int], *, lease_ms: Any,
                now: Optional[int] = None) -> Reservation:
        got = self._call("reserve", sender=sender, id=message_id, expires_at=expires_at, lease_ms=lease_ms, now=now)
        return Reservation(sender, message_id, expires_at, got["token"], got["lease_until"], got["fence"])

    @staticmethod
    def _res(r: Reservation) -> dict:  # type: ignore[type-arg]
        return {"sender": r.sender, "id": r.message_id, "expiresAt": r.expires_at, "token": r.token}

    def commit(self, r: Reservation, *, now: Optional[int] = None) -> None:
        self._call("commit", reservation=self._res(r))

    def release(self, r: Reservation, *, now: Optional[int] = None) -> None:
        self._call("release", reservation=self._res(r))


def _table() -> str:
    return "t_" + uuid.uuid4().hex[:12]


@pytest.mark.parametrize("prop", lc.PROPERTIES, ids=lambda f: f.__name__)
def test_node_passes_every_conformance_property(cluster, prop):
    t = _table()
    prop(lambda: NodeHandle(cluster.dsn, t))


@pytest.mark.parametrize("prop", lc.PROPERTIES, ids=lambda f: f.__name__)
def test_a_python_handle_and_a_node_handle_on_one_table_pass_every_conformance_property(cluster, prop):
    t = _table()
    handles = [lambda: PostgresLedger(cluster.dsn, table=t, allow_caller_time=True), lambda: NodeHandle(cluster.dsn, t)]
    n = {"i": 0}

    def open_handle() -> Any:
        n["i"] += 1
        return handles[n["i"] % 2]()
    prop(open_handle)


# ---------------------------------------------------------------------------------------------------------------------
# PostgreSQL-specific contract properties beyond the generic suite: what Python's PostgresLedger does that the generic
# properties do not reach (expiry by the database's clock, fences, forgotten rows, a stranger's release), run on Python,
# on Node, and on a mixed pair, with the same expectations.
S = lc.S


def _fail_unless(code: str, fn: Any, what: str) -> None:
    lc._refused(code, fn, what)


def pg_expired_message_is_refused_never_granted(h: Any) -> None:
    a, b = h(), h()
    from cns_interop.envelope import now_ms
    t = now_ms()
    _fail_unless("expired", lambda: a.spend(S, "e1", t - 1, now=t), "spend of an expired message")
    _fail_unless("expired", lambda: b.reserve(S, "e2", t - 1, lease_ms=1000, now=t), "reserve of an expired message")
    a.spend(S, "e1", t + 60_000, now=t)   # refusing it wrote nothing, so the live one is not "replayed"


def pg_fences_only_grow_across_handles(h: Any) -> None:
    a, b = h(), h()
    from cns_interop.envelope import now_ms
    t = now_ms()
    first = a.reserve(S, "f", t + 600_000, lease_ms=1000, now=t)
    second = b.reserve(S, "f", t + 600_000, lease_ms=30_000, now=t + 2000)
    other = a.reserve(S, "g", t + 600_000, lease_ms=30_000, now=t)
    assert 0 < first.fence < second.fence and second.fence < other.fence, (first.fence, second.fence, other.fence)
    assert second.lease_until == t + 2000 + 30_000


def pg_release_semantics(h: Any) -> None:
    a, b = h(), h()
    from cns_interop.envelope import now_ms
    t = now_ms()
    r = a.reserve(S, "r", t + 60_000, lease_ms=30_000, now=t)
    stranger = Reservation(S, "r", t + 60_000, "f" * 32, r.lease_until, r.fence)
    _fail_unless("lease_lost", lambda: b.release(stranger), "release by a stranger")
    a.release(r)
    a.release(r)   # releasing what is gone is not an error
    b.reserve(S, "r", t + 60_000, lease_ms=30_000, now=t)


def pg_a_forgotten_row_is_spent_by_a_late_commit_and_a_stranger_cannot(h: Any) -> None:
    a, b = h(), h()
    from cns_interop.envelope import now_ms
    t = now_ms()
    ghost = Reservation(S, "ghost", t + 60_000, "e" * 32, t + 1000, 1)     # no row: the ledger forgot it
    a.commit(ghost)                                                       # it is spent now
    _fail_unless("replayed", lambda: b.spend(S, "ghost", t + 60_000, now=t), "spend after a late commit of a forgotten row")
    _fail_unless("lease_lost", lambda: b.commit(Reservation(S, "ghost", t + 60_000, "d" * 32, t + 1000, 1)), "commit by a stranger")


def pg_spend_without_expiry_is_permanent(h: Any) -> None:
    a, b = h(), h()
    a.spend(S, "forever", None)
    _fail_unless("replayed", lambda: b.spend(S, "forever", None), "second spend, no expiry")


PG_PROPERTIES = (pg_expired_message_is_refused_never_granted, pg_fences_only_grow_across_handles, pg_release_semantics,
                 pg_a_forgotten_row_is_spent_by_a_late_commit_and_a_stranger_cannot, pg_spend_without_expiry_is_permanent)


@pytest.mark.parametrize("prop", PG_PROPERTIES, ids=lambda f: f.__name__)
@pytest.mark.parametrize("who", ["python", "node", "mixed"])
def test_the_postgres_contract_properties_hold_for_python_node_and_a_mixed_pair(cluster, who, prop):
    t = _table()
    py = lambda: PostgresLedger(cluster.dsn, table=t, allow_caller_time=True)  # noqa: E731
    nd = lambda: NodeHandle(cluster.dsn, t)  # noqa: E731
    seq = {"python": [py], "node": [nd], "mixed": [py, nd]}[who]
    n = {"i": 0}

    def open_handle() -> Any:
        n["i"] += 1
        return seq[n["i"] % len(seq)]()
    prop(open_handle)


def test_the_suite_catches_a_node_ledger_that_forgets_everything(cluster):
    class Forgetful(NodeHandle):
        def __init__(self, dsn: str, table: str) -> None:
            super().__init__(dsn, table + "_" + uuid.uuid4().hex[:6])    # every handle is its own world: nothing is shared
    with pytest.raises(AssertionError):
        lc.spend_once(lambda: Forgetful(cluster.dsn, _table()))
