"""PostgresLedger against a REAL PostgreSQL server that the tests start themselves.

Shown here: the shared conformance properties, exactly one winner across processes, server-clock lease authority, a growing
fence, a business write and the spend in one transaction (and a client killed mid-transaction), a server stopped and restarted,
a server that is down, a network partition behind a controllable proxy, and the quorum configuration check. Not shown: a
multi-HOST deployment (one machine), or the behavior of a managed service. The partition and standby tests are about failing
closed, and say what they cannot prove.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import psycopg  # noqa: E402
from pg_cluster import Cluster, make_standby, promote  # type: ignore[import-not-found]  # noqa: E402

from cns_interop import ledger_conformance as lc  # noqa: E402
from cns_interop.envelope import Refused, now_ms  # noqa: E402
from cns_interop.fencing import FencedTarget  # noqa: E402
from cns_interop.ledger_postgres import PostgresLedger  # noqa: E402

S = "uai:ed25519:" + "b" * 64


@pytest.fixture(scope="module")
def cluster():
    c = Cluster().start()
    c.wait_ready()
    yield c
    c.cleanup()


def table() -> str:
    return "t_" + uuid.uuid4().hex[:12]


def code(fn, *a, **k):
    try:
        fn(*a, **k)
    except Refused as exc:
        return exc.code
    return "accepted"


@pytest.mark.parametrize("prop", lc.PROPERTIES, ids=lambda f: f.__name__)
def test_postgres_passes_every_conformance_property(cluster, prop):
    def new_state():
        t = table()
        return lambda: PostgresLedger(cluster.dsn, table=t, allow_caller_time=True)
    prop(new_state())


def _winner(dsn, t, q):
    try:
        PostgresLedger(dsn, table=t).reserve(S, "same", now_ms() + 60_000, lease_ms=30_000)
        q.put("won")
    except Refused as exc:
        q.put(exc.code)


def test_exactly_one_of_sixteen_processes_wins_a_message(cluster):
    t = table()
    PostgresLedger(cluster.dsn, table=t)
    q = mp.Queue()
    ps = [mp.Process(target=_winner, args=(cluster.dsn, t, q)) for _ in range(16)]
    for p in ps:
        p.start()
    for p in ps:
        p.join()
    got = sorted(q.get(timeout=60) for _ in ps)
    assert got == ["replayed"] * 15 + ["won"]


def test_the_servers_clock_decides_a_lease_and_the_callers_clock_is_ignored(cluster):
    led = PostgresLedger(cluster.dsn, table=table())                       # caller time is NOT allowed
    first = led.reserve(S, "m", None, lease_ms=1_000, now=now_ms())
    assert code(led.reserve, S, "m", None, lease_ms=1_000, now=now_ms() + 10 ** 9) == "replayed"   # a lying clock gains nothing
    assert code(led.reserve, S, "m", None, lease_ms=1_000, now=0) == "replayed"
    time.sleep(1.3)                                                          # the SERVER's clock moves on
    second = led.reserve(S, "m", None, lease_ms=1_000)
    assert second.fence > first.fence and second.token != first.token


def test_fences_only_grow_and_a_stale_holder_is_rejected_by_a_fenced_target(cluster):
    led = PostgresLedger(cluster.dsn, table=table())
    stale = led.reserve(S, "m", None, lease_ms=500)
    time.sleep(0.8)
    fresh = led.reserve(S, "m", None, lease_ms=30_000)
    assert 0 < stale.fence < fresh.fence
    target = FencedTarget()
    target.check("account-7", fresh.fence)
    assert code(target.check, "account-7", stale.fence) == "fenced"
    assert code(led.commit, stale) == "lease_lost"                           # and the stale holder cannot commit over the new one


def test_the_business_write_and_the_spend_are_one_transaction_and_a_killed_client_leaves_neither(cluster):
    t = table()
    led = PostgresLedger(cluster.dsn, table=t)
    with psycopg.connect(cluster.dsn, autocommit=True) as db:
        db.execute(f"CREATE TABLE {t}_effects (key text PRIMARY KEY, n int)")
    script = (
        "import os, signal, sys\n"
        f"sys.path.insert(0, {os.path.dirname(os.path.dirname(os.path.dirname(__file__)))!r})\n"
        "import psycopg\n"
        "from cns_interop.ledger_postgres import PostgresLedger\n"
        f"led = PostgresLedger({cluster.dsn!r}, table={t!r})\n"
        f"r = led.reserve({S!r}, 'job', None, lease_ms=1500)\n"
        f"db = psycopg.connect({cluster.dsn!r})\n"
        f"db.execute('INSERT INTO {t}_effects VALUES (%s, 1)', (r.key,))\n"      # the business write, not yet committed
        "led.commit_in(db, r)\n"                                               # the spend, on the same transaction
        "os.kill(os.getpid(), signal.SIGKILL)\n"                               # dies before COMMIT
    )
    done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    assert done.returncode == -signal.SIGKILL, done.stderr
    with psycopg.connect(cluster.dsn, autocommit=True) as db:
        assert db.execute(f"SELECT count(*) FROM {t}_effects").fetchone()[0] == 0          # no effect happened
    assert code(led.reserve, S, "job", None, lease_ms=1500) == "replayed"                     # the lease still holds it
    time.sleep(1.8)                                                                            # ... until it lapses
    r = led.reserve(S, "job", None, lease_ms=30_000)                                           # the retry takes it
    with psycopg.connect(cluster.dsn) as db:
        db.execute(f"INSERT INTO {t}_effects VALUES (%s, 1) ON CONFLICT (key) DO UPDATE SET n = {t}_effects.n + 1", (r.key,))
        led.commit_in(db, r)
        db.commit()
    with psycopg.connect(cluster.dsn, autocommit=True) as db:
        assert db.execute(f"SELECT n FROM {t}_effects WHERE key = %s", (r.key,)).fetchone()[0] == 1   # exactly one effect
    assert code(led.reserve, S, "job", None, lease_ms=1000) == "replayed"                       # and the message is spent


def test_a_committed_message_survives_a_hard_server_stop_and_a_stopped_server_means_unavailable():
    c = Cluster().start()
    try:
        c.wait_ready()
        led = PostgresLedger(c.dsn, table=table())
        led.spend(S, "durable", now_ms() + 600_000)
        c.kill()                                                             # immediate stop: no clean shutdown
        assert code(led.spend, S, "other", now_ms() + 600_000) == "unavailable"            # down means no permission
        assert code(led.reserve, S, "other", None, lease_ms=1000) == "unavailable"
        c.start()
        c.wait_ready()
        assert code(led.spend, S, "durable", now_ms() + 600_000) == "replayed"               # it was durable
        led.spend(S, "other", now_ms() + 600_000)                                            # and service resumes
    finally:
        c.cleanup()


class Proxy:
    """A TCP proxy that can drop traffic: a partition between a client and the server, not a stopped process."""

    def __init__(self, target_port: int) -> None:
        self.block = threading.Event()
        self.ls = socket.socket()
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(16)
        self.port = self.ls.getsockname()[1]
        self.target = target_port
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                c, _ = self.ls.accept()
                u = socket.create_connection(("127.0.0.1", self.target))
            except OSError:
                return
            for a, b in ((c, u), (u, c)):
                threading.Thread(target=self._pipe, args=(a, b), daemon=True).start()

    def _pipe(self, a: socket.socket, b: socket.socket) -> None:
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                if not self.block.is_set():
                    b.sendall(d)
        except OSError:
            pass
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass


def test_a_network_partition_makes_the_ledger_refuse_within_its_timeout_and_never_grants(cluster):
    proxy = Proxy(cluster.port)
    t = table()
    led = PostgresLedger(cluster.dsn_via(proxy.port), table=t, statement_timeout_ms=1500, tcp_user_timeout_ms=1500,
                         connect_timeout_s=2)
    led.reserve(S, "before", None, lease_ms=30_000)                          # healthy
    proxy.block.set()                                                        # the partition: bytes are dropped
    started = time.time()
    assert code(led.reserve, S, "during", None, lease_ms=30_000) == "unavailable"
    assert time.time() - started < 10                                        # it fails closed in bounded time, it does not hang
    proxy.block.clear()
    direct = PostgresLedger(cluster.dsn, table=t)
    # whatever happened to the request that was lost, no second host could be granted the same message while it is held
    state = code(direct.reserve, S, "during", None, lease_ms=1_000)
    assert state in ("replayed", "accepted")                                 # held by the lost request, or never arrived


def test_the_quorum_flag_refuses_to_write_to_a_server_that_is_not_configured_for_it(cluster):
    led = PostgresLedger(cluster.dsn, table=table())
    strict = PostgresLedger(cluster.dsn, table=led._t, require_sync_replication=False)
    assert strict.reserve(S, "m", None, lease_ms=1000)
    with pytest.raises(Refused) as e:
        PostgresLedger(cluster.dsn, table=table(), require_sync_replication=True)    # this single node has no standby
    assert e.value.code == "unavailable" and "quorum-durable" in e.value.reason


def test_a_bad_table_name_is_a_caller_error_and_an_unreachable_dsn_is_unavailable():
    with pytest.raises(ValueError):
        PostgresLedger("host=127.0.0.1", table="x; DROP TABLE y")
    assert code(PostgresLedger, "host=127.0.0.1 port=1 user=postgres dbname=postgres", connect_timeout_s=1) == "unavailable"


def test_a_synchronous_standby_behind_a_partition_makes_the_ledger_refuse_and_a_failover_loses_nothing_anyone_was_told():
    """The same experiment that lost an acknowledged reservation on Redis, with PostgreSQL and a synchronous standby. The
    commit that the standby cannot confirm is NOT reported as granted, so after the primary dies and the standby is
    promoted, nothing that was acknowledged is missing and the one unacknowledged request can be granted again."""
    primary = Cluster(hba_replication=True).start()
    standby = None
    try:
        primary.wait_ready()
        repl = Proxy(primary.port)
        standby = make_standby(primary, repl.port).start()
        standby.wait_ready()
        with psycopg.connect(primary.dsn, autocommit=True) as db:
            db.execute("ALTER SYSTEM SET synchronous_standby_names = 'standby1'")
            db.execute("SELECT pg_reload_conf()")
            for _ in range(50):
                if db.execute("SELECT count(*) FROM pg_stat_replication WHERE sync_state = 'sync'").fetchone()[0] == 1:
                    break
                time.sleep(0.2)
            else:
                raise AssertionError("the standby never became synchronous")
        t = table()
        led = PostgresLedger(primary.dsn, table=t, require_sync_replication=True, statement_timeout_ms=2_000)
        before = led.reserve(S, "before", None, lease_ms=600_000)                      # confirmed by the standby
        with psycopg.connect(standby.dsn, autocommit=True) as sb:
            assert sb.execute(f"SELECT count(*) FROM {t} WHERE id = 'before'").fetchone()[0] == 1
        repl.block.set()                                                               # the standby is partitioned away
        started = time.time()
        assert code(led.reserve, S, "during", None, lease_ms=600_000) == "unavailable"
        assert time.time() - started < 15
        with psycopg.connect(primary.dsn, autocommit=True) as db:                      # the primary DID commit it locally
            assert db.execute(f"SELECT count(*) FROM {t} WHERE id = 'during'").fetchone()[0] == 1
        # While the standby is out of reach EVERY write waits on it, even one that would only be answered "replayed", so the
        # ledger answers "unavailable" to all of them: no host is granted anything during the partition.
        assert code(PostgresLedger(primary.dsn, table=t, require_sync_replication=True, statement_timeout_ms=1500).reserve,
                    S, "someone-else", None, lease_ms=1000) == "unavailable"
        primary.kill()                                                                 # the primary is lost
        promote(standby)
        repl.block.clear()
        survivor = PostgresLedger(standby.dsn, table=t)
        assert code(survivor.reserve, S, "before", None, lease_ms=1000) == "replayed"   # the acknowledged one survived
        granted_again = survivor.reserve(S, "during", None, lease_ms=30_000)           # nobody was told it was granted
        assert granted_again.fence > 0 and before.fence > 0
    finally:
        if standby is not None:
            standby.cleanup()
        primary.cleanup()
