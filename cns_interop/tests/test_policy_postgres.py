"""The receiver's policy and audit state shared across receiver HOSTS, against a real PostgreSQL server (one machine: separate
processes stand in for hosts). Shown: a withdrawal on one host stops the others, a stale or divergent grants file makes a host
refuse to start, two operators cannot both publish a policy version, simultaneous permit attempts on one decision yield exactly
one permit, many writers extend one audit chain, editing or removing an audit row is detected, a database outage permits nothing
and a restart recovers. Not shown: more than one machine, or a managed service. A hash chain does not detect cut-off newest
entries (see policy_postgres.py)."""

from __future__ import annotations

import json
import multiprocessing as mp
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import psycopg  # noqa: E402
from pg_cluster import Cluster  # type: ignore[import-not-found]  # noqa: E402
from test_act_policy import grants_file  # type: ignore[import-not-found]  # noqa: E402
from test_session import ACT_PY, DEC, REQ, act_job  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.envelope import Refused  # noqa: E402
from cns_interop.grants import load_grants  # noqa: E402
from cns_interop.policy_postgres import PostgresAudit, PostgresGrantStore, policy_digest  # noqa: E402

ROOT = str(ACT_PY.parents[1])


@pytest.fixture(scope="module")
def cluster():
    c = Cluster().start()
    c.wait_ready()
    yield c
    c.cleanup()


def pre() -> str:
    return "p_" + uuid.uuid4().hex[:10]


def code(fn, *a):
    try:
        fn(*a)
    except Refused as exc:
        return exc.code
    return "ok"


def append_many(args):
    dsn, prefix, n, tag = args
    a = PostgresAudit(dsn, prefix=prefix + "_audit")
    for i in range(n):
        a.append({"at": i, "outcome": "x", "writer": tag})


def act_host(args):
    cluster_dsn, tmp, job, prefix, extra = args
    cmd = [sys.executable, str(ACT_PY), "--acting-for", REQ.agent, "--capability", "income-screen", "--capability-version", "1",
           "--trust", DEC.agent, "--ledger-backend", "postgres", "--ledger-dsn-env", "RECEIVER_DSN", "--ledger-prefix", prefix,
           "--policy-backend", "postgres", "--grants", str(Path(tmp) / "grants.json"), "--action", "release-funds", *extra]
    done = subprocess.run(cmd, input=json.dumps(job), capture_output=True, text=True, timeout=90,
                          env={"PYTHONPATH": ROOT, "PATH": "/usr/bin:/bin", "RECEIVER_DSN": cluster_dsn})
    return done.returncode, json.loads(done.stdout) if done.stdout else {}, done.stderr


def publish(cluster, tmp, prefix, version=1):
    return act_host((cluster.dsn, str(tmp), {}, prefix, ["--publish-policy", str(version)]))


def test_a_withdrawal_on_one_host_is_seen_by_every_other_host(cluster):
    p = pre()
    a, b = PostgresGrantStore(cluster.dsn, prefix=p), PostgresGrantStore(cluster.dsn, prefix=p)
    assert not b.is_withdrawn("g1")
    a.withdraw("g1")
    assert b.is_withdrawn("g1")
    a.withdraw("g1")                                         # idempotent: a repeated withdrawal is not an error


def test_stale_and_conflicting_policy_state(cluster, tmp_path):
    p = pre()
    store = PostgresGrantStore(cluster.dsn, prefix=p)
    d1 = policy_digest(load_grants(grants_file(tmp_path / "g.json").read_text()))
    d2 = policy_digest(load_grants(grants_file(tmp_path / "g2.json", actions=("other",)).read_text()))
    assert d1 != d2 and d1 == policy_digest(load_grants(grants_file(tmp_path / "g3.json").read_text()))
    assert code(store.require_policy, d1) == "stale_policy"          # nothing published yet: a host does not guess
    store.publish_policy(1, d1)
    assert store.require_policy(d1) == 1
    assert code(store.require_policy, d2) == "stale_policy"          # a host with other grants refuses
    assert code(store.publish_policy, 1, d2) == "conflict"           # the same version cannot be published twice
    assert code(store.publish_policy, 3, d2) == "conflict"           # nor can a version be skipped
    store.publish_policy(2, d2)
    assert store.require_policy(d2) == 2 and code(store.require_policy, d1) == "stale_policy"


def test_two_operators_publishing_the_same_version_at_once_only_one_wins(cluster, tmp_path):
    p = pre()
    PostgresGrantStore(cluster.dsn, prefix=p)
    digests = ["a" * 64, "b" * 64, "c" * 64, "d" * 64]

    def attempt(d):
        s = PostgresGrantStore(cluster.dsn, prefix=p)
        return code(s.publish_policy, 1, d)
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(4) as ex:
        results = list(ex.map(attempt, digests))
    assert results.count("ok") == 1 and results.count("conflict") == 3


def test_a_host_with_stale_grants_does_not_act_and_withdrawal_stops_every_host(cluster, tmp_path):
    prefix, job = pre(), act_job()
    grants_file(tmp_path / "grants.json")
    assert act_host((cluster.dsn, str(tmp_path), job, prefix, []))[1]["refused"]["code"] == "stale_policy"   # nothing published
    assert publish(cluster, tmp_path, prefix)[0] == 0
    grants_file(tmp_path / "grants.json", actions=("release-funds", "extra"))        # this host's file drifted
    assert act_host((cluster.dsn, str(tmp_path), job, prefix, []))[1]["refused"]["code"] == "stale_policy"
    grants_file(tmp_path / "grants.json")
    PostgresGrantStore(cluster.dsn, prefix=prefix + "_policy").withdraw("g1")       # another host withdraws the grant
    got = act_host((cluster.dsn, str(tmp_path), job, prefix, []))[1]
    assert got["refused"]["code"] == "withdrawn"


def test_simultaneous_permit_attempts_on_one_decision_yield_exactly_one_permit_and_one_chain(cluster, tmp_path):
    prefix, job = pre(), act_job()
    grants_file(tmp_path / "grants.json")
    assert publish(cluster, tmp_path, prefix)[0] == 0
    with mp.get_context("spawn").Pool(6) as pool:
        outs = pool.map(act_host, [(cluster.dsn, str(tmp_path), job, prefix, [])] * 6)
    permitted = [o for o in outs if o[1].get("permitted") is True]
    assert len(permitted) == 1, outs
    assert all(o[1].get("refused", {}).get("code") in ("replayed", "unavailable") for o in outs if o not in permitted)
    audit = PostgresAudit(cluster.dsn, prefix=prefix + "_audit")
    assert audit.verify() == audit.head() != "0" * 64            # every host's entries extend one intact chain


def test_many_writers_extend_one_chain_and_editing_or_removing_a_row_is_detected(cluster):
    p = pre()
    PostgresAudit(cluster.dsn, prefix=p + "_audit")
    with mp.get_context("spawn").Pool(4) as pool:
        pool.map(append_many, [(cluster.dsn, p, 25, t) for t in "abcd"])
    audit = PostgresAudit(cluster.dsn, prefix=p + "_audit")
    head = audit.verify()
    with psycopg.connect(cluster.dsn) as db:
        assert db.execute(f"select count(*) from {p}_audit_chain").fetchone()[0] == 100
        db.execute(f"update {p}_audit_chain set entry = replace(entry, '\"outcome\": \"x\"', '\"outcome\": \"permitted\"') where seq = 50")
    assert code(audit.verify) == "unavailable"                   # an edited entry
    with psycopg.connect(cluster.dsn) as db:
        db.execute(f"update {p}_audit_chain set entry = replace(entry, '\"outcome\": \"permitted\"', '\"outcome\": \"x\"') where seq = 50")
    assert audit.verify() == head                                 # restored: the chain verifies again
    with psycopg.connect(cluster.dsn) as db:
        db.execute(f"delete from {p}_audit_chain where seq = 30")
    assert code(audit.verify) == "unavailable"                   # a removed middle entry


def test_an_outage_permits_nothing_and_the_chain_resumes_after_restart(cluster):
    p = pre()
    audit = PostgresAudit(cluster.dsn, prefix=p + "_audit")
    audit.append({"at": 1, "outcome": "first"})
    before = audit.head()
    cluster.stop()
    try:
        assert code(audit.append, {"at": 2, "outcome": "lost"}) == "unavailable"
        assert code(audit.verify) == "unavailable"
    finally:
        cluster.start()
        cluster.wait_ready()
    assert audit.head() == before                                  # the refused write left nothing behind
    audit.append({"at": 3, "outcome": "after"})
    assert audit.verify() == audit.head() != before


def test_the_production_profile_refuses_host_local_withdrawals_and_audit(tmp_path):
    cmd = [sys.executable, str(ACT_PY), "--acting-for", REQ.agent, "--capability", "income-screen", "--capability-version", "1",
           "--trust", DEC.agent, "--ledger-backend", "postgres", "--ledger-dsn-env", "RECEIVER_DSN",
           "--grants", str(grants_file(tmp_path / "grants.json")), "--grant-store", str(tmp_path / "s.db"),
           "--action", "release-funds", "--audit", str(tmp_path / "a.jsonl")]
    done = subprocess.run(cmd, input="{}", capture_output=True, text=True, timeout=60,
                          env={"PYTHONPATH": ROOT, "PATH": "/usr/bin:/bin", "UAI_PROFILE": "production",
                               "UAI_CRYPTO_BACKEND": "cryptography", "RECEIVER_DSN": "x"})
    assert done.returncode == 2 and "host-local" in json.loads(done.stdout)["refused"]["reason"]
