"""Revision 4 adversarial cases that no earlier test covered, each with its threat, its setup and the ACTUAL result.

1. A process crashes after the receiver permitted an action and before it completed (real PostgreSQL, real process death).
   Expected and measured: while the lease is live the decision is refused; after it lapses the action may be offered again,
   with the SAME idempotency key. That is at-least-once delivery, which is the documented model: a target that does not
   deduplicate on the key can act twice. This is a deployment limitation, not a defect.
2. The receiver's own clock is wrong. Measured: a clock set BACK makes the receiver accept a message that has expired, and a
   clock set FORWARD refuses a fresh one and expires an approval. The envelope's lifetime is judged by the receiver's clock;
   the PostgreSQL ledger judges LEASES by the server's clock (tested in test_ledger_postgres). A deployment limitation: the
   receiver's clock must be disciplined. The gap is asserted here, not skipped."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from pg_cluster import Cluster  # type: ignore[import-not-found]  # noqa: E402
from test_act_policy import grants_file  # type: ignore[import-not-found]  # noqa: E402
from test_policy_postgres import act_host, publish  # type: ignore[import-not-found]  # noqa: E402
from test_session import ACT_PY, CAP, DEC, GUARD_CAP, REQ, act_job, pair, run  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.decision import RemoteDecisionGuard  # noqa: E402
from cns_interop.envelope import Refused, now_ms  # noqa: E402
from cns_interop.grants import Grant, GrantTable  # noqa: E402
from cns_interop.identity import Signer  # noqa: E402
from cns_interop.ledger import MemoryLedger  # noqa: E402
from cns_interop.trust import TrustPolicy  # noqa: E402

ROOT = str(ACT_PY.parents[1])
HUMAN = Signer(bytes([81] * 32))


@pytest.fixture(scope="module")
def cluster():
    c = Cluster().start()
    c.wait_ready()
    yield c
    c.cleanup()


CRASHER = textwrap.dedent("""
    import json, os, sys
    sys.path.insert(0, sys.argv[1])
    from cns_interop.decision import RemoteDecisionGuard
    from cns_interop.grants import GrantTable, load_grants
    from cns_interop.ledger_postgres import PostgresLedger
    from cns_interop.policy_postgres import PostgresAudit, PostgresGrantStore
    from cns_interop.trust import TrustPolicy
    job = json.load(sys.stdin); dsn = os.environ["RECEIVER_DSN"]; pre = sys.argv[2]
    table = GrantTable(load_grants(open(sys.argv[3]).read()), store=PostgresGrantStore(dsn, prefix=pre + "_policy"),
                       permit_ledger=PostgresLedger(dsn, table=pre + "_permits"), permit_lease_ms=1500,
                       audit_sink=PostgresAudit(dsn, prefix=pre + "_audit"))
    guard = RemoteDecisionGuard(lambda a: tuple(a), acting_for=sys.argv[4], capability=("income-screen", 1),
                                trust=TrustPolicy(pinned=frozenset({sys.argv[5]})),
                                ledger=PostgresLedger(dsn, table=pre + "_decisions"), grants=table, action="release-funds")
    guard.authorize(job["decision"], terms=job["terms"], accept_digest=job["accept_digest"], lease_ms=1500)
    assert guard(tuple(job["artifact"])) is True        # the action is about to happen ...
    print(guard.idempotency_key, flush=True)
    os._exit(9)                                          # ... and the process dies before complete()
""")


def test_a_crash_after_the_permit_and_before_completion_is_refused_while_leased_then_offered_again_with_the_same_key(cluster, tmp_path):
    prefix, job = "c_" + str(now_ms()), act_job()
    grants_file(tmp_path / "grants.json")
    assert publish(cluster, tmp_path, prefix)[0] == 0
    done = subprocess.run([sys.executable, "-c", CRASHER, ROOT, prefix, str(tmp_path / "grants.json"), REQ.agent, DEC.agent],
                          input=json.dumps(job), capture_output=True, text=True, timeout=60,
                          env={"PATH": "/usr/bin:/bin", "RECEIVER_DSN": cluster.dsn})
    assert done.returncode == 9, done.stderr                        # it really died mid-action
    first_key = done.stdout.strip()
    assert first_key.startswith("permit:") or first_key.startswith("uai:")
    during = act_host((cluster.dsn, str(tmp_path), job, prefix, []))[1]
    assert during["refused"]["code"] == "replayed"                  # the lease is still live: nobody else may act
    time.sleep(2.0)                                                 # the lease (1.5 s, on the SERVER's clock) lapses
    again = act_host((cluster.dsn, str(tmp_path), job, prefix, []))[1]
    assert again["permitted"] is True                               # offered again: at-least-once ...
    assert again["permit"]["idempotency_key"].endswith(job["decision"]["id"] + ":release-funds")   # ... under a stable key
    third = act_host((cluster.dsn, str(tmp_path), job, prefix, []))[1]
    assert third["refused"]["code"] == "replayed"                   # and now it is spent for good


def test_the_receivers_own_clock_decides_an_envelopes_lifetime_a_deployment_limitation_asserted_not_skipped():
    dec, req, clock = pair(clock=now_ms)
    _, offer, accept, decision = run(dec, req)
    terms = offer.body["terms"]
    expired_at = decision.expires_at
    trust = TrustPolicy(pinned=frozenset({DEC.agent}))

    def guard(t):
        return RemoteDecisionGuard(lambda a: tuple(a), acting_for=REQ.agent, capability=GUARD_CAP, trust=trust,
                                   ledger=MemoryLedger(), clock=lambda: t)
    code = None
    try:
        guard(expired_at + 3_600_000).authorize(decision.to_wire(), terms=terms, accept_digest=accept.digest)
    except Refused as exc:
        code = exc.code
    assert code == "expired"                                         # a correct clock refuses the expired decision
    # the same receiver with its clock set BACK one hour accepts a decision whose lifetime had ended: the gap
    set_back = guard(expired_at - 1_000)
    set_back.authorize(decision.to_wire(), terms=terms, accept_digest=accept.digest)
    assert set_back(tuple([terms["subject"]["identity"], terms["subject"]["digest"]])) is True
    # a clock set far FORWARD refuses a fresh decision and an approval that has not yet expired
    with pytest.raises(Refused) as e:
        guard(now_ms() + 86_400_000 * 2).authorize(decision.to_wire(), terms=terms, accept_digest=accept.digest)
    assert e.value.code == "expired"


def test_a_receiver_clock_moved_past_an_approvals_expiry_refuses_it_and_back_does_not_extend_it_beyond_its_signed_expiry():
    dec, req, _ = pair(clock=now_ms)
    _, offer, accept, decision = run(dec, req)
    terms = offer.body["terms"]
    job = {"decision": decision.to_wire(), "terms": terms, "accept_digest": accept.digest}
    approver_grant = Grant(id="g1", capability="income-screen", version=1, requester=REQ.agent, deciders=frozenset({DEC.agent}),
                           actions=frozenset({"release-funds"}), disclose_max=frozenset(CAP.accepts), approvers=frozenset({HUMAN.agent}))
    from cns_interop.grants import approve
    from cns_interop.decision import verify_decision
    verified = verify_decision(job["decision"], terms=terms, accept_digest=accept.digest, ledger=MemoryLedger(), now=now_ms())
    approval = approve(HUMAN, verified, "release-funds", ttl_ms=60_000, now=now_ms())
    table = GrantTable([approver_grant], permit_ledger=MemoryLedger())
    with pytest.raises(Refused) as e:
        table.permit("release-funds", verified, terms, approval=approval, now=approval.expires_at + 1)
    assert e.value.code == "approval"
    assert table.permit("release-funds", verified, terms, approval=approval, now=approval.expires_at - 1).approver == HUMAN.agent
