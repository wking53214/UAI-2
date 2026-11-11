"""The four defects found in the receiver policy by the 8.0 closure baseline, each reproduced first and now closed:

  P-A  permit() took caller-supplied terms and never compared them with the terms the decision was made under
  P-B  one decision and one approval produced unlimited permits
  P-C  a withdrawal was lost on restart
  P-D  two writers broke the audit chain, after which no GrantTable could start

Each test changes one condition from a passing case and watches the answer change.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_session import CAP, DEC, GUARD_CAP, REQ, code_of, pair, run  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.decision import RemoteDecisionGuard  # noqa: E402
from cns_interop.envelope import Refused  # noqa: E402
from cns_interop.grants import Grant, GrantStore, GrantTable, load_grants, verify_audit  # noqa: E402
from cns_interop.ledger import FileLedger, MemoryLedger, SqliteLedger  # noqa: E402
from cns_interop.trust import TrustPolicy  # noqa: E402

ALL = frozenset({"doc_type", "monthly_income_cents"})


def verified_decision():
    dec, req, clock = pair()
    _, offer, accept, decision = run(dec, req)
    g = RemoteDecisionGuard(lambda a: a, acting_for=REQ.agent, capability=GUARD_CAP, ledger=MemoryLedger(),
                            trust=TrustPolicy(pinned=frozenset({DEC.agent})), clock=clock)
    got = g.authorize(decision.to_wire(), terms=offer.body["terms"], accept_digest=accept.digest)
    return got, offer.body["terms"], clock()


def grant(cap=CAP.name, **kw):
    base = dict(id="g", capability=cap, version=1, requester=REQ.agent, deciders=frozenset({DEC.agent}),
                actions=frozenset({"release-funds"}), disclose_max=ALL)
    base.update(kw)
    return Grant(**base)


# ------------------------------------------------------------------ P-A
def test_p_a_terms_that_are_not_the_decisions_terms_are_refused_even_when_a_grant_matches_them():
    got, terms, now = verified_decision()
    other_purpose = {**terms, "capability": "income-screen.loan-underwriting"}
    table = GrantTable([grant("income-screen.loan-underwriting")])
    assert code_of(table.permit, "release-funds", got, other_purpose, now=now) == "terms"      # was permitted
    assert GrantTable([grant()]).permit("release-funds", got, terms, now=now)                 # the real terms still work
    for key, value in (("disclose", ["doc_type"]), ("decision_ttl_ms", 1), ("evidence", [])):
        assert code_of(GrantTable([grant()]).permit, "release-funds", got, {**terms, key: value}, now=now) == "terms", key


def test_p_a_terms_that_are_not_complete_terms_are_refused_not_crashed():
    got, terms, now = verified_decision()
    partial = {k: v for k, v in terms.items() if k != "subject"}
    assert code_of(GrantTable([grant()]).permit, "release-funds", got, partial, now=now) == "terms"
    assert code_of(GrantTable([grant()]).permit, "release-funds", got, {**terms, "x": 1}, now=now) == "terms"
    assert code_of(GrantTable([grant()]).permit, "release-funds", got, None, now=now) == "terms"


# ------------------------------------------------------------------ P-B
def test_p_b_a_decision_yields_one_permit_per_action_and_the_second_is_refused_as_replayed():
    got, terms, now = verified_decision()
    table = GrantTable([grant()])
    first = table.permit("release-funds", got, terms, now=now)
    assert code_of(table.permit, "release-funds", got, terms, now=now) == "replayed"
    first.complete()
    assert code_of(table.permit, "release-funds", got, terms, now=now) == "replayed"      # spent for good


def test_p_b_an_aborted_permit_can_be_taken_again_and_a_lapsed_lease_can_be_retried_with_the_same_key():
    got, terms, now = verified_decision()
    table = GrantTable([grant()], permit_lease_ms=10_000)
    a = table.permit("release-funds", got, terms, now=now)
    a.abort()
    b = table.permit("release-funds", got, terms, now=now)                                # the action did not happen
    assert b.idempotency_key == a.idempotency_key
    assert code_of(table.permit, "release-funds", got, terms, now=now + 5_000) == "replayed"   # lease live
    c = table.permit("release-funds", got, terms, now=now + 10_001)                       # crashed holder: lease lapsed
    assert c.idempotency_key == b.idempotency_key


def test_p_b_two_tables_sharing_a_permit_ledger_permit_one_action_between_them(tmp_path):
    got, terms, now = verified_decision()
    for ledger in (FileLedger(tmp_path / "p.jsonl"), SqliteLedger(tmp_path / "p.db")):
        t1, t2 = GrantTable([grant()], permit_ledger=ledger), GrantTable([grant()], permit_ledger=ledger)
        t1.permit("release-funds", got, terms, now=now)
        assert code_of(t2.permit, "release-funds", got, terms, now=now) == "replayed"
        ledger = None


def test_p_b_a_permit_ledger_that_cannot_answer_permits_nothing():
    class Down:
        def reserve(self, *a, **k):
            raise OSError("db gone")

        def commit(self, *a, **k): ...

        def release(self, *a, **k): ...

    got, terms, now = verified_decision()
    assert code_of(GrantTable([grant()], permit_ledger=Down()).permit, "release-funds", got, terms, now=now) == "unavailable"
    with pytest.raises(ValueError):
        GrantTable([grant()], permit_ledger=object())


# ------------------------------------------------------------------ P-C
def test_p_c_a_withdrawal_survives_a_restart_and_is_seen_by_another_process(tmp_path):
    got, terms, now = verified_decision()
    store_path = tmp_path / "grants.db"
    GrantTable([grant()], store=GrantStore(store_path)).withdraw("g")
    restarted = GrantTable([grant()], store=GrantStore(store_path))                       # new object, same configuration
    assert code_of(restarted.permit, "release-funds", got, terms, now=now) == "withdrawn"
    assert code_of(restarted.check_terms, terms, now=now) == "withdrawn"
    other = GrantTable([grant()], store=GrantStore(tmp_path / "elsewhere.db"))
    assert other.permit("release-funds", got, terms, now=now)                             # a different store knows nothing


def test_p_c_an_unreadable_grant_store_refuses_it_does_not_assume_nothing_was_withdrawn(tmp_path):
    got, terms, now = verified_decision()
    path = tmp_path / "grants.db"
    table = GrantTable([grant()], store=GrantStore(path))
    path.write_bytes(b"corrupted after open" * 300)
    assert code_of(table.permit, "release-funds", got, terms, now=now) == "unavailable"
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"not a database" * 200)
    with pytest.raises(Refused):
        GrantStore(bad)


# ------------------------------------------------------------------ P-D
def _writer(path, n, q):
    got, terms, now = verified_decision()
    t = GrantTable([grant()], audit_path=path)
    for _ in range(n):
        code_of(t.permit, "no-such-action", got, terms, now=now)                          # refusals are audited too
    q.put("done")


def test_p_d_several_processes_writing_one_audit_file_keep_one_unbroken_chain(tmp_path):
    path, q = tmp_path / "audit.jsonl", mp.Queue()
    ps = [mp.Process(target=_writer, args=(path, 25, q)) for _ in range(4)]
    for p in ps:
        p.start()
    for p in ps:
        p.join()
    assert [q.get(timeout=60) for _ in ps] == ["done"] * 4   # a crashed writer fails the test instead of hanging it
    last = verify_audit(path)                                                              # raises if the chain is broken
    assert len(path.read_text().splitlines()) == 100 and last != "0" * 64
    GrantTable([grant()], audit_path=path)                                                 # and a new table can start


def test_p_d_two_tables_in_one_process_interleaving_also_keep_the_chain(tmp_path):
    got, terms, now = verified_decision()
    path = tmp_path / "audit.jsonl"
    a, b = GrantTable([grant()], audit_path=path), GrantTable([grant()], audit_path=path)
    for t in (a, b, a, b, a):
        code_of(t.permit, "no-such-action", got, terms, now=now)
    verify_audit(path)


def test_p_d_a_damaged_audit_stops_authorization_until_an_operator_recovers_it_and_the_damage_is_kept(tmp_path):
    got, terms, now = verified_decision()
    path = tmp_path / "audit.jsonl"
    t = GrantTable([grant()], audit_path=path)
    t.permit("release-funds", got, terms, now=now).complete()
    good = path.read_bytes()
    path.write_bytes(good.replace(b'"permitted"', b'"nothing"'))                           # tampered
    with pytest.raises(Refused):
        GrantTable([grant()], audit_path=path)                                             # fails closed by default
    recovered = GrantTable([grant()], audit_path=path, audit_recover=True)
    assert recovered is not None
    kept = [p for p in tmp_path.iterdir() if ".damaged." in p.name]
    assert len(kept) == 1 and kept[0].read_bytes() != good                                 # evidence preserved untouched
    first = path.read_text().splitlines()[0]
    assert "audit_recovered" in first and "damaged_sha256" in first
    verify_audit(path)


def test_p_d_a_torn_last_entry_refuses_writes_and_writes_nothing(tmp_path):
    got, terms, now = verified_decision()
    path = tmp_path / "audit.jsonl"
    t = GrantTable([grant()], audit_path=path)
    code_of(t.permit, "no-such-action", got, terms, now=now)
    with open(path, "ab") as fh:
        fh.write(b'{"at": 1, "outcome": "perm')
    size = path.stat().st_size
    assert code_of(t.permit, "release-funds", got, terms, now=now) == "unavailable"
    assert path.stat().st_size == size


def test_a_permit_whose_audit_write_fails_gives_its_lease_back_so_the_action_is_not_lost(tmp_path):
    got, terms, now = verified_decision()
    table = GrantTable([grant()], audit_path=tmp_path / "audit.jsonl")
    table._audit = tmp_path                                                                # a directory: the append fails
    assert code_of(table.permit, "release-funds", got, terms, now=now) == "unavailable"
    table._audit = None
    assert table.permit("release-funds", got, terms, now=now)                              # not burned by the failure


# ------------------------------------------------------------------ configuration file
def test_the_grants_file_is_read_strictly_so_a_typo_cannot_become_a_wider_grant():
    good = ('{"grants":[{"id":"g","capability":"c","version":1,"requester":"%s","deciders":["%s"],"actions":["a"],'
            '"disclose_max":["x"],"approvers":[]}]}') % (REQ.agent, DEC.agent)
    (g,) = load_grants(good)
    assert g.actions == frozenset({"a"}) and g.disclose_max == frozenset({"x"})
    for bad in (good.replace('"actions"', '"action"'), good.replace('"version":1', '"version":1,"version":2'),
                good.replace('"deciders":["%s"]' % DEC.agent, '"deciders":"all"'), '{"grants":[],"extra":1}',
                good.replace('"version":1', '"version":true'), "[]", good.replace('"id":"g"', '"id":"g","wildcard":"*"')):
        with pytest.raises(ValueError):
            load_grants(bad)
    assert os.name == "posix"
