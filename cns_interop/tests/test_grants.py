"""Receiver-side grants: a verified decision is not permission, a purpose is not transferable, a person's approval
cannot be supplied by an agent, withdrawal bites at once, and the audit record cannot silently lose an entry.

Each test changes one condition from the passing case and watches the answer change."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_session import CAP, DEC, GUARD_CAP, REQ, code_of, pair, run  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.decision import RemoteDecisionGuard  # noqa: E402
from cns_interop.envelope import Refused  # noqa: E402
from cns_interop.grants import Grant, GrantTable, approve, verify_audit  # noqa: E402
from cns_interop.identity import Signer  # noqa: E402
from cns_interop.ledger import MemoryLedger  # noqa: E402
from cns_interop.trust import TrustPolicy  # noqa: E402

HUMAN = Signer(bytes([61] * 32))
OTHER_HUMAN = Signer(bytes([62] * 32))
ALL = frozenset({"doc_type", "monthly_income_cents"})


def verified_decision(**kw):
    dec, req, clock = pair()
    _, offer, accept, decision = run(dec, req)
    guard = RemoteDecisionGuard(lambda a: a, acting_for=REQ.agent, capability=GUARD_CAP, ledger=MemoryLedger(),
                                trust=TrustPolicy(pinned=frozenset({DEC.agent})), clock=clock)
    got = guard.authorize(decision.to_wire(), terms=offer.body["terms"], accept_digest=accept.digest)
    return got, offer.body["terms"], clock()


def grant(**kw):
    base = dict(id="g1", capability=CAP.name, version=CAP.version, requester=REQ.agent,
                deciders=frozenset({DEC.agent}), actions=frozenset({"release-funds"}), disclose_max=ALL)
    base.update(kw)
    return Grant(**base)


def test_default_deny_a_valid_signature_and_a_pass_are_not_permission():
    got, terms, now = verified_decision()
    assert got.allowed
    assert code_of(GrantTable([]).permit, "release-funds", got, terms, now=now) == "no_grant"


def test_a_grant_for_the_capability_and_action_permits_and_changing_one_condition_refuses():
    got, terms, now = verified_decision()
    permit = GrantTable([grant()]).permit("release-funds", got, terms, now=now)
    assert permit.action == "release-funds" and permit.decision_id == got.envelope.id
    cases = {
        "action": (grant(), "delete-everything", terms),
        "decider": (grant(deciders=frozenset({Signer(bytes([70] * 32)).agent})), "release-funds", terms),
        "no_grant": (grant(version=2), "release-funds", terms),
        "no_grant ": (grant(capability="income-screen.marketing"), "release-funds", terms),   # another purpose
        "no_grant  ": (grant(requester=Signer(bytes([71] * 32)).agent), "release-funds", terms),
        "disclosure": (grant(disclose_max=frozenset({"doc_type"})), "release-funds", terms),
        "grant_expired": (grant(expires_at=now), "release-funds", terms),
    }
    for want, (g, action, t) in cases.items():
        assert code_of(GrantTable([g]).permit, action, got, t, now=now) == want.strip(), want
    assert GrantTable([grant(expires_at=now + 1)]).permit("release-funds", got, terms, now=now)  # the boundary


def test_a_purpose_is_a_capability_name_so_a_decision_for_one_purpose_does_not_open_another():
    got, terms, now = verified_decision()
    marketing = grant(capability=CAP.name + ".marketing")
    assert code_of(GrantTable([marketing]).permit, "release-funds", got, terms, now=now) == "no_grant"


def test_check_terms_refuses_before_anything_is_disclosed():
    _, terms, now = verified_decision()
    assert GrantTable([grant()]).check_terms(terms, now=now).id == "g1"
    assert code_of(GrantTable([grant(disclose_max=frozenset())]).check_terms, terms, now=now) == "disclosure"
    assert code_of(GrantTable([grant()]).check_terms, {**terms, "capability": "other"}, now=now) == "no_grant"
    assert code_of(GrantTable([grant()]).check_terms, {**terms, "decider": HUMAN.agent}, now=now) == "decider"


def test_withdrawal_bites_at_once_and_only_for_that_grant():
    got, terms, now = verified_decision()
    table = GrantTable([grant()])
    table.permit("release-funds", got, terms, now=now)
    table.withdraw("g1")
    assert code_of(table.permit, "release-funds", got, terms, now=now) == "withdrawn"
    assert code_of(table.check_terms, terms, now=now) == "withdrawn"


def test_a_verified_retry_permits_nothing_and_a_decision_that_is_not_the_one_in_the_terms_is_refused():
    got, terms, now = verified_decision()
    from dataclasses import replace
    assert code_of(GrantTable([grant()]).permit, "release-funds", replace(got, verdict="retry"), terms,
                   now=now) == "refused"
    other = {**terms, "subject": {**terms["subject"], "digest": "00" * 32}}
    assert code_of(GrantTable([grant()]).permit, "release-funds", got, other, now=now) == "terms"


# ------------------------------------------------------------------ human approval
def needs_human():
    return grant(approvers=frozenset({HUMAN.agent}))


def test_an_action_that_needs_a_person_is_refused_without_one_and_permitted_with_one():
    got, terms, now = verified_decision()
    table = GrantTable([needs_human()])
    assert code_of(table.permit, "release-funds", got, terms, now=now) == "approval_required"
    a = approve(HUMAN, got, "release-funds", now=now)
    assert table.permit("release-funds", got, terms, approval=a, now=now).approver == HUMAN.agent


@pytest.mark.parametrize("mutate,why", [
    (lambda a, got: type(a)(**{**a.__dict__, "action": "other"}), "another action"),
    (lambda a, got: type(a)(**{**a.__dict__, "decision_id": "00" * 16}), "another decision"),
    (lambda a, got: type(a)(**{**a.__dict__, "subject_digest": "00" * 32}), "another document"),
    (lambda a, got: type(a)(**{**a.__dict__, "expires_at": a.expires_at + 10 ** 6}), "an extended expiry"),
    (lambda a, got: type(a)(**{**a.__dict__, "sig": "00" * 64}), "a forged signature"),
])
def test_an_approval_is_bound_to_one_decision_action_and_document_and_cannot_be_edited(mutate, why):
    got, terms, now = verified_decision()
    a = mutate(approve(HUMAN, got, "release-funds", now=now), got)
    assert code_of(GrantTable([needs_human()]).permit, "release-funds", got, terms, approval=a, now=now) == "approval", why


def test_an_unlisted_person_an_expired_approval_and_an_agent_approving_itself_are_all_refused():
    got, terms, now = verified_decision()
    table = GrantTable([needs_human()])
    assert code_of(table.permit, "release-funds", got, terms, approval=approve(OTHER_HUMAN, got, "release-funds", now=now), now=now) == "approval"
    stale = approve(HUMAN, got, "release-funds", ttl_ms=1000, now=now)
    assert code_of(table.permit, "release-funds", got, terms, approval=stale, now=now + 1000) == "approval"
    # the requester or the decider can never be an approver: the grant cannot even be built
    with pytest.raises(ValueError):
        grant(approvers=frozenset({REQ.agent}))
    with pytest.raises(ValueError):
        grant(approvers=frozenset({DEC.agent}))
    # and an approval signed by the decider itself is refused even if an operator listed it some other way
    agent_approval = approve(DEC, got, "release-funds", now=now)
    assert code_of(GrantTable([grant(approvers=frozenset({HUMAN.agent}))]).permit, "release-funds", got, terms,
                   approval=agent_approval, now=now) == "approval"


# ------------------------------------------------------------------ audit
def test_every_outcome_is_audited_in_a_hash_chain_and_edits_or_deletions_are_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    got, terms, now = verified_decision()
    table = GrantTable([grant()], audit_path=path)
    table.permit("release-funds", got, terms, now=now)
    code_of(table.permit, "delete-everything", got, terms, now=now)
    table.withdraw("g1")
    code_of(table.permit, "release-funds", got, terms, now=now)
    rows = [json.loads(ln) for ln in path.read_text().splitlines()]
    assert [r["outcome"] for r in rows] == ["permitted", "action", "withdrawn"]
    assert rows[0]["decision_id"] == got.envelope.id and rows[0]["grant"] == "g1" and rows[0]["terms_digest"]
    last = verify_audit(path)
    assert last == rows[-1]["digest"]
    # reopening continues the chain
    GrantTable([grant()], audit_path=path).permit("release-funds", got, terms, now=now)
    assert verify_audit(path) != last
    # an edit in the middle, a deleted middle line, and a reordering are each detected
    lines = path.read_text().splitlines()
    edited = [lines[0].replace('"permitted"', '"nothing-happened"'), *lines[1:]]
    for broken in (edited, [lines[0], *lines[2:]], [lines[1], lines[0], *lines[2:]]):
        p2 = tmp_path / "broken.jsonl"
        p2.write_text("\n".join(broken) + "\n")
        with pytest.raises(Refused) as e:
            verify_audit(p2)
        assert e.value.code == "unavailable"


def test_if_the_audit_cannot_be_written_nothing_is_permitted(tmp_path):
    got, terms, now = verified_decision()
    table = GrantTable([grant()], audit_path=tmp_path / "audit.jsonl")
    (tmp_path / "audit.jsonl").unlink(missing_ok=True)
    import os
    os.mkdir(tmp_path / "gone")
    table._audit = tmp_path / "gone"          # a directory: the append fails
    assert code_of(table.permit, "release-funds", got, terms, now=now) == "unavailable"


def test_a_tail_truncation_is_not_detected_by_the_chain_alone_which_is_why_the_last_digest_is_worth_anchoring(tmp_path):
    """Stated plainly so nobody over-trusts the chain: dropping the final entries leaves a valid shorter chain."""
    path = tmp_path / "audit.jsonl"
    got, terms, now = verified_decision()
    t = GrantTable([grant()], audit_path=path)
    t.permit("release-funds", got, terms, now=now)
    code_of(t.permit, "delete-everything", got, terms, now=now)
    anchored = verify_audit(path)
    path.write_text(path.read_text().splitlines()[0] + "\n")
    assert verify_audit(path) != anchored           # an external copy of the last digest does catch it
