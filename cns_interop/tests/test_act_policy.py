"""interop/act.py is where a decision becomes an action, so it is where a signature must NOT be enough.

These run the real program as its own process, with its policy on its command line and in files, and change one thing at
a time: no policy at all, no grant, the wrong purpose or action, a withdrawn grant, a missing or wrong approval, altered
terms, the wrong document. A refusal that a person or an operator can cure (no approval yet, a grant added later) must
not burn the decision; a replay must.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_session import ACT_PY, DEC, REQ, act_job  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.grants import GrantStore, approve, verify_audit  # noqa: E402
from cns_interop.identity import Signer  # noqa: E402

HUMAN = Signer(bytes([81] * 32))
ROOT = str(ACT_PY.parents[1])


def grants_file(path, *, capability="income-screen", actions=("release-funds",), approvers=(), deciders=None,
                disclose=("doc_type", "monthly_income_cents"), requester=None, extra=None):
    g = {"id": "g1", "capability": capability, "version": 1, "requester": requester or REQ.agent,
         "deciders": list(deciders or [DEC.agent]), "actions": list(actions), "disclose_max": list(disclose),
         "approvers": list(approvers), **(extra or {})}
    path.write_text(json.dumps({"grants": [g]}), encoding="utf-8")
    return path


def run(tmp, job, *, grants=None, action="release-funds", extra_args=(), policy=True, decision_only=False, capability="income-screen"):
    args = [sys.executable, str(ACT_PY), "--acting-for", REQ.agent, "--capability", capability, "--capability-version", "1",
            "--trust", DEC.agent, "--ledger", str(tmp / "spent.jsonl")]
    if decision_only:
        args.append("--decision-only")
    if policy:
        args += ["--grants", str(grants or tmp / "grants.json"), "--grant-store", str(tmp / "grants.db"), "--action", action,
                 "--audit", str(tmp / "audit.jsonl")]
    done = subprocess.run([*args, *extra_args], input=job if isinstance(job, str) else json.dumps(job), capture_output=True,
                          text=True, env={"PYTHONPATH": ROOT, "PATH": "/usr/bin:/bin"}, timeout=60)
    return done.returncode, json.loads(done.stdout), done.stderr


def codes(result):
    return result.get("refused", {}).get("code", "permitted" if result.get("permitted") else "not-permitted")


@pytest.fixture
def tmp(tmp_path):
    grants_file(tmp_path / "grants.json")
    return tmp_path


def approval_for(job, action="release-funds", signer=HUMAN):
    fake = SimpleNamespace(envelope=SimpleNamespace(id=job["decision"]["id"]),
                           subject={"digest": job["terms"]["subject"]["digest"]})
    a = approve(signer, fake, action)  # type: ignore[arg-type]
    return {"approver": a.approver, "decision_id": a.decision_id, "action": a.action, "subject_digest": a.subject_digest,
            "expires_at": a.expires_at, "sig": a.sig}


def test_without_any_policy_act_py_refuses_to_start_there_is_no_silent_default(tmp):
    rc, out, _ = run(tmp, act_job(), policy=False)
    assert rc == 2 and out["refused"]["code"] == "config" and "receiver's policy" in out["refused"]["reason"]
    assert not (tmp / "spent.jsonl").exists() or (tmp / "spent.jsonl").read_text() == ""


def test_decision_only_is_explicit_loud_and_cannot_be_mixed_with_policy(tmp):
    rc, out, err = run(tmp, act_job(), policy=False, decision_only=True)
    assert rc == 0 and out == {"permitted": True} and "NOT receiver-authorized" in err
    rc, out, _ = run(tmp, act_job(), policy=True, decision_only=True)
    assert rc == 2 and out["refused"]["code"] == "config"


def test_a_verified_decision_with_a_grant_is_permitted_once_with_a_permit_and_an_audit_entry(tmp):
    job = act_job()
    rc, out, _ = run(tmp, job)
    assert rc == 0 and out["permitted"] is True and out["permit"]["grant"] == "g1"
    assert out["permit"]["idempotency_key"].startswith("permit:g1 ")
    assert codes(run(tmp, job)[1]) == "replayed"                       # the decision is spent, for every process
    rows = [json.loads(ln) for ln in (tmp / "audit.jsonl").read_text().splitlines()]
    assert [r["outcome"] for r in rows] == ["permitted"] and rows[0]["action"] == "release-funds"
    verify_audit(tmp / "audit.jsonl")


@pytest.mark.parametrize("change,expect", [
    ("no grant at all", "no_grant"),
    ("another purpose", "no_grant"),
    ("another action", "action"),
    ("decider not named", "decider"),
    ("another requester", "no_grant"),
    ("disclosure too wide", "disclosure"),
    ("expired grant", "grant_expired"),
])
def test_a_decision_without_a_matching_grant_is_refused_for_the_stated_reason_and_not_burned(tmp, change, expect):
    job = act_job()
    g = tmp / "grants.json"
    if change == "no grant at all":
        g.write_text('{"grants": []}')
    elif change == "another purpose":
        grants_file(g, capability="income-screen.marketing")
    elif change == "another action":
        grants_file(g, actions=("delete-everything",))
    elif change == "decider not named":
        grants_file(g, deciders=[Signer(bytes([82] * 32)).agent])
    elif change == "another requester":
        grants_file(g, requester=Signer(bytes([83] * 32)).agent)
    elif change == "disclosure too wide":
        grants_file(g, disclose=("doc_type",))
    elif change == "expired grant":
        grants_file(g, extra={"expires_at": 1})
    rc, out, _ = run(tmp, job)
    assert rc == 0 and codes(out) == expect
    # the refusal did not use the decision up: with a proper grant the SAME job now lands
    grants_file(g)
    assert codes(run(tmp, job)[1]) == "permitted"


def test_an_action_that_needs_a_person_is_refused_until_a_listed_person_approves_that_exact_decision(tmp):
    job = act_job()
    grants_file(tmp / "grants.json", approvers=[HUMAN.agent])
    assert codes(run(tmp, job)[1]) == "approval_required"
    stranger = approval_for(job, signer=Signer(bytes([84] * 32)))
    assert codes(run(tmp, {**job, "approval": stranger})[1]) == "approval"          # not a listed approver
    assert codes(run(tmp, {**job, "approval": approval_for(job, action="wire-money")})[1]) == "approval"   # other action
    forged = {**approval_for(job), "sig": "00" * 64}
    assert codes(run(tmp, {**job, "approval": forged})[1]) == "approval"
    assert codes(run(tmp, {**job, "approval": {"approver": HUMAN.agent}})[1]) == "approval"                 # malformed
    rc, out, _ = run(tmp, {**job, "approval": approval_for(job)})                                         # and now it lands
    assert out["permitted"] is True and out["permit"]["grant"] == "g1"
    assert codes(run(tmp, {**job, "approval": approval_for(job)})[1]) == "replayed"


def test_an_approval_for_one_decision_does_not_approve_another_decision(tmp):
    grants_file(tmp / "grants.json", approvers=[HUMAN.agent])
    first, second = act_job(), act_job()
    assert first["decision"]["id"] != second["decision"]["id"]
    assert codes(run(tmp, {**second, "approval": approval_for(first)})[1]) == "approval"


def test_a_withdrawn_grant_refuses_in_a_new_process_and_does_not_burn_the_decision(tmp):
    job = act_job()
    GrantStore(tmp / "grants.db").withdraw("g1")
    assert codes(run(tmp, job)[1]) == "withdrawn"
    other = tmp / "elsewhere"
    other.mkdir()
    grants_file(other / "grants.json")
    # a different store has no withdrawal, so the same decision (never spent) is permitted there
    args_ledger = other / "spent.jsonl"
    assert args_ledger.exists() is False
    assert codes(run(other, job)[1]) == "permitted"


def test_terms_that_are_not_the_terms_of_the_decision_are_refused_even_with_a_matching_grant(tmp):
    job = act_job()
    altered = {**job, "terms": {**job["terms"], "disclose": ["doc_type"]}}
    assert codes(run(tmp, altered)[1]) == "terms"
    other_purpose = {**job, "terms": {**job["terms"], "capability": "income-screen.loan-underwriting"}}
    grants_file(tmp / "grants.json", capability="income-screen.loan-underwriting")
    assert codes(run(tmp, other_purpose)[1]) == "terms"


def test_the_wrong_document_is_not_permitted_and_uses_nothing_up(tmp):
    job = act_job()
    wrong = {**job, "artifact": ["loan-app-17", "some-other-digest"]}
    rc, out, _ = run(tmp, wrong)
    assert rc == 0 and out == {"permitted": False}
    assert codes(run(tmp, job)[1]) == "permitted"                                      # the real document still lands


def test_a_job_carrying_anything_but_its_known_fields_is_refused(tmp):
    job = act_job()
    assert codes(run(tmp, {**job, "grant": "g1"})[1]) == "malformed"                    # a job cannot bring its own policy
    assert codes(run(tmp, {k: v for k, v in job.items() if k != "terms"})[1]) == "malformed"


def test_a_damaged_audit_stops_authorization_with_a_stated_config_error_not_a_crash(tmp):
    job = act_job()
    (tmp / "audit.jsonl").write_text("garbage\n")
    rc, out, _ = run(tmp, job)
    assert rc == 2 and out["refused"]["code"] == "unavailable"


def test_an_unreadable_grants_file_or_store_stops_the_program_before_any_decision_is_read(tmp):
    job = act_job()
    (tmp / "grants.json").write_text('{"grants": [{"id": "g1"}]}')
    rc, out, _ = run(tmp, job)
    assert rc == 2 and out["refused"]["code"] == "config"
    grants_file(tmp / "grants.json")
    (tmp / "grants.db").write_bytes(b"not a database" * 100)
    rc, out, _ = run(tmp, job)
    assert rc == 2 and out["refused"]["code"] == "unavailable"
