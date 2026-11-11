"""The Phase 6 demonstration, run for real: a Node decider and a Python adapter-backed decider, one receiver that keeps
its own grants, trust, revocations and approvals. The assertions are about what actually happened in the run."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def facts():
    done = subprocess.run([sys.executable, str(ROOT / "interop" / "demo_adapters.py"), "--json"], capture_output=True,
                          text=True, timeout=300, env={**__import__("os").environ, "PYTHONPATH": str(ROOT)})
    assert done.returncode == 0, done.stderr[-3000:]
    out = json.loads(done.stdout)
    out["by_n"] = {s["n"]: s for s in out["steps"]}
    return out


def test_the_actors_are_labeled_truthfully(facts):
    a = facts["actors"]
    assert a["node_decider"]["real_independent_implementation"] is True
    assert a["python_decider"]["judgment_source"] == "scripted-double" and a["python_decider"]["live_model_called"] is False


def test_identity_negotiation_and_the_purpose_bound_capability(facts):
    s = facts["by_n"]
    assert s[1]["admitted"] == [True, True]
    assert s[2]["node_offers"] == s[2]["python_offers"] == ["income-screen.loan-underwriting"]
    assert s[3]["grant_checked_before_disclosure"] is True


def test_selective_disclosure_names_what_never_left_the_receiver(facts):
    s = facts["by_n"][4]
    assert s["disclosed"] == ["doc_type", "monthly_income_cents"] == s["opened_in_accept"]
    assert s["never_sent"] == ["account_number", "employer", "full_name"]


def test_both_independent_implementations_sign_and_agree_on_every_verdict(facts):
    assert facts["by_n"][5] == {"n": 5, "name": "signed decisions verified", "node_signed_by": True, "python_signed_by": True}
    nine = facts["by_n"][9]
    assert nine["agree"] is True
    assert nine["verdicts"] == {"node/clears": "pass", "python/clears": "pass", "node/below": "retry", "python/below": "retry"}


def test_the_receiver_authorizes_each_decision_itself_and_acts_once(facts):
    for who in ("node", "python"):
        got = facts["by_n"][6][who]
        assert got == {"no_approval": "approval_required", "wrong_action": "action", "permitted": True, "acted_once": True}


def test_authorization_that_is_absent_is_refused_for_every_reason_it_can_be_absent(facts):
    eight = facts["by_n"][8]
    assert eight["a_retry_permits_nothing"] == "refused"
    assert eight["no_approval_refused"] == "approval_required"
    assert eight["action_not_granted"] == "action"
    assert eight["withdrawn_after"] == "withdrawn"


def test_revocation_and_expiry_close_what_a_signature_alone_would_have_left_open(facts):
    seven = facts["by_n"][7]
    assert seven["revoked_decider_refused"] == "untrusted"
    assert seven["expired_decision_refused"] == "expired"
    assert seven["node_still_trusted"] == "pinned"       # revoking one decider did not touch the other


def test_a_model_that_announces_authority_it_does_not_have_gets_a_signed_failure_and_no_pass(facts):
    ten = facts["by_n"][10]
    assert ten["verdict"] == "terminal_breach" and ten["allowed"] is False and "adapter_output" in ten["reason"]


def test_every_permit_and_refusal_was_written_to_the_audit_record(facts):
    assert facts["audit_entries"] >= 8
