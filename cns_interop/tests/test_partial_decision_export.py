"""A partial assessment never crosses the process boundary as a pass.

`SuperGate(..., require_complete=False)` runs a roster with one end. Its `outcome` reads PASS because every gate it holds
passed, and it is never `allowed`. `from_super_gate` must sign it as a refusal, with the reason, or a receiver would act
on an assessment of half the roster.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_session import IncomeGate, pair, run  # type: ignore[import-not-found]  # noqa: E402

from cns_composition.super_gate import SuperGate  # noqa: E402


def partial_judge(cap, disclosed, subject):
    gate = SuperGate([("Governance_Gateway", IncomeGate())], required=("Governance_Gateway:income",),
                     require_complete=False)
    cand = {"identity": subject["identity"], "digest": subject["digest"], "income": disclosed["monthly_income_cents"]}
    decision = gate.decide({"Governance_Gateway:income": cand})
    assert decision.outcome.value == "pass" and decision.partial and not decision.allowed
    return decision, {"threshold-check": {"roster_root": decision.root}}


def test_a_partial_assessment_that_passed_every_gate_it_holds_crosses_as_a_breach_with_its_reason():
    dec, req, clock = pair(judge=partial_judge)
    *_, decision = run(dec, req)
    got = req.on_reply(decision.to_wire())
    assert got.verdict == "terminal_breach" and not got.allowed
    assert any("partial" in reason for reason in got.reasons)
    assert not got.evidence, "no evidence travels with a refusal"
