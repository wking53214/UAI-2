"""interop/fuzz_policy.py: the hostile-model fuzzer must (1) find no breach in the real chain and (2) FIND each of these deliberate
bugs. Mutation testing is what makes a clean fuzz run mean something: a search that cannot catch a broken policy shows nothing
when it finds nothing. Nothing here calls a network or a provider.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "interop"))

import fuzz_policy as fz  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.adapter import Recommendation  # noqa: E402

CASES = 4000


def lowered(rec: Recommendation) -> Recommendation:
    return Recommendation("retry", rec.reasons + ("re-checked",), {})


def clears_with(kind_ok: Any, income_ok: Any):
    """A policy built from two predicates, so each mutant changes exactly one rule."""
    def pol(cap: Any, disclosed: Dict[str, Any], subject: Any, rec: Recommendation) -> Recommendation:
        try:
            ok = kind_ok(disclosed.get("doc_type")) and income_ok(disclosed.get("monthly_income_cents"))
        except Exception:
            ok = False
        return lowered(rec) if rec.verdict == "pass" and not ok else rec
    return pol


def real_kind(k): return k in ("paystub", "tax-return")
def real_income(n): return isinstance(n, int) and not isinstance(n, bool) and n >= 450_000


# Each mutant is a policy with one deliberate bug. The fuzzer must report a breach for every one.
MUTANTS = {
    "no re-check at all": lambda cap, d, s, rec: rec,
    "skips the document type": clears_with(lambda k: True, real_income),
    "accepts a float income": clears_with(real_kind, lambda n: isinstance(n, (int, float)) and n >= 450_000),
    "threshold off by one": clears_with(real_kind, lambda n: isinstance(n, int) and n >= 449_999),
    "type compared by prefix": clears_with(lambda k: str(k).startswith("pay") or str(k).startswith("tax"), real_income),
    "type compared case-insensitively": clears_with(lambda k: str(k).lower() in ("paystub", "tax-return"), real_income),
    "type compared after strip": clears_with(lambda k: str(k).strip() in ("paystub", "tax-return"), real_income),
    "income read as text": clears_with(real_kind, lambda n: int(str(n).split(".")[0]) >= 450_000 if str(n).lstrip("-").isdigit() else False),
    "a missing income counts as clearing": clears_with(real_kind, lambda n: n is None or real_income(n)),
}


def test_the_real_policy_and_chain_hold_every_invariant_over_a_fixed_deterministic_run():
    for seed in (1, 2, 3):
        rep = fz.fuzz(CASES, seed)
        assert rep.breaches == [] and rep.violations == [], (seed, rep.breaches[:2], rep.violations[:2])
        assert not rep.crashed, rep.crashed
        assert rep.overblocked == 0
        assert rep.model_passes_accepted > 500 and rep.lowered > 100 and rep.final_passes > 100   # the run really tested something


@pytest.mark.parametrize("name", list(MUTANTS))
def test_the_fuzzer_catches_each_deliberately_broken_policy(name):
    rep = fz.fuzz(CASES, seed=1, the_policy=MUTANTS[name])
    assert rep.breaches, f"the fuzzer did not find the bug: {name}"
    assert not fz.oracle_clears(rep.breaches[0]["doc_value"])            # the counterexample really is a document that must fail


def test_the_fuzzer_catches_a_policy_that_lowers_the_verdict_text_but_keeps_the_pass():
    def keeps(cap, d, s, rec):
        ok = real_kind(d.get("doc_type")) and real_income(d.get("monthly_income_cents"))
        return Recommendation("pass", rec.reasons + ("re-checked",), rec.evidence) if rec.verdict == "pass" and not ok else rec
    assert fz.fuzz(CASES, seed=1, the_policy=keeps).breaches


def test_the_fuzzer_measures_over_blocking_without_calling_it_a_breach():
    strict = clears_with(real_kind, lambda n: isinstance(n, int) and not isinstance(n, bool) and n > 450_000)  # > not >=
    rep = fz.fuzz(CASES, seed=1, the_policy=strict)
    assert rep.breaches == [] and rep.overblocked > 0


def test_the_oracle_is_independent_and_strict_about_types():
    assert fz.oracle_clears({"doc_type": "paystub", "monthly_income_cents": 450_000})
    assert fz.oracle_clears({"doc_type": "tax-return", "monthly_income_cents": 512_000})
    for bad in ({"doc_type": "paystub", "monthly_income_cents": 449_999}, {"doc_type": "Paystub", "monthly_income_cents": 900_000},
                {"doc_type": "paystub", "monthly_income_cents": True}, {"doc_type": "paystub", "monthly_income_cents": 900_000.0},
                {"doc_type": "paystub", "monthly_income_cents": "900000"}, {"doc_type": "paystub"}, {"monthly_income_cents": 900_000},
                {"doc_type": "paystub\n", "monthly_income_cents": 900_000}, [], None):
        assert not fz.oracle_clears(bad)


def test_the_same_seed_gives_the_same_run():
    a, b = fz.fuzz(1000, seed=5), fz.fuzz(1000, seed=5)
    assert (a.judged, a.refused, a.final_passes, a.lowered) == (b.judged, b.refused, b.final_passes, b.lowered)
