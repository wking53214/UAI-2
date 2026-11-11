"""The independent interoperability campaign.

contracts/uai-interop-vectors.json holds every expected result, typed by hand with its reason, and signatures made by
the OpenSSL command line. This test runs it through the Python reference AND the Node implementation, then asks
three separate questions: does each match the hand-written expectation, do the two agree with each other, and is the
answer key itself still what its generator produces. A failure here is a finding about an implementation, never
something to fix by regenerating the vectors.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from interop import campaign  # type: ignore[import-not-found]  # noqa: E402

VECTORS = json.loads((ROOT / "contracts" / "uai-interop-vectors.json").read_text(encoding="utf-8"))
GROUPS = ("digest", "wire", "envelope", "negotiation", "sequences", "decisions")
CASES = {c["id"]: (g, c) for g in GROUPS for c in VECTORS[g]}


@pytest.fixture(scope="module")
def reports():
    node = shutil.which("node")
    assert node, "node is not on PATH; the second implementation cannot be run (install Node 20+)"
    done = subprocess.run([node, str(ROOT / "interop" / "node" / "campaign.mjs")], capture_output=True, text=True,
                          timeout=300)
    assert done.returncode == 0, done.stderr[-3000:]
    return {"python": campaign.run_all(VECTORS), "node": json.loads(done.stdout)}


def expected_ok(group, case, got):
    exp = case.get("expect", {})
    if group == "digest":
        assert got == {"outcome": "ok", "canonical": case["canonical"], "sha256": case["sha256"]}
    elif group == "negotiation":
        if exp["outcome"] == "ok":
            assert got == {"outcome": "ok", "terms": exp["terms"]}
        else:
            assert got["outcome"] == "refuse" and got["code"] in exp["codes"], got
    elif group in ("sequences", "decisions"):
        wanted = [s["expect"] for s in case["steps"]]
        assert got["steps"] == wanted, f"expected {wanted}, got {got['steps']}"
    else:
        if exp["outcome"] == "ok":
            assert got == {"outcome": "ok"}, got
        else:
            assert got["outcome"] == "refuse" and got["code"] in exp["codes"], got


@pytest.mark.parametrize("impl", ["python", "node"])
@pytest.mark.parametrize("case_id", sorted(CASES))
def test_each_implementation_matches_the_hand_written_expectation(impl, case_id, reports):
    group, case = CASES[case_id]
    try:
        expected_ok(group, case, reports[impl][case_id])
    except AssertionError as exc:
        raise AssertionError(f"{impl} on {case_id} ({case['why']}): {exc}") from None


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_the_two_implementations_agree_with_each_other_exactly_including_refusal_codes(case_id, reports):
    assert reports["python"][case_id] == reports["node"][case_id], case_id


def test_the_campaign_covers_what_the_assignment_names():
    ids = " ".join(CASES)
    for needle in ("duplicate-key", "nfd", "key-order", "float", "missing-field", "unknown-field", "one-byte-over",
                   "invalid-utf8", "algorithm-substitution", "expired", "self-revocation", "audience-mismatch",
                   "capability-mismatch", "replay", "version-two", "retry-verdict", "rotation"):
        assert needle in ids, f"no case for {needle}"
    assert len(CASES) >= 130


def test_every_case_has_a_reason_and_the_expected_results_were_not_copied_from_an_implementation():
    for cid, (group, case) in CASES.items():
        assert case["why"].strip(), cid
    # The hand-written canonical text of every digest case equals what the generator's own encoder makes of the text.
    for case in VECTORS["digest"]:
        assert case["canonical"] and case["sha256"]


def test_the_committed_answer_key_is_what_its_generator_makes_now():
    openssl = shutil.which("openssl")
    assert openssl, "openssl is not on PATH; the answer key's signatures cannot be re-made"
    done = subprocess.run([sys.executable, str(ROOT / "interop" / "vectors" / "make_interop_vectors.py"), "--check"],
                          capture_output=True, text=True, timeout=300)
    assert done.returncode == 0, done.stderr


def test_the_generator_imports_nothing_from_the_implementations_it_checks():
    src = (ROOT / "interop" / "vectors" / "make_interop_vectors.py").read_text(encoding="utf-8")
    code = "\n".join(ln for ln in src.splitlines() if ln.lstrip().startswith(("import ", "from ")))
    for forbidden in ("cns", "cns_composition", "cns_interop"):
        assert f"import {forbidden}" not in code and f"from {forbidden}" not in code
