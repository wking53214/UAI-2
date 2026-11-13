"""interop/live_signing.py: the full signed exchange per model and document, checked by Node as well.

Stand-in servers play the models here (no key, no network): an honest one, one that says pass to everything, one that sends
garbage. The tests check that a signed decision is produced for every case, that Node accepts each signature, and that no
model, however it answers, gets a signed pass for a document that does not clear.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "interop"))

import live_signing as ls  # type: ignore[import-not-found]  # noqa: E402
from jury import jurors_from_env  # type: ignore[import-not-found]  # noqa: E402
from test_provider_layer import serving  # type: ignore[import-not-found]  # noqa: E402


def disclosed(prompt):
    return json.loads(prompt.split("DISCLOSED ", 1)[1].split("\n", 1)[0]) if "DISCLOSED " in prompt else {}


def says(verdict, evidence=True):
    def model(prompt):
        return json.dumps({"verdict": verdict, "reasons": ["stand-in"], "escalate": False,
                           "evidence": {"threshold-check": {"stand_in": 1}} if evidence and verdict == "pass" else {}})
    return model


def honest(prompt):
    d = disclosed(prompt)
    inc = d.get("monthly_income_cents")
    ok = d.get("doc_type") in ("paystub", "tax-return") and type(inc) is int and inc >= 450_000
    return says("pass" if ok else "retry")(prompt)


def run_against(tmp_path, model):
    stub = serving("groq", model)
    try:
        jurors = jurors_from_env({"GROQ_API_KEY": "k" * 20, "GROQ_MODEL": "stand-in"}, [], stub.url)
        out = tmp_path / "rows.jsonl"
        code = ls.run(jurors, str(out), spacing=0.0)
        return code, [json.loads(line) for line in out.read_text().splitlines()]
    finally:
        stub.close()


def test_an_honest_model_gets_every_document_a_signed_decision_that_both_implementations_accept(tmp_path, capsys):
    code, rows = run_against(tmp_path, honest)
    assert code == 0 and len(rows) == len(ls.DOCUMENTS)
    for r in rows:
        assert r["verdict"] == r["expect"], r["name"]
        assert r["signed_by_decider"] and r["node_check"] == "accept" and not r["breach"], r["name"]
        assert r["decision_wire"]["kind"] == "decision" and r["decision_wire"]["from"] == r["decider"]
    assert {r["verdict"] for r in rows} == {"pass", "retry"}
    assert "BREACHES (a signed pass for a document that does not clear): 0" in capsys.readouterr().out


def test_a_model_that_says_pass_to_everything_never_gets_a_signed_pass_for_a_document_that_does_not_clear(tmp_path):
    code, rows = run_against(tmp_path, says("pass"))
    assert code == 0
    for r in rows:
        assert r["model_verdict"] == "pass", r["name"]
        assert r["allowed"] == (r["expect"] == "pass"), r["name"]            # the policy lowered every wrong pass, signed
        assert r["node_check"] == "accept" and not r["breach"]


@pytest.mark.parametrize("garbage", ["I think this is fine.", "{}", "```json\n{}\n```", '{"verdict":"pass"}'])
def test_an_unreadable_answer_becomes_a_signed_terminal_breach_not_a_pass(tmp_path, garbage):
    code, rows = run_against(tmp_path, lambda prompt: garbage)
    assert code == 0
    for r in rows:
        assert r["verdict"] == "terminal_breach" and not r["allowed"] and r["node_check"] == "accept", r["name"]


def test_a_tampered_decision_is_refused_by_node(tmp_path):
    _, rows = run_against(tmp_path, honest)
    wire = json.loads(json.dumps(rows[0]["decision_wire"]))
    wire["body"]["verdict"] = "pass" if wire["body"].get("verdict") != "pass" else "retry"
    node = ls.Node()
    try:
        got = node.check(wire, now=wire["issued_at"] + 1000, audience=rows[0]["requester"], decider=rows[0]["decider"])
    finally:
        node.close()
    assert got == "signature"


def test_the_summary_exit_code_is_one_on_a_breach(tmp_path):
    p = tmp_path / "r.jsonl"
    p.write_text(json.dumps({"juror": "x", "name": "n", "verdict": "pass", "allowed": True, "breach": True, "node_check": "accept",
                             "decision_wire": {}, "signed_by_decider": True, "matches_expect": False}) + "\n")
    assert ls.summarize(str(p)) == 1


def test_recheck_verifies_every_signed_decision_in_a_rows_file_again_and_fails_on_a_tampered_one(tmp_path, capsys):
    _, rows = run_against(tmp_path, honest)
    good = tmp_path / "good.jsonl"
    good.write_text("".join(json.dumps(r) + "\n" for r in rows))
    assert ls.recheck(str(good)) == 0
    assert f"Python reader accepted {len(rows)} of {len(rows)}; Node accepted {len(rows)} of {len(rows)}" in capsys.readouterr().out

    bad_rows = json.loads(json.dumps(rows))
    wire = bad_rows[0]["decision_wire"]
    wire["body"]["verdict"] = "pass" if wire["body"].get("verdict") != "pass" else "retry"      # an edit after signing
    bad_rows[1]["decider"] = bad_rows[1]["requester"]                                            # a row naming the wrong signer
    bad = tmp_path / "bad.jsonl"
    bad.write_text("".join(json.dumps(r) + "\n" for r in bad_rows))
    assert ls.recheck(str(bad)) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out and out.count("FAILED") == 2


def test_recheck_of_a_file_with_no_signed_decision_fails(tmp_path):
    empty = tmp_path / "e.jsonl"
    empty.write_text(json.dumps({"juror": "x", "name": "n", "verdict": "failed:Refused"}) + "\n")
    assert ls.recheck(str(empty)) == 1
