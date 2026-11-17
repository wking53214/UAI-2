"""Offline regression over the committed live jury rows. No provider is called and no key is read.

What this holds: the recorded runs and the CURRENT code still agree. The policy in `interop/live_providers.py` is replayed on
every recorded wrong-pass recommendation, the recorded document names and expected verdicts must still match the corpus in
`interop/jury.py`, and the totals stated in the evidence READMEs are recomputed from the rows.

What it does NOT show: how any model answers today, or how a model answers the current prompt. The rows were recorded before
the prompt change of PR #31 (verdict definitions), so they say nothing about it; only a new live run can.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "interop"))

import jury  # type: ignore[import-not-found]  # noqa: E402
import live_providers  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.adapter import Recommendation  # noqa: E402

RUNS = Path(__file__).resolve().parents[1] / "evidence" / "live-runs"
FILES = {"2026-11-11-raw": ["jury.jsonl", "jury-2.jsonl", "jury-3.jsonl"], "2026-11-13-free-panel": ["jury-4.jsonl"],
         "2026-11-17-jury-current-prompt": ["jury-5.jsonl"]}
CORPUS = {name: (kind, disclosed, expect) for kind, name, disclosed, expect in jury.documents()}


def _rows(run: str):
    return [json.loads(line) for f in FILES[run] for line in (RUNS / run / f).read_text(encoding="utf-8").splitlines() if line.strip()]


ALL = _rows("2026-11-11-raw") + _rows("2026-11-13-free-panel") + _rows("2026-11-17-jury-current-prompt")


def test_every_recorded_document_is_still_in_the_corpus_with_the_same_expected_verdict():
    for r in ALL:
        assert r["name"] in CORPUS, f"recorded document {r['name']} is no longer in jury.documents()"
        kind, _, expect = CORPUS[r["name"]]
        assert (r["kind"], r["expect"]) == (kind, expect), f"{r['name']}: recorded {(r['kind'], r['expect'])}, corpus {(kind, expect)}"


def test_the_current_policy_still_lowers_every_wrong_pass_a_model_recommended():
    fooled = [r for r in ALL if r["model_verdict"] == "pass" and r["expect"] != "pass"]
    assert len(fooled) > 26, "the recorded runs should contain more than the 26 of the clean rerun"
    for r in fooled:
        _, disclosed, _ = CORPUS[r["name"]]
        out = live_providers.policy(live_providers.CAP, dict(disclosed), None, Recommendation("pass", ("recorded",), {}))
        assert out.verdict != "pass", f"{r['juror']} on {r['name']}: the current policy lets a recorded wrong pass stand"
        assert r["verdict"] != "pass" and r["policy_lowered"] and not r["breach"]


def test_the_current_policy_never_passes_a_document_that_does_not_clear_whatever_is_recommended():
    for name, (_, disclosed, expect) in CORPUS.items():
        for verdict in ("pass", "retry", "terminal_breach", "escalate"):
            out = live_providers.policy(live_providers.CAP, dict(disclosed), None, Recommendation(verdict, ("x",), {}))
            if expect != "pass":
                assert out.verdict != "pass", f"{name}: a {verdict} recommendation became a pass"


def test_row_flags_agree_with_the_row_verdicts_and_there_are_no_breaches():
    for r in ALL:
        assert r["breach"] is (r["verdict"] == "pass" and r["expect"] != "pass")
        assert r["policy_lowered"] is (r["model_verdict"] == "pass" and r["verdict"] != "pass")
        assert r["breach"] is False, f"{r['juror']} {r['name']} round {r['round']}"


def test_the_totals_the_evidence_readmes_state_are_recomputed_from_the_rows():
    raw = _rows("2026-11-11-raw")
    assert len(raw) == 3698                                              # README: 3,698 rows over three runs
    assert sum(1 for r in raw if r["http_status"] == 200) == 1679          # README: the provider answered (HTTP 200) on 1,679
    free = _rows("2026-11-13-free-panel")
    assert len(free) == 315
    assert sum(1 for r in free if not r["verdict"].startswith("refused")) == 294
    assert sum(1 for r in free if r["model_verdict"] == "pass" and r["expect"] != "pass") == 26
    assert sum(1 for r in free if r["policy_lowered"] and r["expect"] != "pass") == 26


def test_the_totals_the_current_prompt_run_readme_states_are_recomputed_from_its_rows():
    """evidence/live-runs/2026-11-17-jury-current-prompt/README.md: one round, seven models, three providers, no breach, $0."""
    rows = _rows("2026-11-17-jury-current-prompt")
    run = [r for r in rows if r["round"] != -1]
    assert len(rows) == 161 and len(run) == 154 and len(rows) - len(run) == 7           # 7 preflight rows, 7 jurors x 22 documents
    assert {r["round"] for r in run} == {0}                                              # one round, not the two the plan asks for
    assert len({r["juror"] for r in rows}) == 7 and {r["provider"] for r in rows} == {"groq", "cloudflare-workers-ai", "openrouter"}
    assert all(r["http_status"] == 200 for r in rows)
    assert sum(1 for r in run if r["model_verdict"] is not None) == 147               # README: 147 readable of 154
    wrong = [r for r in run if r["model_verdict"] == "pass" and r["expect"] != "pass"]
    assert len(wrong) == 8 and all(r["policy_lowered"] and not r["breach"] for r in wrong)
    assert not any(r["breach"] for r in rows)
    assert all(not r["cost_usd"] for r in rows) and not any(r["provider"] == "anthropic" for r in rows)       # README: $0, no Anthropic
    assert {r["juror"] for r in wrong} == {"groq:allam-2-7b", "cloudflare-workers-ai:@cf/meta/llama-3.3-70b-instruct-fp8-fast",
                                           "cloudflare-workers-ai:@cf/nvidia/nemotron-3-120b-a12b"}
