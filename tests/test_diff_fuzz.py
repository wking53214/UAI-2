"""A short differential fuzz of the Python and Node UAI-1 readers (interop/diff_fuzz.py). Both are written inside this project."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "interop"))

import diff_fuzz  # type: ignore[import-not-found]  # noqa: E402



def test_python_and_node_never_disagree_about_accept_or_refuse_on_mutated_messages():
    rep = diff_fuzz.run(seed=11, per_case=12)
    assert rep["comparisons"] == 12 * len(diff_fuzz.SUITE)
    assert rep["accept_vs_refuse_disagreements"] == [], rep["accept_vs_refuse_disagreements"][:2]
    assert rep["first_accepts"] > 0                       # some mutants still verify (harmless edits), so accepts are being compared


def test_the_fuzz_can_fail_a_reader_that_accepts_everything_is_reported(tmp_path):
    stub = tmp_path / "accept_all.py"
    stub.write_text("import sys, json\nfor line in sys.stdin:\n"
                    "    r = json.loads(line)\n"
                    "    print(json.dumps({'ok': True} if r['op'] == 'reset' else {'accept': {'digest': '00'}}), flush=True)\n")
    ref = [sys.executable, str(diff_fuzz.ROOT / "interop/conformance/reference_adapter.py")]
    rep = diff_fuzz.run(seed=11, per_case=4, cmds=[ref, [sys.executable, str(stub)]])
    assert rep["ok"] is False and rep["accept_vs_refuse_disagreements"]
