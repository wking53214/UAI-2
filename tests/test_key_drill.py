"""The SIMULATED key-compromise drill (interop/key_drill.py) and its recorded report. Software only: this is not an operational drill."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "interop"))

import key_drill  # type: ignore[import-not-found]  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / "evidence" / "drills" / "2026-11-17-key-drill"


def test_every_scenario_does_what_the_custody_procedure_relies_on():
    rep = key_drill.run()
    failed = [s for s in rep["scenarios"] if not s["ok"]]
    assert not failed, [(s["scenario"], s["expected"], s["observed"]) for s in failed]
    assert rep["ok"] is True and len(rep["scenarios"]) == 9


def test_a_scenario_whose_observation_differs_is_reported_as_failed(monkeypatch):
    """The drill can fail: if the compromised key were still admitted after the authority's revoke, the report says so."""
    monkeypatch.setattr(key_drill, "SCENARIOS", [lambda tmp: {"expected": {"x": "untrusted"}, "observed": {"x": "pinned"}}])
    monkeypatch.setattr(key_drill.SCENARIOS[0], "__name__", "fake", raising=False)
    rep = key_drill.run()
    assert rep["ok"] is False and rep["scenarios"][0]["ok"] is False


def test_the_report_is_reproducible_and_matches_the_recorded_file_and_its_hash():
    text = json.dumps(key_drill.run(), indent=2, sort_keys=True) + "\n"
    recorded = (FOLDER / "key-drill.json").read_bytes()
    assert text.encode() == recorded, "the drill's report changed; re-run it and update the evidence folder"
    digest = hashlib.sha256(recorded).hexdigest()
    assert digest in set(re.findall(r"\b[0-9a-f]{64}\b", (FOLDER / "README.md").read_text(encoding="utf-8")))
