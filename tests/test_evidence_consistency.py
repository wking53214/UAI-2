"""The repository's evidence must agree with itself, and CI is where that is checked.

1. Every file under evidence/live-runs/<run>/ has its SHA-256 written in that run's README, and every SHA-256 written
   in a README belongs to a file in the same folder. An edited or swapped evidence file, or a README that was
   not updated, fails here.
2. The conformance step names in .github/workflows/ci.yml and the case count in docs/EVIDENCE.md equal the number of
   cases in the published suite, so a label cannot go stale when cases are added.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "evidence" / "live-runs"
HEX64 = re.compile(r"\b[0-9a-f]{64}\b")


def _run_dirs():
    return sorted(d for d in RUNS.iterdir() if d.is_dir())


def test_every_evidence_file_matches_the_hash_its_readme_records():
    assert _run_dirs(), "no evidence folders found"
    for run in _run_dirs():
        recorded = set(HEX64.findall((run / "README.md").read_text(encoding="utf-8")))
        actual = {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in run.iterdir() if f.name != "README.md"}
        assert actual, f"{run.name}: no evidence files"
        for name, digest in actual.items():
            assert digest in recorded, f"{run.name}/{name}: SHA-256 {digest} is not recorded in the README"
        for digest in recorded:
            assert digest in actual.values(), f"{run.name}: README records {digest}, which is no file in the folder"


def test_conformance_labels_match_the_suite_size():
    suite = json.loads((ROOT / "contracts" / "uai1" / "conformance-suite.json").read_text(encoding="utf-8"))
    n = len(suite["cases"])
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    labels = [int(x) for x in re.findall(r"(\d+)[- ]case", ci)]
    assert labels, "ci.yml no longer states a case count"
    assert set(labels) == {n}, f"ci.yml says {sorted(set(labels))} cases, the suite has {n}"
    evidence = (ROOT / "docs" / "EVIDENCE.md").read_text(encoding="utf-8")
    m = re.search(r"conformance (\d+) of (\d+)", evidence)
    assert m and int(m.group(1)) == int(m.group(2)) == n, f"EVIDENCE.md last-run line does not say {n} of {n}"
