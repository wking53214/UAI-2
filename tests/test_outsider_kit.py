"""The UAI-1 implementer kit (contracts/uai1/build_kit.py): what it contains, what it must not, and that it works on its own.

This holds the PACKAGE. It does not show that anyone outside the project can implement UAI-1 from it; nobody has tried yet.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "contracts" / "uai1"))

import build_kit  # type: ignore[import-not-found]  # noqa: E402

SUITE = json.loads((ROOT / "contracts" / "uai1" / "conformance-suite.json").read_text(encoding="utf-8"))


def _extract(tmp_path: Path) -> Path:
    z = tmp_path / "kit.zip"
    z.write_bytes(build_kit.build())
    out = tmp_path / "kit"
    with zipfile.ZipFile(z) as zf:
        zf.extractall(out)
    return out / "uai1-kit"


def test_the_kit_is_built_the_same_way_every_time():
    assert build_kit.build() == build_kit.build()


def test_the_kit_holds_the_documents_and_no_implementation_source(tmp_path):
    kit = _extract(tmp_path)
    names = {str(p.relative_to(kit)) for p in kit.rglob("*") if p.is_file()}
    assert set(build_kit.FILES) | {"KIT_README.md", "MANIFEST.sha256"} == names
    py = {n for n in names if n.endswith((".py", ".mjs", ".js", ".go", ".rs"))}
    assert py == {"contracts/uai1/run_conformance.py"}, f"the kit must hold no implementation, found {sorted(py)}"
    for n in names:
        assert not n.startswith(("cns_interop", "interop")), n
    # The runner is standard library only: nothing in it imports the project's own packages.
    runner = (kit / "contracts/uai1/run_conformance.py").read_text(encoding="utf-8")
    assert not re.search(r"^\s*(from|import)\s+(cns|cns_interop|uai|interop)\b", runner, re.M)


def test_every_manifest_hash_matches_its_file(tmp_path):
    kit = _extract(tmp_path)
    lines = (kit / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
    listed = {}
    for line in lines:
        digest, name = line.split("  ", 1)
        listed[name] = digest
    assert set(listed) == {str(p.relative_to(kit)) for p in kit.rglob("*") if p.is_file() and p.name != "MANIFEST.sha256"}
    for name, digest in listed.items():
        assert hashlib.sha256((kit / name).read_bytes()).hexdigest() == digest, name


def test_the_kits_own_runner_checks_the_reference_adapter_with_nothing_else_from_the_repository(tmp_path):
    """Run the runner from inside the extracted kit, on the kit's own copy of the suite, against the Python reference adapter."""
    kit = _extract(tmp_path)
    adapter = ROOT / "interop" / "conformance" / "reference_adapter.py"
    res = subprocess.run([sys.executable, "-I", str(kit / "contracts/uai1/run_conformance.py"), "--cmd", f"{sys.executable} {adapter}",
                          "--suite", str(kit / "contracts/uai1/conformance-suite.json"), "--json"],
                         capture_output=True, text=True, cwd=kit, timeout=300)
    assert res.returncode == 0, res.stdout[-800:] + res.stderr[-800:]
    assert str(len(SUITE["cases"])) in res.stdout


def test_files_the_guide_names_are_in_the_kit_or_named_as_left_out():
    guide = (ROOT / "docs/interop/implementers/README.md").read_text(encoding="utf-8")
    table = guide.split("## What you get", 1)[1].split("## Minimal implementation", 1)[0]
    named = set(re.findall(r"`((?:docs|contracts|interop)/[^`]+)`", table))
    assert named, "the guide's file table could not be read"
    for n in sorted(named):
        in_kit = n in build_kit.FILES
        excluded = any(n.startswith(e) or n == e for e in build_kit.EXCLUDED)
        assert in_kit or excluded or n == "contracts/uai1/build_kit.py", f"{n} is named by the guide but is neither in the kit nor listed as left out"


def test_no_prose_states_a_case_count_other_than_the_suites():
    n = len(SUITE["cases"])
    for rel in ("README.md", "docs/interop/implementers/README.md"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        counts = {int(x) for x in re.findall(r"\b(\d+)[- ]cases?\b", text)}
        assert counts <= {n}, f"{rel} states case counts {sorted(counts)}, the suite has {n}"


def test_every_section_the_suite_points_to_exists_in_the_specification():
    spec = (ROOT / "docs/interop/UAI-1.md").read_text(encoding="utf-8")
    headings = set(re.findall(r"^## (\d+)[a-z]?\.", spec, re.M))
    for case in SUITE["cases"]:
        for sec in re.findall(r"UAI-1\.md section (\d+)", case.get("spec", "")):
            assert sec in headings, f"{case['name']} points to section {sec}, which UAI-1.md does not have"
