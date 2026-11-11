"""The documented examples run, and print what the documentation says they print. A published example that no longer runs
is a false claim, so these are part of the suite."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CLEAN = {k: v for k, v in os.environ.items() if not k.endswith(("_API_KEY", "_MODEL")) and k not in ("GITHUB_MODELS_TOKEN", "COPILOT_MODEL")}


def run(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, env=CLEAN, timeout=120)


def test_the_python_quickstart_runs_and_a_second_use_of_the_decision_is_refused():
    done = run(sys.executable, "interop/examples/quickstart.py")
    assert done.returncode == 0, done.stderr
    assert "decision: pass" in done.stdout and "the ssn never left" in done.stdout
    assert "acting on the judged document: True" in done.stdout
    assert "acting on the same decision a second time: False" in done.stdout


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_the_node_quickstart_runs_and_the_receivers_grant_permits_the_action():
    done = run("node", "interop/examples/quickstart.mjs")
    assert done.returncode == 0, done.stderr
    assert "acting on the judged document: true" in done.stdout and "permit: g1 release-funds" in done.stdout


def test_the_provider_example_says_not_executed_without_keys_and_never_claims_a_live_call():
    done = run(sys.executable, "interop/examples/provider_adapter.py")
    assert done.returncode == 0, done.stderr
    assert done.stdout.count("NOT EXECUTED") == 4
    assert "live provider call: False" in done.stdout and "local-stand-in" in done.stdout
