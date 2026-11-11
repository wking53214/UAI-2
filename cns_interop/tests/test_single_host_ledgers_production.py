"""Under the production profile, the single-host ledgers are refused at construction, in a fresh process.

The audit's approval-reuse gap: a process that builds its own file ledger accepts an approval another process already
spent. Under the production profile that construction is now refused, so the gap cannot be reached by configuration
that claims to be production. The default profile is unchanged, and the spine still records the gap there.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _run(code, **env):
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=ROOT,
                          env={**os.environ, **env}, timeout=60)


@pytest.mark.parametrize("ledger", ["FileLedger", "SqliteLedger"])
def test_a_single_host_ledger_is_refused_under_the_production_profile(ledger, tmp_path):
    code = (f"from cns_interop.ledger import {ledger}\n"
            f"try:\n {ledger}({str(tmp_path / 'x')!r})\n"
            "except RuntimeError as e:\n print('refused:', e)\n")
    done = _run(code, UAI_PROFILE="production", UAI_CRYPTO_BACKEND="cryptography")
    assert done.returncode == 0 and "refused:" in done.stdout and "PostgresLedger" in done.stdout, done.stderr


@pytest.mark.parametrize("ledger", ["FileLedger", "SqliteLedger"])
def test_the_default_profile_still_builds_a_single_host_ledger(ledger, tmp_path):
    code = (f"from cns_interop.ledger import {ledger}\n"
            f"{ledger}({str(tmp_path / 'x')!r})\nprint('built')\n")
    done = _run(code)
    assert done.returncode == 0 and "built" in done.stdout, done.stderr
