"""Two independent systems, in two languages, made to talk to each other through interop/demo.py.

Node is required. If it is missing these tests fail and say so (see test_uai_vectors.py).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def demo():
    assert shutil.which("node"), "node is not on PATH; the demo needs the second implementation"
    done = subprocess.run([sys.executable, str(ROOT / "interop" / "demo.py"), "--json"], capture_output=True,
                          text=True, timeout=300)
    assert done.returncode == 0, done.stderr[-4000:]
    return json.loads(done.stdout)


def test_python_requests_node_decides_and_python_verifies(demo):
    r = demo["node_decides"]
    assert r["verdict"] == "pass" and r["allowed"] and r["signer"] == r["node_agent"]
    assert r["terms"]["disclose"] == ["doc_type", "monthly_income_cents"]
    assert r["accept_disclosed"] == ["doc_type", "monthly_income_cents"]
    assert set(r["never_sent"]) == {"account_number", "employer", "full_name"}
    assert r["evidence"]["threshold-check"]["observed_cents"] == 512_000


def test_a_third_process_acts_once_on_the_one_document(demo):
    r = demo["node_decides"]
    assert r["act_first"]["permitted"] is True and r["act_first"]["permit"]["grant"] == "demo-ingest"  # under policy (T0-5)
    assert r["act_second"]["refused"]["code"] == "replayed"
    assert r["act_other"] == {"permitted": False}
    assert r["act_impostor"]["refused"]["code"] == "untrusted"  # the job cannot choose its own decider


def test_the_rails_hold_across_the_language_boundary(demo):
    r = demo["node_decides"]
    assert r["replay"]["uai_error"]["code"] == "replayed"
    assert r["tamper"] == "signature"
    assert r["bad_doc_verdict"] == "retry"
    assert r["withheld"].startswith("declined")
    p = demo["python_decides"]
    assert p["stranger_reply"] == "dropped" and "not one this receiver deals with" in p["stranger_reason"]  # T2-1


def test_node_requests_a_cns_super_gate_decides_and_node_verifies(demo):
    p = demo["python_decides"]["result"]
    assert p["verified_by"] == "node/uai.mjs" and p["verdict"] == "pass" and p["allowed"]
    assert p["signer"] == demo["python_decides"]["decider"]
    assert len(p["cns_root"]) == 64 and p["evidence"]["threshold-check"]["roster_root"] == p["cns_root"]
    assert p["disclosed"] == ["doc_type", "monthly_income_cents"]  # the Node requester's full_name stayed home
