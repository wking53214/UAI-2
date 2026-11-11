"""Two implementations that share no code, held to one answer key.

Node is required. If it is missing these tests fail and say so: a cross-implementation claim that quietly stops
being checked is exactly the kind of gap conftest.py exists to prevent.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from cns_interop import vectors, wire
from cns_interop.disclosure import commit, open_disclosure
from cns_interop.envelope import Refused, check_profile, open_envelope
from cns_interop.identity import Signer
from cns_interop.negotiate import terms_digest

ROOT = Path(__file__).resolve().parents[2]
NODE = shutil.which("node")
V = json.loads(vectors.PATH.read_text(encoding="utf-8"))


def node() -> str:
    assert NODE, "node is not on PATH; the second UAI-1 implementation cannot be checked (install Node 20+)"
    return NODE


def test_the_committed_vectors_are_what_the_reference_produces_now():
    assert vectors.PATH.read_text(encoding="utf-8") == vectors.render(), \
        "contracts/uai-vectors.json is stale: python -m cns_interop.vectors --write"


def test_the_python_reference_passes_its_own_answer_key():
    for name, s in V["seeds"].items():
        assert Signer(bytes.fromhex(s["seed"])).agent == s["agent"], name
    for e in V["envelopes"]:
        env = open_envelope(e["wire"], now=e["wire"]["issued_at"])
        assert env.digest == e["digest"], e["name"]
    for r in V["rejections"]:
        with pytest.raises(Refused) as caught:
            open_envelope(r["wire"], now=r["now"])
        assert caught.value.code == r["code"], r["name"]
    for w in V["wire_text"]:
        with pytest.raises(Refused) as caught:
            check_profile(wire.loads(w["text"]))
        assert caught.value.code == w["code"], w["name"]
    d = V["disclosure"]
    assert commit(d["identity"], d["values"], d["salts"]).digest == d["digest"]
    assert open_disclosure(d["digest"], d["reveal"], ["doc_type", "monthly_income_cents"])["doc_type"] == "paystub"
    assert terms_digest(V["terms"]["terms"]) == V["terms"]["digest"]


def test_the_node_implementation_passes_the_same_answer_key():
    tests = [str(ROOT / "interop" / "node" / name) for name in ("test.mjs", "agent.test.mjs", "revocation.test.mjs", "grants.test.mjs")]
    done = subprocess.run([node(), "--test", "--test-reporter=tap", *tests], capture_output=True, text=True, timeout=180)
    assert done.returncode == 0, done.stdout[-4000:] + done.stderr[-2000:]
    assert "# fail 0" in done.stdout and "# pass 37" in done.stdout


def test_the_node_small_order_list_is_exactly_the_curves_eight_torsion_points():
    import re

    from cns_interop import ed25519 as e

    torsion = set()
    for i in range(64):
        for j in range(64):
            try:
                point = e._decompress(bytes([i, j]) * 16)
                break
            except ValueError:
                continue
        torsion.add(e._compress(e._mul(e._L, point)).hex())
    js = (ROOT / "interop" / "node" / "uai.mjs").read_text(encoding="utf-8")
    listed = set(re.findall(r'"([0-9a-f]{64})"', js[js.index("SMALL_ORDER"):js.index("]);", js.index("SMALL_ORDER"))]))
    assert len(torsion) == 8 and listed == torsion


def test_no_small_order_key_verifies_in_the_python_reference():
    from cns_interop import ed25519 as e

    assert not e.verify(bytes.fromhex("01" + "00" * 31), b"anything", bytes.fromhex("01" + "00" * 63))


def test_cns_interop_imports_only_cns_cns_composition_itself_and_the_standard_library():
    import ast

    allowed = set(sys.stdlib_module_names) | {"cns", "cns_composition", "cns_interop", "__future__"}
    for path in (ROOT / "cns_interop").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for n in ast.walk(tree):
            names = [a.name for a in n.names] if isinstance(n, ast.Import) else \
                [n.module or ""] if isinstance(n, ast.ImportFrom) and n.level == 0 else []
            for name in names:
                # Step S5: the one optional third-party import, in the one backend file, inside a function.
                optional = (path.name == "crypto_backend.py" and name.split(".")[0] == "cryptography") or (
                    path.name == "ledger_postgres.py" and name.split(".")[0] == "psycopg")  # T1-3: the other one, also lazy
                assert name.split(".")[0] in allowed or optional, f"{path.name} imports {name}"


def test_cns_never_imports_cns_interop():
    for path in (ROOT / "cns").glob("*.py"):
        assert "cns_interop" not in path.read_text(encoding="utf-8"), path.name
