"""interop/policy_differential.py: the harness must report agreement when two implementations agree and catch one that is wrong.

The "other implementation" here is a Python program that speaks the line protocol of docs/interop/POLICY_CHAIN_SPEC.md: the
reference itself (the harness must find no disagreement) and three deliberately broken variants (it must find each). This tests the
harness, its protocol and its comparison; a second implementation in another language is compared with the same harness by hand
(see the module docstring). Also checked: the committed examples file is exactly what the reference produces now.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "interop"))

import policy_differential as pd  # type: ignore[import-not-found]  # noqa: E402

REFERENCE = f"{sys.executable} {ROOT / 'interop' / 'policy_reference.py'}"

# A broken variant is the reference with one change, written as a tiny program that speaks the protocol.
VARIANT = '''
import base64, json, sys
sys.path.insert(0, {root!r}); sys.path.insert(0, {interop!r})
import policy_reference as ref
{patch}
for line in sys.stdin:
    r = json.loads(line)
    print(json.dumps(ref.run(r["doc"], base64.b64decode(r["answer_b64"]))), flush=True)
'''

PATCHES = {
    # the policy forgets the document check entirely
    "no re-check": "import live_providers as lp\nref.policy = lambda cap, d, s, rec: rec",
    # the policy compares the document type without case
    "type compared without case": (
        "import live_providers as lp\nfrom cns_interop.adapter import Recommendation\n"
        "def pol(cap, d, s, rec):\n"
        "    ok = str(d.get('doc_type')).lower() in ('paystub', 'tax-return') and type(d.get('monthly_income_cents')) is int "
        "and d.get('monthly_income_cents') >= 450000\n"
        "    return Recommendation('retry', rec.reasons, {}) if rec.verdict == 'pass' and not ok else rec\n"
        "ref.policy = pol"),
    # the reader accepts an answer with text before it (a lenient reader)
    "lenient reader": (
        "from cns_interop import adapter as ad\nimport re\n_orig = ad.parse_recommendation\n"
        "def lenient(raw, cap):\n"
        "    t = raw.decode('utf-8', 'replace') if isinstance(raw, bytes) else raw\n"
        "    m = re.search(r'\\{.*\\}', t, re.S)\n"
        "    return _orig(m.group(0) if m else t, cap)\n"
        "ad.parse_recommendation = lenient"),
}


def write_variant(tmp_path, patch: str) -> str:
    path = tmp_path / "variant.py"
    path.write_text(VARIANT.format(root=str(ROOT), interop=str(ROOT / "interop"), patch=patch))
    return f"{sys.executable} {path}"


def test_the_reference_agrees_with_itself_through_the_protocol_on_random_cases(capsys):
    assert pd.compare(REFERENCE, cases=1500, seed=3, out=None) == 0
    assert "disagree 0" in capsys.readouterr().out


@pytest.mark.parametrize("name", list(PATCHES))
def test_the_harness_finds_each_deliberately_broken_implementation(tmp_path, name, capsys):
    out = tmp_path / "d.json"
    assert pd.compare(write_variant(tmp_path, PATCHES[name]), cases=3000, seed=3, out=str(out)) == 1, name
    assert json.loads(out.read_text()), name                       # and it wrote the disagreements down


def test_the_committed_examples_are_exactly_what_the_reference_produces_now():
    committed = json.loads((ROOT / "docs" / "interop" / "policy_examples.json").read_text(encoding="utf-8"))
    assert committed == json.loads(json.dumps(pd.example_cases(), ensure_ascii=False))


def test_the_reference_agrees_with_every_hand_written_example_through_the_protocol(capsys):
    assert pd.run_examples(REFERENCE, str(ROOT / "docs" / "interop" / "policy_examples.json")) == 0
    assert "examples agree" in capsys.readouterr().out


def test_the_generators_stay_inside_the_specs_document_precondition():
    for doc, ans in pd.generate(3000, 9):
        def walk(v):
            assert not isinstance(v, float)
            if isinstance(v, int) and not isinstance(v, bool):
                assert abs(v) <= 2 ** 53 - 1
            if isinstance(v, str):
                assert not any(0xD800 <= ord(c) <= 0xDFFF for c in v)
            if isinstance(v, list):
                [walk(x) for x in v]
            if isinstance(v, dict):
                [walk(k) or walk(x) for k, x in v.items()]
        walk(doc)
        assert isinstance(ans, bytes)


def test_an_answer_is_base64_clean_for_any_bytes():
    assert base64.b64decode(base64.b64encode(b"\xff\xfe\x00abc")) == b"\xff\xfe\x00abc"
