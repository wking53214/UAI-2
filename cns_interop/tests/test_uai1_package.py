"""The independent-implementer package (contracts/uai1/): schema, error registry and conformance suite.

What this shows: the JSON Schema accepts every envelope and body the reference produces in a live exchange and rejects the
structural defects (and only those: it cannot see signatures, time, digests or replay, and a test says so); the error
registry covers every code either implementation can emit; the published conformance suite is current, both shipped
implementations pass it through the stand-alone runner, and the runner FAILS an implementation that accepts everything or
refuses everything. What it does NOT show: that a third-party implementation conforms. None has been run."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import jsonschema  # type: ignore[import-untyped]
import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_act_policy import grants_file  # type: ignore[import-not-found]  # noqa: E402
from test_session import ACT_PY, act_job, pair, run  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.envelope import now_ms  # noqa: E402

ROOT = ACT_PY.parents[1]
PKG = ROOT / "contracts" / "uai1"
SCHEMA = json.loads((PKG / "schema.json").read_text())
VECTORS = json.loads((ROOT / "contracts" / "uai-vectors.json").read_text())


def valid(defn: str, instance) -> bool:
    ref = {"$ref": f"#/$defs/{defn}", "$defs": SCHEMA["$defs"]}
    try:
        jsonschema.Draft202012Validator(ref).validate(instance)
        return True
    except jsonschema.ValidationError:
        return False


def live_exchange():
    dec, req, _ = pair(clock=now_ms)
    request, offer, accept, decision = run(dec, req)
    return dec, [request, offer, accept, decision]


def test_the_schema_is_itself_a_valid_draft_2020_12_schema():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)


def test_every_envelope_and_body_of_a_live_exchange_validates_and_so_do_the_published_vectors():
    dec, msgs = live_exchange()
    for env in msgs:
        wire = env.to_wire()
        assert valid("envelope", wire), env.kind
        assert valid(f"body.{env.kind}", wire["body"]), (env.kind, wire["body"])
    assert valid("body.manifest", dec.manifest().to_wire()["body"])
    for e in VECTORS["envelopes"]:
        assert valid("envelope", e["wire"])


def test_the_schema_rejects_structural_defects_and_admits_what_only_the_receiver_can_catch():
    by_name = {r["name"]: r["wire"] for r in VECTORS["rejections"]}
    for name in ("extra-field", "missing-field", "unknown-kind", "bad-sig-hex", "other-version"):
        assert not valid("envelope", by_name[name]), name          # a shape defect: the schema catches it
    for name in ("body-edited", "sender-swapped", "expired", "from-the-future", "small-order-key"):
        assert valid("envelope", by_name[name]), name              # well-formed but wrong: only signature/time checks can say
    dec, msgs = live_exchange()
    body = dict(msgs[0].to_wire()["body"])
    assert not valid("body.request", {**body, "extra": 1}) and not valid("body.request", {k: v for k, v in body.items() if k != "subject"})
    assert not valid("body.decision", {**msgs[3].to_wire()["body"], "verdict": "maybe"})


def test_receiver_documents_validate_a_grants_file_a_job_and_an_approval(tmp_path):
    g = json.loads(grants_file(tmp_path / "g.json", approvers=["uai:ed25519:" + "a" * 64]).read_text())
    assert valid("grants_file", g)
    assert not valid("grants_file", {"grants": [{**g["grants"][0], "unknown": 1}]})
    job = act_job()
    assert valid("job", job)
    assert not valid("job", {**job, "extra": 1})
    assert valid("approval", {"approver": "uai:ed25519:" + "a" * 64, "decision_id": "0" * 32, "action": "x",
                              "subject_digest": "y", "expires_at": 1, "sig": "0" * 128})


#: How each implementation spells a refusal. Python: Refused("code"), _refuse("code"), _refuse_startup(cfg, "code").
#: Node: Refused("code"), refuse("code"), refuseStartup(cfg, "code") (act.mjs's runner refusals, which the first form missed).
_PY_FORMS = (r'Refused\(\s*"([a-z_]+)"', r'_refuse\(\s*"([a-z_]+)"', r'_refuse_startup\(\s*\w+,\s*"([a-z_]+)"')
_NODE_FORMS = (r'Refused\(\s*"([a-z_]+)"', r'\brefuse\(\s*"([a-z_]+)"', r'\brefuseStartup\(\s*\w+,\s*"([a-z_]+)"')


def codes_emitted(files: list, forms: tuple) -> set:
    found: set = set()
    for f in files:
        text = f.read_text()
        for form in forms:
            found |= set(re.findall(form, text))
    return found


def python_source() -> list:
    return [*(ROOT / "cns_interop").glob("*.py"), ROOT / "interop" / "act.py"]


def node_source() -> list:
    return [p for p in (ROOT / "interop" / "node").glob("*.mjs") if not p.name.endswith("test.mjs")]


def codes_in_source() -> set:
    return codes_emitted(python_source(), _PY_FORMS) | codes_emitted(node_source(), _NODE_FORMS)


def test_the_error_registry_covers_every_code_either_implementation_can_emit():
    reg = json.loads((PKG / "errors.json").read_text())
    codes = [c["code"] for c in reg["codes"]]
    assert len(codes) == len(set(codes))
    for c in reg["codes"]:
        assert set(c) == {"code", "layer", "meaning", "retry", "implementations", "consumes_message"}, c["code"]
        assert c["retry"] in ("never", "after-fix", "later") and c["implementations"] in ("both", "python", "node")
        assert c["consumes_message"] in (True, False, None) and len(c["meaning"]) > 20
    missing = codes_in_source() - set(codes)
    assert not missing, f"codes emitted by the source but absent from the registry: {sorted(missing)}"
    # a code the registry says only Python emits must not appear in the Node source (and the reverse for "both")
    node_codes = codes_emitted(node_source(), _NODE_FORMS)
    for c in reg["codes"]:
        if c["implementations"] == "python":
            assert c["code"] not in node_codes, c["code"]
    assert node_codes <= set(codes)


def test_the_registry_says_exactly_which_implementation_emits_each_code_and_the_two_vocabularies_are_the_registry():
    """R2-C-08: `config` was registered Python-only though act.mjs emits it, and the scan above could not see Node's `refuse(`.
    For every code the registry's `implementations` must equal what each implementation's source emits, in both directions."""
    reg = {c["code"]: c["implementations"] for c in json.loads((PKG / "errors.json").read_text())["codes"]}
    py, node = codes_emitted(python_source(), _PY_FORMS), codes_emitted(node_source(), _NODE_FORMS)
    wrong = {code: (impl, code in py, code in node) for code, impl in reg.items()
             if (impl in ("both", "python")) != (code in py) or (impl in ("both", "node")) != (code in node)}
    assert not wrong, f"code: (registered, emitted by Python, emitted by Node): {wrong}"
    assert (py | node) <= set(reg)
    for code in ("config", "clock_skew", "unavailable"):      # the clock-trust vocabulary, named: both implementations, same words
        assert reg[code] == "both" and code in py and code in node, code


def test_the_published_conformance_suite_is_current():
    sys.path.insert(0, str(ROOT / "interop" / "vectors"))
    import make_conformance_suite as m  # type: ignore[import-not-found]
    assert (PKG / "conformance-suite.json").read_text() == m.render(), "regenerate: python interop/vectors/make_conformance_suite.py --write"


def conform(cmd: str):
    done = subprocess.run([sys.executable, str(PKG / "run_conformance.py"), "--cmd", cmd, "--json"], capture_output=True, text=True,
                          cwd=ROOT, timeout=120)
    return done.returncode, json.loads(done.stdout)


@pytest.mark.parametrize("cmd", [f"{sys.executable} interop/conformance/reference_adapter.py", "node interop/node/conformance_adapter.mjs"])
def test_both_shipped_implementations_pass_the_conformance_suite_through_the_standalone_runner(cmd):
    rc, summary = conform(cmd)
    assert rc == 0 and summary["failures"] == [], summary["failures"]
    assert sum(summary["passed"].values()) == summary["cases"] >= 30


def test_the_runner_fails_an_implementation_that_accepts_everything_or_refuses_everything(tmp_path):
    lax = tmp_path / "lax.py"
    lax.write_text("import sys, json\nfor l in sys.stdin:\n    r = json.loads(l)\n    print(json.dumps({'ok': True} if r['op']=='reset' else {'accept': {'digest': ''}}), flush=True)\n")
    strict = tmp_path / "strict.py"
    strict.write_text("import sys, json\nfor l in sys.stdin:\n    r = json.loads(l)\n    print(json.dumps({'ok': True} if r['op']=='reset' else {'refuse': 'malformed'}), flush=True)\n")
    for adapter in (lax, strict):
        rc, summary = conform(f"{sys.executable} {adapter}")
        assert rc == 1 and summary["failures"], adapter.name
    # the lax one is caught on the cases that need a refusal, the strict one on those that need an acceptance
    assert any(f["wanted"].get("refuse") for f in conform(f"{sys.executable} {lax}")[1]["failures"])
    assert any(f["wanted"].get("accept") for f in conform(f"{sys.executable} {strict}")[1]["failures"])


def test_the_runner_depends_on_nothing_from_cns():
    src = (PKG / "run_conformance.py").read_text()
    imports = set(re.findall(r"^\s*(?:from|import)\s+([A-Za-z_][\w.]*)", src, re.M))
    assert not {i for i in imports if i.split(".")[0] in ("cns", "cns_interop", "cns_composition")}
    assert imports <= {"__future__", "argparse", "json", "shlex", "subprocess", "sys", "pathlib"}
