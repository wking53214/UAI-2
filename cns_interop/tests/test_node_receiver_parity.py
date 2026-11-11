"""Python and Node receivers, same policy and same job, must reach the same security outcome.

Both programs (interop/act.py and interop/node/act.mjs) are run as real processes over the same scenarios. Each scenario
changes ONE thing. The outcome is the permit or the refusal code; the two must be identical, and each must equal the code the
scenario expects (so the two cannot agree on something wrong). The programs also share SQLite files, so a decision spent or a
grant withdrawn through one is seen by the other. Not shown: any difference that depends on a multi-host deployment (the
shared PostgreSQL ledger is tested in test_node_act_postgres.py)."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_act_policy import grants_file  # type: ignore[import-not-found]  # noqa: E402
from test_session import ACT_PY, DEC, REQ, act_job  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.grants import GrantStore, approve, verify_audit  # noqa: E402
from cns_interop.identity import Signer  # noqa: E402

ROOT = ACT_PY.parents[1]
ACT_MJS = ROOT / "interop" / "node" / "act.mjs"
NODE = shutil.which("node")
HUMAN = Signer(bytes([81] * 32))
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")  # reported by conftest as a failure on skip


def approval_for(job, *, signer=HUMAN, action="release-funds", ttl_ms=300_000, now=None):
    fake = SimpleNamespace(envelope=SimpleNamespace(id=job["decision"]["id"]), subject={"digest": job["terms"]["subject"]["digest"]})
    a = approve(signer, fake, action, ttl_ms=ttl_ms, now=now)  # type: ignore[arg-type]
    return {"approver": a.approver, "decision_id": a.decision_id, "action": a.action, "subject_digest": a.subject_digest,
            "expires_at": a.expires_at, "sig": a.sig}


def run(impl, tmp, job, *, action="release-funds", trust=None, capability="income-screen", raw=None):
    common = ["--acting-for", REQ.agent, "--capability", capability, "--capability-version", "1", "--trust", trust or DEC.agent,
              "--ledger", str(tmp / "spent.db"), "--grants", str(tmp / "grants.json"), "--grant-store", str(tmp / "grants.db"),
              "--action", action, "--audit", str(tmp / f"audit-{impl}.jsonl")]
    cmd = ([sys.executable, str(ACT_PY), "--ledger-backend", "sqlite", *common] if impl == "py"
           else [NODE, str(ACT_MJS), *common])
    done = subprocess.run(cmd, input=raw if raw is not None else json.dumps(job), capture_output=True, text=True, timeout=90,
                          env={"PYTHONPATH": str(ROOT), "PATH": "/usr/bin:/bin:/opt/node22/bin", "HOME": str(tmp)})
    assert done.stdout, done.stderr
    out = json.loads(done.stdout)
    return ("refused:" + out["refused"]["code"]) if "refused" in out else ("permitted" if out["permitted"] else "not-permitted")


def both(tmp_path, scenario):
    """Run the scenario once per implementation, each in its own directory, and return both outcomes."""
    outcomes = {}
    for impl in ("py", "node"):
        d = tmp_path / impl
        d.mkdir()
        grants_file(d / "grants.json")
        outcomes[impl] = scenario(d, lambda job, **kw: run(impl, d, job, **kw))
    return outcomes


def check(tmp_path, scenario, expect):
    got = both(tmp_path, scenario)
    assert got["py"] == got["node"] == expect, got


def test_a_proper_decision_with_a_grant_is_permitted_by_both(tmp_path):
    check(tmp_path, lambda d, r: r(act_job()), "permitted")


def test_a_replay_is_refused_by_both(tmp_path):
    def s(d, r):
        job = act_job()
        r(job)
        return r(job)
    check(tmp_path, s, "refused:replayed")


@pytest.mark.parametrize("change,expect", [
    ("no grant at all", "refused:no_grant"), ("another purpose", "refused:no_grant"), ("another action", "refused:action"),
    ("decider not named", "refused:decider"), ("another requester", "refused:no_grant"),
    ("disclosure too wide", "refused:disclosure"), ("expired grant", "refused:grant_expired")])
def test_every_grant_mismatch_gets_the_same_refusal_and_does_not_burn_the_decision(tmp_path, change, expect):
    def s(d, r):
        job, g = act_job(), d / "grants.json"
        if change == "no grant at all":
            g.write_text('{"grants": []}')
        elif change == "another purpose":
            grants_file(g, capability="income-screen.marketing")
        elif change == "another action":
            grants_file(g, actions=("delete-everything",))
        elif change == "decider not named":
            grants_file(g, deciders=[Signer(bytes([82] * 32)).agent])
        elif change == "another requester":
            grants_file(g, requester=Signer(bytes([83] * 32)).agent)
        elif change == "disclosure too wide":
            grants_file(g, disclose=("doc_type",))
        elif change == "expired grant":
            grants_file(g, extra={"expires_at": 1})
        first = r(job)
        grants_file(g)
        assert r(job) == "permitted"                                  # not burned: the same job lands with a proper grant
        return first
    check(tmp_path, s, expect)


def test_approval_rules_are_identical(tmp_path):
    def s(d, r):
        job = act_job()
        grants_file(d / "grants.json", approvers=[HUMAN.agent])
        seen = [r(job)]                                                                   # none given
        seen.append(r({**job, "approval": approval_for(job, signer=Signer(bytes([84] * 32)))}))   # not a listed approver
        seen.append(r({**job, "approval": approval_for(job, action="wire-money")}))             # another action
        seen.append(r({**job, "approval": approval_for(act_job())}))                            # another decision
        seen.append(r({**job, "approval": approval_for(job, now=1_000)}))                       # expired
        seen.append(r({**job, "approval": {**approval_for(job), "sig": "00" * 64}}))            # forged
        seen.append(r({**job, "approval": {"approver": HUMAN.agent}}))                         # malformed
        seen.append(r({**job, "approval": approval_for(job)}))                                 # and now it lands
        seen.append(r({**job, "approval": approval_for(job)}))                                 # and only once
        return seen
    got = both(tmp_path, s)
    assert got["py"] == got["node"], got
    assert got["py"] == ["refused:approval_required", "refused:approval", "refused:approval", "refused:approval",
                         "refused:approval", "refused:approval", "refused:approval", "permitted", "refused:replayed"]


def test_a_grant_that_names_a_party_as_its_own_approver_cannot_start_either_receiver(tmp_path):
    def s(d, r):
        grants_file(d / "grants.json", approvers=[REQ.agent])
        return r(act_job())
    check(tmp_path, s, "refused:config")


def test_altered_terms_a_wrong_document_an_untrusted_decider_and_tampering_are_refused_alike(tmp_path):
    def s(d, r):
        job, seen = act_job(), []
        seen.append(r({**job, "terms": {**job["terms"], "disclose": ["doc_type"]}}))             # not the signed terms
        seen.append(r({**job, "artifact": ["loan-app-17", "0" * 64]}))                           # a different document
        seen.append(r(job, trust=Signer(bytes([85] * 32)).agent))                                # decider not trusted here
        forged = json.loads(json.dumps(job))
        forged["decision"]["sig"] = "00" * 64
        seen.append(r(forged))                                                                   # a forged signature
        seen.append(r({**job, "extra": 1}))                                                      # a job with an extra key
        seen.append(r(job, raw=json.dumps(job)[:-1] + ', "decision": {}}'))                      # a duplicate key
        seen.append(r(job, capability="ingest"))                                                 # another capability
        seen.append(r(job))                                                                      # and the real one still lands
        return seen
    got = both(tmp_path, s)
    assert got["py"] == got["node"], got
    assert got["py"][-1] == "permitted"
    assert all(x.startswith("refused:") or x == "not-permitted" for x in got["py"][:-1])


def test_a_withdrawal_and_a_spent_decision_made_through_one_language_bind_the_other(tmp_path):
    # Python spends, Node is refused as a replay: the same SQLite decision and permit ledgers.
    d = tmp_path / "shared"
    d.mkdir()
    grants_file(d / "grants.json")
    job = act_job()
    assert run("py", d, job) == "permitted"
    assert run("node", d, job) == "refused:replayed"
    # Node spends, Python is refused.
    job2 = act_job()
    assert run("node", d, job2) == "permitted"
    assert run("py", d, job2) == "refused:replayed"
    # A withdrawal written by Python is seen by Node.
    GrantStore(d / "grants.db").withdraw("g1")
    assert run("node", d, act_job()) == "refused:withdrawn"
    verify_audit(d / "audit-py.jsonl")                                  # each language's chain verifies under Python's verifier
    verify_audit(d / "audit-node.jsonl")                                # including the Node-written one


def test_concurrent_attempts_on_one_decision_yield_one_permit_across_both_languages(tmp_path):
    d = tmp_path / "race"
    d.mkdir()
    grants_file(d / "grants.json")
    job = act_job()
    procs = []
    for impl in ["py", "node"] * 4:
        common = ["--acting-for", REQ.agent, "--capability", "income-screen", "--capability-version", "1", "--trust", DEC.agent,
                  "--ledger", str(d / "spent.db"), "--grants", str(d / "grants.json"), "--grant-store", str(d / "grants.db"),
                  "--action", "release-funds", "--audit", str(d / f"audit-{impl}.jsonl")]
        cmd = [sys.executable, str(ACT_PY), "--ledger-backend", "sqlite", *common] if impl == "py" else [NODE, str(ACT_MJS), *common]
        procs.append(subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                      env={"PYTHONPATH": str(ROOT), "PATH": "/usr/bin:/bin:/opt/node22/bin"}))
    outs = []
    for p in procs:
        out, _ = p.communicate(json.dumps(job), timeout=120)
        outs.append(json.loads(out))
    permitted = [o for o in outs if o.get("permitted") is True]
    assert len(permitted) == 1, outs
    assert all(o.get("refused", {}).get("code") in ("replayed", "unavailable") for o in outs if o not in permitted), outs
