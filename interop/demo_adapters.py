"""demo_adapters.py: two independently implemented agents, one receiver, and everything between them that UAI-1 says.

    python interop/demo_adapters.py            a readable transcript
    python interop/demo_adapters.py --json     the same run as one JSON object (cns_interop/tests/test_demo_adapters.py)

WHO IS WHO, AND WHAT IS REAL

  Node decider        REAL, independent: interop/node/agent.mjs. Its own parser, canonical encoder, OpenSSL Ed25519 and
                      rule (income at or above 450000 from a paystub or tax return). Shares no code with Python.
  Python decider      a Python implementation whose judgment comes from an ADAPTER. The adapter here is a DETERMINISTIC
                      SCRIPT standing in for a model: no model provider is called and nothing here shows that any
                      provider's model interoperates. The seam where a real provider plugs in is
                      cns_interop.adapter.PromptedModelAdapter. The decider's own policy, not the script, has the last word.
  Receiver            the Python Requester, a GrantTable, a RemoteDecisionGuard and a RevocationStore: the party that
                      keeps its own identity, trust, grants and authority and is the one that may act.
  Human               a key that belongs to a person, held by the receiver's approval tool. Neither agent has it.

The purpose is carried in the capability name (`income-screen.loan-underwriting`), so both deciders offer the purpose-bound
capability and the receiver's grant is for that purpose and no other.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cns_interop.adapter import AdapterJudge, PromptedModelAdapter, ProviderInfo, Recommendation  # noqa: E402
from cns_interop.decision import RemoteDecisionGuard  # noqa: E402
from cns_interop.disclosure import commit  # noqa: E402
from cns_interop.envelope import Refused  # noqa: E402
from cns_interop.grants import Grant, GrantTable, approve  # noqa: E402
from cns_interop.identity import Signer  # noqa: E402
from cns_interop.ledger import FileLedger  # noqa: E402
from cns_interop.manifest import Capability  # noqa: E402
from cns_interop.revocation import RevocationStore, revoke  # noqa: E402
from cns_interop.session import Decider, Requester  # noqa: E402
from cns_interop.trust import TrustPolicy  # noqa: E402
from interop.demo import NodeAgent  # noqa: E402

PURPOSE = "income-screen.loan-underwriting"
THRESHOLD = 450_000
ACTION = "release-funds"
FIELDS = ["doc_type", "monthly_income_cents"]
CAP = Capability(name=PURPOSE, version=1, summary="monthly income at or above 450000 cents, from a paystub or tax return",
                 accepts=tuple(FIELDS), requires=tuple(FIELDS), evidence=("threshold-check",), max_ttl_ms=120_000)


def scripted_model(mode: str = "honest"):
    """A deterministic stand-in for a model. `mode` is what it says. It is NOT a model."""
    def reply(prompt: str) -> str:
        data = json.loads(prompt.split("DISCLOSED ", 1)[1])
        income, doc_type = data["monthly_income_cents"], data["doc_type"]
        ok = doc_type in ("paystub", "tax-return") and income >= THRESHOLD
        out = {"verdict": "pass" if ok else "retry", "reasons": ["the scripted model recommends " + ("pass" if ok else "retry")],
               "evidence": {"threshold-check": {"threshold_cents": THRESHOLD, "observed_cents": income, "doc_type": doc_type}} if ok else {},
               "escalate": False}
        if mode == "injected":   # a model fooled into approving whatever it is told, and announcing authority it lacks
            return json.dumps({**out, "verdict": "pass", "evidence": {"threshold-check": {"observed_cents": income}}, "sign": True})
        if mode == "prose":
            return "Certainly! " + json.dumps(out)
        return json.dumps(out)
    return reply


def policy(cap, disclosed, subject, rec: Recommendation) -> Recommendation:
    """The Python decider's own rule, re-checking the facts the model was shown."""
    clears = disclosed.get("doc_type") in ("paystub", "tax-return") and disclosed.get("monthly_income_cents", 0) >= THRESHOLD
    if rec.verdict == "pass" and not clears:
        return Recommendation("retry", rec.reasons + ("the decider's policy re-checked and it does not clear",), {})
    return rec


def python_decider(signer: Signer, requester: str, mode: str) -> Decider:
    adapter = PromptedModelAdapter(CAP, scripted_model(mode), ProviderInfo("scripted-model", "none", "script", "scripted-double"))
    return Decider(signer, name="python-adapter-decider", implementation="python/cns_interop + scripted model double",
                   capabilities=[(CAP, AdapterJudge(adapter, policy))], trust=TrustPolicy(pinned=frozenset({requester})))


def document(identity: str, income: int, doc_type: str = "paystub") -> Any:
    return commit(identity, {"monthly_income_cents": income, "doc_type": doc_type, "employer": "Acme Tools",
                             "full_name": "Pat Doe", "account_number": "000123456789"})


def code_of(fn, *a, **k) -> str:
    try:
        fn(*a, **k)
    except Refused as exc:
        return exc.code
    return "accepted"


def exchange(req: Requester, decide, decider_id: str, doc: Any):
    """request -> offer -> accept -> decision, with `decide(wire) -> wire` standing for the transport to the decider."""
    request = req.request(decider_id, doc, PURPOSE, 1, offer_fields=FIELDS + ["employer"], require_evidence=["threshold-check"],
                          max_ttl_ms=600_000)
    offer_wire = decide(request.to_wire())
    terms = offer_wire["body"]["terms"]
    accept = req.on_reply(offer_wire)
    decision_wire = decide(accept.to_wire())
    return terms, accept, decision_wire


def run() -> Dict[str, Any]:
    os.environ["UAI_CAP_NAME"] = PURPOSE
    me, human = Signer.generate(), Signer.generate()
    node_seed, py_signer = secrets.token_bytes(32), Signer.generate()
    node_id = Signer(node_seed).agent
    facts: Dict[str, Any] = {"actors": {
        "node_decider": {"id": node_id, "implementation": "node/uai.mjs", "real_independent_implementation": True, "provider": "none (rule)"},
        "python_decider": {"id": py_signer.agent, "implementation": "python/cns_interop", "real_independent_implementation": True,
                           "judgment_source": "scripted-double", "live_model_called": False},
        "receiver": {"id": me.agent}, "human_approver": {"id": human.agent}}}
    steps: List[Dict[str, Any]] = []

    def step(n: int, name: str, **kw: Any) -> None:
        steps.append({"n": n, "name": name, **kw})

    tmp = Path(tempfile.mkdtemp())
    store = RevocationStore(tmp / "revocations.db")
    store.mark_fresh()
    trust = TrustPolicy(pinned=frozenset({node_id, py_signer.agent}), revocations=store, max_staleness_ms=3_600_000)
    grants = GrantTable([Grant(id="g-underwriting", capability=PURPOSE, version=1, requester=me.agent,
                               deciders=frozenset({node_id, py_signer.agent}), actions=frozenset({ACTION}),
                               disclose_max=frozenset(FIELDS), approvers=frozenset({human.agent}))],
                        audit_path=tmp / "audit.jsonl")
    node = NodeAgent("decider", node_seed, trust=[me.agent])
    try:
        # 1. identity and 2. capability negotiation
        req = Requester(me, trust=trust)
        node_manifest = req.discover(node.read())
        node.send(req.manifest())
        py_dec = python_decider(py_signer, me.agent, "honest")
        py_manifest = req.discover(py_dec.manifest().to_wire())
        step(1, "identity", note="each side pins the other's public key; nothing is looked up",
             admitted=[node_manifest.agent == node_id, py_manifest.agent == py_signer.agent])
        step(2, "capability negotiation", node_offers=[c.name for c in node_manifest.capabilities],
             python_offers=[c.name for c in py_manifest.capabilities], advertisement_only=True)

        # 3. purpose-bound exchange, 4. selective disclosure, 5. signed decisions, 9. consistency across implementations
        results: Dict[str, Dict[str, Any]] = {}
        for label, income in (("clears", 512_000), ("below", 100_000)):
            for who, decide, did in (("node", lambda w: node.send(w), node_id),
                                     ("python", lambda w: _wire(py_dec.handle(w)), py_signer.agent)):
                d = document(f"loan-{label}-{who}", income)
                terms, accept, decision_wire = exchange(req, decide, did, d)
                grants.check_terms(terms)       # the receiver's disclosure ceiling, before the accept's openings are trusted
                got = req.on_decision(decision_wire)
                results[f"{who}/{label}"] = {"verdict": got.verdict, "terms": terms, "accept": accept, "decision": decision_wire,
                                             "verified": got, "doc": d}
        first = results["node/clears"]
        step(3, "purpose-bound exchange", capability=first["terms"]["capability"], grant_checked_before_disclosure=True)
        step(4, "selective disclosure", disclosed=first["terms"]["disclose"],
             never_sent=sorted(set(first["doc"].values) - set(first["terms"]["disclose"])),
             opened_in_accept=sorted(first["accept"].body["disclosure"]["disclosed"]))
        step(5, "signed decisions verified", node_signed_by=results["node/clears"]["verified"].envelope.sender == node_id,
             python_signed_by=results["python/clears"]["verified"].envelope.sender == py_signer.agent)
        verdicts = {k: v["verdict"] for k, v in results.items()}
        step(9, "consistent across implementations", verdicts=verdicts,
             agree=verdicts["node/clears"] == verdicts["python/clears"] and verdicts["node/below"] == verdicts["python/below"])

        # 6. receiver-side authorization, 8. refusal when authorization is absent
        for who, did in (("node", node_id), ("python", py_signer.agent)):
            r = results[f"{who}/clears"]
            guard = RemoteDecisionGuard(lambda a: tuple(a), acting_for=me.agent, capability=(PURPOSE, 1),
                                        trust=trust, ledger=FileLedger(tmp / f"spent-{who}.jsonl"))
            got = guard.authorize(r["decision"], terms=r["terms"], accept_digest=r["accept"].digest)
            no_approval = code_of(grants.permit, ACTION, got, r["terms"])
            wrong_action = code_of(grants.permit, "wire-money", got, r["terms"], approval=approve(human, got, "wire-money"))
            permit = grants.permit(ACTION, got, r["terms"], approval=approve(human, got, ACTION))
            artifact = [r["terms"]["subject"]["identity"], r["terms"]["subject"]["digest"]]
            first_use, second_use = guard(artifact), guard(artifact)
            r["authorize"] = {"no_approval": no_approval, "wrong_action": wrong_action, "permitted": bool(permit.audit_digest),
                              "acted_once": first_use and not second_use}
        step(6, "receiver-side authorization", node=results["node/clears"]["authorize"], python=results["python/clears"]["authorize"])
        retry = results["node/below"]["verified"]
        step(8, "refusal when authorization is absent",
             a_retry_permits_nothing=code_of(grants.permit, ACTION, retry, results["node/below"]["terms"]),
             no_approval_refused=results["node/clears"]["authorize"]["no_approval"],
             action_not_granted=results["node/clears"]["authorize"]["wrong_action"],
             withdrawn_after=_withdraw_then_permit(grants, results, human))

        # 7. revocation and expiry
        d2 = document("loan-after-revocation", 600_000)
        terms2, accept2, dec2 = exchange(req, lambda w: _wire(py_dec.handle(w)), py_signer.agent, d2)
        store.accept(revoke(py_signer, py_signer.agent, reason="decider key reported lost").to_wire())
        late_guard = RemoteDecisionGuard(lambda a: tuple(a), acting_for=me.agent, capability=(PURPOSE, 1), trust=trust,
                                         ledger=FileLedger(tmp / "spent-late.jsonl"))
        revoked = code_of(late_guard.authorize, dec2, terms=terms2, accept_digest=accept2.digest)
        r = results["node/clears"]
        exp_guard = RemoteDecisionGuard(lambda a: tuple(a), acting_for=me.agent, capability=(PURPOSE, 1), trust=trust,
                                        ledger=FileLedger(tmp / "spent-exp.jsonl"),
                                        clock=lambda: r["verified"].envelope.expires_at + 1)
        step(7, "revocation and expiry", revoked_decider_refused=revoked,
             expired_decision_refused=code_of(exp_guard.authorize, r["decision"], terms=r["terms"], accept_digest=r["accept"].digest),
             node_still_trusted=trust.admit(node_id).via)

        # an injected model: signed failure, no pass, no permit
        bad = python_decider(Signer.generate(), me.agent, "injected")
        bad_req = Requester(me, trust=TrustPolicy(pinned=frozenset({bad.agent})))
        bad_req.discover(bad.manifest().to_wire())
        terms3, accept3, dec3 = exchange(bad_req, lambda w: _wire(bad.handle(w)), bad.agent, document("loan-injected", 100_000))
        v3 = bad_req.on_decision(dec3)
        step(10, "a model that tries to claim authority", verdict=v3.verdict, reason=v3.reasons[0][:90],
             allowed=v3.allowed)
        facts["audit_entries"] = len((tmp / "audit.jsonl").read_text().splitlines())
    finally:
        node.close()
    facts["steps"] = steps
    return facts


def _wire(env: Any) -> Dict[str, Any]:
    return json.loads(json.dumps(env.to_wire(), sort_keys=True))


def _withdraw_then_permit(grants: GrantTable, results: Dict[str, Any], human: Signer) -> str:
    r = results["python/clears"]
    got = r["verified"]
    grants.withdraw("g-underwriting")
    return code_of(grants.permit, ACTION, got, r["terms"], approval=approve(human, got, ACTION))


def main(argv: List[str]) -> int:
    facts = run()
    if "--json" in argv:
        print(json.dumps(facts, sort_keys=True, default=str))
        return 0
    for a, info in facts["actors"].items():
        print(f"{a:16} {info}")
    for s in facts["steps"]:
        print(f"\n[{s['n']}] {s['name']}")
        for k, v in s.items():
            if k not in ("n", "name"):
                print(f"      {k}: {v}")
    print(f"\naudit entries written: {facts['audit_entries']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
