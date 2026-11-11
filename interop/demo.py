"""demo.py: two independent systems, in two languages, exchange a request, negotiate, disclose, decide and verify.

    python interop/demo.py          a readable transcript
    python interop/demo.py --json   the same run as one JSON object (what cns_interop/tests/test_two_systems.py reads)

WHAT RUNS

Round 1, Node decides. A Node.js process (interop/node/agent.mjs: its own canonical encoder, its own strict JSON
reader, OpenSSL's Ed25519, its own policy) is the decider. This Python process is the requester (cns_interop). The
requester holds a document with five fields, offers three, and the Node agent's terms take only the two it needs;
the name and the account number never leave the requester. The Node agent signs a decision; Python verifies it.

Round 2, the action boundary. A third process (interop/act.py) that holds no key and shares no memory with either
system checks the Node-signed decision for itself and permits one action on the one document. A second run of it,
another process sharing only the ledger file, is refused as a replay. An artifact that is not the judged document
is not permitted.

Round 3, Python decides, Node verifies. The roles reverse: the decider is Python, and its capability is a CNS
SuperGate roster, so the signed decision carries the roster's root. The Node agent verifies it with OpenSSL.

Round 4, the rails. A replayed request, a tampered decision, a document the Node agent will not accept, and a
requester the decider does not trust, each refused for its own stated reason.

Both systems pin each other's identity here because the demo generates both keys. In a deployment each side would
learn the other's identity out of band or admit it through an authority's endorsement (cns_interop.trust).
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cns.gate import GateOutcome, GatePosition, GateResult, subject_digest  # noqa: E402

from cns_composition.super_gate import Judged, SuperGate  # noqa: E402
from cns_interop.decision import issue, verify_decision  # noqa: E402
from cns_interop.disclosure import commit  # noqa: E402
from cns_interop.envelope import Refused  # noqa: E402
from cns_interop.identity import Signer  # noqa: E402
from cns_interop.ledger import MemoryLedger  # noqa: E402
from cns_interop.manifest import Capability  # noqa: E402
from cns_interop.session import Decider, Requester  # noqa: E402
from cns_interop.trust import TrustPolicy  # noqa: E402
from cns_interop.wire import dumps, loads  # noqa: E402

AGENT_JS = ROOT / "interop" / "node" / "agent.mjs"
ACT_PY = ROOT / "interop" / "act.py"


class NodeAgent:
    """One Node agent process, driven one JSON line in, one JSON line out."""

    def __init__(self, role: str, seed: bytes, trust: List[str], doc: Optional[Dict[str, Any]] = None) -> None:
        node = shutil.which("node")
        if node is None:
            raise RuntimeError("node is not installed; the demo needs a second, independent implementation to talk to")
        env = dict(os.environ, UAI_SEED=seed.hex(), UAI_TRUST=",".join(trust), UAI_DOC=json.dumps(doc or {}))
        self.proc = subprocess.Popen([node, str(AGENT_JS), role], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, encoding="utf-8", env=env)

    def read(self) -> Dict[str, Any]:
        assert self.proc.stdout is not None
        line = self.proc.stdout.readline()
        if not line:
            err = self.proc.stderr.read() if self.proc.stderr else ""
            raise RuntimeError("the Node agent stopped: " + err)
        value: Dict[str, Any] = loads(line)
        return value

    def send(self, obj: Any) -> Dict[str, Any]:
        assert self.proc.stdin is not None
        text = dumps(obj) if hasattr(obj, "to_wire") else json.dumps(obj, sort_keys=True)
        self.proc.stdin.write(text + "\n")
        self.proc.stdin.flush()
        return self.read()

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        self.proc.wait(timeout=10)


def act(decision: Dict[str, Any], terms: Dict[str, Any], accept_digest: str, artifact: List[str], *,
        acting_for: str, capability: str, version: int, trust: str, ledger: str) -> Dict[str, Any]:
    """Run interop/act.py as its own process. Its configuration (who it acts for, which capability it acts on, which
    deciders it trusts, its ledger) is its command line, and so is the receiver's POLICY: a grants file naming the
    capability, decider and action, a durable grant store and an audit record. The job carries only the decision and what
    it is about. Without that policy act.py refuses to start: a signature alone does not open the action."""
    job = {"decision": decision, "terms": terms, "accept_digest": accept_digest, "artifact": artifact}
    env = dict(os.environ, PYTHONPATH=str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    here = Path(ledger).parent
    grants = here / "grants.json"
    grants.write_text(json.dumps({"grants": [{"id": "demo-ingest", "capability": capability, "version": version,
                                              "requester": acting_for, "deciders": [trust], "actions": ["ingest"],
                                              "disclose_max": ["doc_type", "monthly_income_cents", "employer"]}]}),
                      encoding="utf-8")
    done = subprocess.run([sys.executable, str(ACT_PY), "--acting-for", acting_for,
                           "--capability", capability, "--capability-version", str(version), "--trust", trust,
                           "--ledger", ledger, "--grants", str(grants), "--grant-store", str(here / "grants.db"),
                           "--action", "ingest", "--audit", str(here / "audit.jsonl")], input=json.dumps(job),
                          capture_output=True, text=True, env=env, timeout=60, check=True)
    result: Dict[str, Any] = json.loads(done.stdout)
    return result


def document(identity: str, income: int, doc_type: str = "paystub") -> Any:
    return commit(identity, {"monthly_income_cents": income, "doc_type": doc_type, "employer": "Acme Tools",
                             "full_name": "Pat Doe", "account_number": "000123456789"})


def round_node_decides(log: List[str]) -> Dict[str, Any]:
    py = Signer.generate()
    node_seed = secrets.token_bytes(32)
    node_id = Signer(node_seed).agent  # what the Node agent's identity must be; its manifest is checked against it
    agent = NodeAgent("decider", node_seed, trust=[py.agent])
    try:
        requester = Requester(py, trust=TrustPolicy(pinned=frozenset({node_id})))
        manifest = requester.discover(agent.read())
        log.append(f"Python read and admitted the manifest of {manifest.name} ({manifest.implementation})")
        agent.send(requester.manifest())
        doc = document("loan-app-2026-1030-A", 512_000)
        request = requester.request(node_id, doc, "income-screen", 1,
                                    offer_fields=["monthly_income_cents", "doc_type", "employer"],
                                    require_evidence=["threshold-check"], max_ttl_ms=600_000)
        offer_wire = agent.send(request)
        accept = requester.on_offer(offer_wire)
        terms = offer_wire["body"]["terms"]
        log.append(f"Node offered terms: sees {terms['disclose']}, returns {terms['evidence']}, "
                   f"decision lives {terms['decision_ttl_ms']} ms")
        decision_wire = agent.send(accept)
        verified = requester.on_decision(decision_wire)
        log.append(f"Node decided {verified.verdict}; Python verified the OpenSSL signature: "
                   f"{verified.reasons[0] if verified.reasons else ''}")

        # Round 2: a separate process, sharing only a ledger file, acts once.
        with tempfile.TemporaryDirectory() as tmp:
            cfg = {"acting_for": py.agent, "capability": "income-screen", "version": 1, "trust": node_id,
                   "ledger": str(Path(tmp) / "spent.jsonl")}
            artifact = [doc.identity, doc.digest]
            first = act(decision_wire, terms, accept.digest, artifact, **cfg)
            second = act(decision_wire, terms, accept.digest, artifact, **cfg)
            other = act(decision_wire, terms, accept.digest, [doc.identity, "0" * 64],
                        **dict(cfg, ledger=str(Path(tmp) / "other.jsonl")))
            # A job that names its own decider: a key the attacker made, signing a pass the attacker wrote.
            mallory = Signer.generate()
            forged_terms = dict(terms, decider=mallory.agent)
            forged = issue(mallory, accept, forged_terms, "pass",
                           evidence={"threshold-check": {"observed_cents": 1}})
            impostor = act(forged.to_wire(), forged_terms, accept.digest, artifact,
                           **dict(cfg, ledger=str(Path(tmp) / "fresh.jsonl")))
        log.append(f"act.py (process 3) permitted the action: {first.get('permitted')}; a second act.py process "
                   f"with the same ledger was refused: {second.get('refused', {}).get('code')}; a different "
                   f"document was permitted: {other.get('permitted')}; a job naming its own decider was refused: "
                   f"{impostor.get('refused', {}).get('code')}")

        # Round 4 on this pair: replay, tamper, an unacceptable document.
        replay = agent.send(request)
        tampered = json.loads(json.dumps(decision_wire))
        tampered["body"]["evidence"][0]["content"]["observed_cents"] = 9_999_999
        try:
            verify_decision(tampered, terms=terms, accept_digest=accept.digest, ledger=MemoryLedger())
            tamper_code = "accepted"
        except Refused as exc:
            tamper_code = exc.code
        bad_doc = document("loan-app-2026-1030-B", 900_000, doc_type="bank-statement")
        r2 = requester.request(node_id, bad_doc, "income-screen", 1, offer_fields=["monthly_income_cents", "doc_type"],
                               require_evidence=["threshold-check"], max_ttl_ms=600_000)
        a2 = requester.on_offer(agent.send(r2))
        v2 = requester.on_decision(agent.send(a2))
        withheld = requester.request(node_id, document("loan-app-2026-1030-C", 600_000), "income-screen", 1,
                                     offer_fields=["monthly_income_cents"], max_ttl_ms=600_000)
        try:
            requester.on_offer(agent.send(withheld))
            withheld_code = "accepted"
        except Refused as exc:
            withheld_code = exc.code + ": " + exc.reason
        log.append(f"Rails: replayed request -> {replay.get('uai_error', {}).get('code')}; tampered decision -> "
                   f"{tamper_code}; bank statement -> {v2.verdict} ({v2.reasons[0]}); withholding a required field "
                   f"-> {withheld_code}")
        return {"node_agent": node_id, "python_agent": py.agent, "terms": terms,
                "never_sent": sorted(set(doc.values) - set(terms["disclose"])),
                "accept_disclosed": sorted(accept.body["disclosure"]["disclosed"]),
                "verdict": verified.verdict, "allowed": verified.allowed, "evidence": dict(verified.evidence),
                "signer": verified.envelope.sender, "act_first": first, "act_second": second, "act_other": other, "act_impostor": impostor,
                "replay": replay, "tamper": tamper_code, "bad_doc_verdict": v2.verdict, "withheld": withheld_code}
    finally:
        agent.close()


class IncomeGate:
    name, position = "standin_income", GatePosition.ALPHA

    def check(self, c: Any) -> GateResult:
        ok = c["income"] >= 400_000
        return GateResult(gate=self.name, position=self.position, outcome=GateOutcome.PASS if ok else GateOutcome.RETRY,
                          reason="income at or above 400000" if ok else "income below 400000",
                          subject=c["identity"], subject_digest=subject_digest({"candidate": c}))


class DocumentGate:
    name, position = "standin_document", GatePosition.OMEGA

    def check(self, c: Any) -> GateResult:
        ok = c["doc_type"] in {"paystub", "tax-return"}
        return GateResult(gate=self.name, position=self.position,
                          outcome=GateOutcome.PASS if ok else GateOutcome.TERMINAL_BREACH,
                          reason="accepted document" if ok else "not an accepted document",
                          subject=c["identity"], subject_digest=subject_digest({"candidate": c}))


def roster(cap: Capability, disclosed: Dict[str, Any], subject: Dict[str, str]) -> Any:
    """The Python decider's capability is a CNS SuperGate. Its two gates are stand-ins written in this file, seated
    in the Governance_Gateway row (an admission door, ALPHA) and the DIT row (an outbound judge, OMEGA) the way the
    CNS test suite seats its fakes. No repository's real gate is imported or claimed."""
    seats = {"income": "Governance_Gateway:standin_income", "document": "DIT:standin_document"}
    read = {s: (lambda c: Judged(c["identity"], c["digest"])) for s in seats.values()}
    gate = SuperGate([("Governance_Gateway", IncomeGate()), ("DIT", DocumentGate())],
                     required=(*seats.values(), "CNS:same_subject"), same_subject=read)
    cand = {"identity": subject["identity"], "digest": subject["digest"],
            "income": disclosed["monthly_income_cents"], "doc_type": disclosed["doc_type"]}
    decision = gate.decide({s: cand for s in seats.values()})
    return decision, {"threshold-check": {"threshold_cents": 400_000, "observed_cents": cand["income"],
                                          "roster_root": decision.root}}


def round_python_decides(log: List[str]) -> Dict[str, Any]:
    dec_signer = Signer.generate()
    node_seed = secrets.token_bytes(32)
    node_id = Signer(node_seed).agent
    cap = Capability(name="income-screen", version=1, summary="a CNS SuperGate roster over income and document type",
                     accepts=("doc_type", "monthly_income_cents"), requires=("doc_type", "monthly_income_cents"),
                     evidence=("threshold-check",), max_ttl_ms=120_000)
    decider = Decider(dec_signer, name="cns-roster-screener", implementation="python/cns_interop + CNS SuperGate",
                      capabilities=[(cap, roster)], trust=TrustPolicy(pinned=frozenset({node_id})))
    doc = {"identity": "loan-app-2026-1030-N", "evidence": ["threshold-check"],
           "offer": ["monthly_income_cents", "doc_type"],
           "values": {"monthly_income_cents": 480_000, "doc_type": "tax-return", "full_name": "Sam Roe"}}
    agent = NodeAgent("requester", node_seed, trust=[dec_signer.agent], doc=doc)
    try:
        request = agent.send(decider.manifest())
        offer = decider.handle(request)
        assert offer is not None
        accept = agent.send(offer)
        decision = decider.handle(accept)
        assert decision is not None
        result = agent.send(decision)["uai_result"]
        log.append(f"Python (CNS SuperGate) decided {result['verdict']}; Node verified it with OpenSSL; the roster "
                   f"root {result['cns_root'][:16]}... crossed with it")

        stranger = Signer.generate()
        cold = Requester(stranger, trust=TrustPolicy(pinned=frozenset({decider.agent})))
        cold.discover(decider.manifest().to_wire())
        r = cold.request(decider.agent, document("x", 500_000), "income-screen", 1,
                         offer_fields=["monthly_income_cents", "doc_type"], max_ttl_ms=600_000)
        try:
            reply = decider.handle(r.to_wire())
            seen = (reply.kind if reply is not None else "none", reply.body["reasons"][0] if reply is not None else "")
        except Refused as exc:  # revision 3: a sender the decider has not admitted gets nothing signed and costs it no signature check
            seen = ("dropped", exc.reason)
        log.append(f"Rails: a requester the Python decider does not trust -> {seen[0]} ({seen[1]})")
        return {"result": result, "decider": dec_signer.agent, "stranger_reply": seen[0], "stranger_reason": seen[1]}
    finally:
        agent.close()


def main(argv: List[str]) -> int:
    log: List[str] = []
    out = {"node_decides": round_node_decides(log), "python_decides": round_python_decides(log)}
    if "--json" in argv:
        print(json.dumps(out, sort_keys=True))
    else:
        print("UAI-1: two independent systems, two languages, one exchange each way\n")
        for line in log:
            print(" - " + line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
