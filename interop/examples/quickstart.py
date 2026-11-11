"""quickstart.py: one UAI-1 exchange and one receiver-authorized action, using only the supported public API.

    python interop/examples/quickstart.py

Two independent parties (a requester and a decider) exchange a request, agree terms, disclose only what the terms name, and
the decider signs a decision. A third role, the RECEIVER that will act, then checks the decision for itself and acts only if
its OWN grant allows it. The signature on the decision is never enough. Nothing here is an AI model: the decider's judgement
is an ordinary function, which is where a model adapter plugs in (see provider_adapter.py).

Keys are generated fresh and live in this process: fine for a demo, not a production profile (docs/interop/implementers).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cns_interop.decision import RemoteDecisionGuard  # noqa: E402
from cns_interop.disclosure import commit  # noqa: E402
from cns_interop.envelope import Refused  # noqa: E402
from cns_interop.grants import Grant, GrantTable  # noqa: E402
from cns_interop.identity import Signer  # noqa: E402
from cns_interop.ledger import MemoryLedger  # noqa: E402
from cns_interop.manifest import Capability  # noqa: E402
from cns_interop.session import Decider, Judgment, Requester  # noqa: E402
from cns_interop.trust import TrustPolicy  # noqa: E402

CAP = Capability(name="income-screen", version=1, summary="monthly income at or above 4000.00",
                 accepts=("doc_type", "monthly_income_cents"), requires=("monthly_income_cents",),
                 evidence=("threshold-check",), max_ttl_ms=300_000)


def judge(cap, disclosed, subject):
    income = disclosed["monthly_income_cents"]
    if income >= 400_000:
        return Judgment("pass", ("income meets the threshold",), {"threshold-check": {"observed_cents": income}})
    return Judgment("retry", ("income is below the threshold",))


def main() -> int:
    requester_key, decider_key = Signer.generate(), Signer.generate()
    decider = Decider(decider_key, name="screener", implementation="quickstart/1", capabilities=[(CAP, judge)],
                      trust=TrustPolicy(pinned=frozenset({requester_key.agent})))
    requester = Requester(requester_key, trust=TrustPolicy(pinned=frozenset({decider_key.agent})))
    requester.discover(decider.manifest().to_wire())

    # The requester holds a document with an SSN it never offers.
    doc = commit("loan-app-17", {"monthly_income_cents": 512_000, "doc_type": "paystub", "ssn": "000-00-0000"})
    request = requester.request(decider_key.agent, doc, "income-screen", 1, offer_fields=["monthly_income_cents", "doc_type"],
                                require_evidence=["threshold-check"], max_ttl_ms=600_000)
    offer = decider.handle(request.to_wire())
    accept = requester.on_reply(offer.to_wire())
    decision = decider.handle(accept.to_wire())
    verified = requester.on_reply(decision.to_wire())
    terms = offer.body["terms"]
    print(f"decision: {verified.verdict}; disclosed fields: {terms['disclose']} (the ssn never left)")

    # The receiver that will ACT. Its grant, not the signature, is what permits the action.
    grants = GrantTable([Grant(id="g1", capability="income-screen", version=1, requester=requester_key.agent,
                               deciders=frozenset({decider_key.agent}), actions=frozenset({"release-funds"}),
                               disclose_max=frozenset({"doc_type", "monthly_income_cents"}))],
                        permit_ledger=MemoryLedger())
    guard = RemoteDecisionGuard(lambda artifact: artifact, acting_for=requester_key.agent, capability=("income-screen", 1),
                                trust=TrustPolicy(pinned=frozenset({decider_key.agent})), ledger=MemoryLedger(),
                                grants=grants, action="release-funds")
    try:
        guard.authorize(decision.to_wire(), terms=terms, accept_digest=accept.digest)
    except Refused as exc:
        print(f"refused: {exc.code}: {exc.reason}")
        return 1
    judged = (terms["subject"]["identity"], terms["subject"]["digest"])
    print("acting on the judged document:", guard(judged))
    print("acting on the same decision a second time:", guard(judged))
    guard.complete()
    print("permit:", guard.permit.grant, guard.permit.action, "idempotency key", guard.permit.idempotency_key[:24] + "...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
