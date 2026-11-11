"""uai_quickstart.py: one model, one recommendation, one signed decision, verified.

    export GROQ_API_KEY=...                                   # the one thing to set: your provider's key
    python interop/examples/uai_quickstart.py groq llama-3.3-70b-versatile

The provider is one of: anthropic, gemini, openai, copilot, copilot-azure, groq, cloudflare. Without the key it prints
NOT EXECUTED and exits 3, so a script cannot mistake "no key" for "it worked".

What happens, in order:
  1. `uai.connect` builds the provider client. Nothing is sent yet.
  2. A requester asks a decider to screen one document, and they agree terms. Only two of the document's fields are
     disclosed; the name on it never leaves the requester.
  3. The model is asked for a recommendation. Its answer is read strictly: exactly verdict, reasons, evidence, escalate.
  4. The decider's own policy re-checks the facts. A model's "pass" stands only if the policy keeps it.
  5. The decider signs the decision. A pass carries the record of the provider call (which model, and the digests of
     the request sent and the answer read).
  6. The requester verifies the signature, the terms, the subject and that it has not seen this decision before. The
     same decision presented a second time is refused.

The decider and the requester run in this one process to keep the example short. They share nothing but the signed
messages, so either can run anywhere, in Python or in Node (interop/node/).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import uai  # noqa: E402
from cns_interop.adapter import Recommendation  # noqa: E402
from cns_interop.disclosure import commit  # noqa: E402
from cns_interop.envelope import Refused  # noqa: E402
from cns_interop.identity import Signer  # noqa: E402
from cns_interop.manifest import Capability  # noqa: E402
from cns_interop.session import Decider, Requester  # noqa: E402
from cns_interop.trust import TrustPolicy  # noqa: E402

THRESHOLD = 450_000
CAPABILITY = Capability(name="income-screen", version=1, summary=f"monthly income at or above {THRESHOLD} cents",
                        accepts=("doc_type", "monthly_income_cents"), requires=("doc_type", "monthly_income_cents"),
                        evidence=(uai.PROVIDER_CALL, "threshold-check"), max_ttl_ms=120_000)


def policy(capability, disclosed, subject, rec: Recommendation) -> Recommendation:
    """The decider's own rule, in code, with the facts in front of it. The model's answer is only a recommendation."""
    if rec.verdict == "pass" and disclosed.get("monthly_income_cents", 0) < THRESHOLD:
        return Recommendation("retry", rec.reasons + ("the decider's policy re-checked and it does not clear",), {})
    return rec


def main(argv=None) -> int:
    args = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    args.add_argument("provider")
    args.add_argument("model")
    args.add_argument("--income", type=int, default=512_000, help="monthly income on the example document, in cents")
    args.add_argument("--base-url", default=None, help="for a local test server only; https or a loopback address")
    opts = args.parse_args(argv)

    try:
        model = uai.connect(opts.provider, opts.model, base_url=opts.base_url, timeout_s=120.0)
    except ValueError as exc:
        print(f"NOT EXECUTED: {exc}")
        return 3

    decider_key, requester_key = Signer.generate(), Signer.generate()
    decider = Decider(decider_key, name="quickstart-decider", implementation="python/uai-quickstart",
                      capabilities=[(CAPABILITY, model.judge(policy))],
                      trust=TrustPolicy(pinned=frozenset({requester_key.agent})))
    requester = Requester(requester_key, trust=TrustPolicy(pinned=frozenset({decider_key.agent})))
    requester.discover(decider.manifest().to_wire())

    document = commit("loan-application-17", {"monthly_income_cents": opts.income, "doc_type": "paystub", "full_name": "Sam Roe"})
    request = requester.request(decider_key.agent, document, CAPABILITY.name, CAPABILITY.version,
                                offer_fields=["monthly_income_cents", "doc_type"],
                                require_evidence=[uai.PROVIDER_CALL, "threshold-check"], max_ttl_ms=600_000)
    accept = requester.on_reply(decider.handle(request.to_wire()).to_wire())
    signed = decider.handle(accept.to_wire())
    verified = requester.on_reply(signed.to_wire())

    print(f"provider: {model.provider}  model: {model.model}")
    for rec in model.log.records:
        print(f"provider call: {rec.call}; recommendation {rec.outcome} ({rec.reason})")
    print(f"decision: {verified.verdict}  allowed: {verified.allowed}  signed by: {verified.envelope.sender[:24]}...")
    for reason in verified.reasons:
        print(f"  reason: {reason}")
    call = verified.evidence.get(uai.PROVIDER_CALL)
    if call:
        print(f"  signed record of the call: request {call['request_sha256'][:16]}...  answer {call['response_sha256'][:16]}...")
    try:
        requester.on_reply(signed.to_wire())
        print("the same decision was accepted twice: THIS IS A BUG")
        return 1
    except Refused as exc:
        print(f"presented a second time: refused ({exc.code})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
