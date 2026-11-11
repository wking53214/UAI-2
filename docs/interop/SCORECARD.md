# Universal AI interface scorecard: before and after UAI-1

The 2026-10-30 external assessment (at `41592fb`) scored CNS **2.5/10** as a universal AI interface and named the
milestone that would move it most: two genuinely independent systems, using different implementations, exchanging a
request, negotiating boundaries, exchanging evidence and independently verifying the decision, without either
surrendering its authority. This branch builds that milestone.

The "after" column is this branch's own projection against the assessment's ten dimensions. The assessor's rubric is
not published, so it is a claim to be checked, not a score. Each row names the evidence and what still holds it back.

| dimension | before | projected | evidence on this branch | still missing |
|---|---|---|---|---|
| Shared contract foundation | 5 | 6 | `docs/interop/UAI-1.md`; `contracts/uai-vectors.json` beside the digest vectors | one implementation outside this repository |
| Common decision vocabulary | 5 | 6 | CNS `GateOutcome` verdicts signed and verified by a second language | richer verdict semantics (conditions, partial approvals) |
| Cross-system decision composition | 4 | 5 | a SuperGate decision exported with its root (`decision.from_super_gate`), verified by Node | composing verdicts from several remote deciders into one |
| Vendor/model independence | 3 | 4 | a Node agent with its own encoder, parser and OpenSSL crypto, no CNS import | adapters for actual model APIs; the reference agents decide by rule |
| Universal communication protocol | 1 | 4 | versioned envelope, strict wire, stable refusal codes, two interoperating implementations | encryption, sessions, streaming, a third language |
| Agent discovery and capability negotiation | 1 | 4 | signed manifests; terms set by the decider and checked by the requester before any disclosure | registries and search; negotiation beyond fields, evidence and lifetime |
| Federated identity and trust | 1 | 3 | self-certifying identities; domain-scoped, expiring endorsements; revocation | chains, delegation, key rotation, revocation lists; Node pins only |
| Distributed authorization | 1 | 4 | public-key decisions any process verifies; audience binding; `FileLedger` shared by processes; `interop/act.py` acts once | a ledger shared across hosts; delegation of authority |
| Privacy-preserving interoperability | 2 | 3 | salted per-field commitments; only agreed fields opened; over-disclosure refused | confidentiality in transit; purpose and retention terms |
| External ecosystem adoption | 1 | 1 | nothing: no outside party uses it yet | an outside implementer or user |
| **average** | **2.4** | **4.0** | | |

The assessment's headline was 2.5 against a row average of 2.4, so the projection is read the same way: about 4.

## Independent review

Before the pull request, a separate reviewer that had not seen the work being written attacked it and proved ten
findings with scripts: the action guard trusted the decider named in the job it was handed, the guard could open
twice under concurrent calls, a third party could use up a requester's pending accept, the Node decider took accepts
for lapsed offers and with extra fields, unknown senders could make the Python decider re-check piles of
endorsements, hostile JSON could crash the Python reader, ledger entries could be made permanent, the two Ed25519
paths disagreed on non-canonical and small-order keys, and Node took a non-text evidence kind. Every one is fixed on
this branch and kept as a test (`cns_interop/tests/test_session.py`, `test_envelope.py`, `test_uai_vectors.py`,
`interop/node/agent.test.mjs`, and two new rejection vectors).

## How to check it yourself

```
python -m pytest -q cns_interop/tests        # 100+ tests, including both implementations against one answer key
node --test interop/node/test.mjs interop/node/agent.test.mjs   # the Node implementation alone
python interop/demo.py                       # the two-language exchange, both directions, with the attacks
```

## The STACK spine

The evidence spine now carries the roster's approval across the process boundary (`chains/evidence_spine.py`, the
PORTABLE scenarios): the roster signs its SuperGate decision, and the kernel and CCC act on it through
`RemoteDecisionGuard`, verified by a separate program that shares only the ledger file. This addresses the first
item the assessment held against the spine score, "authorization is still process-local". What it does not change:
the in-process `DecisionGuard` scenarios stay as they were, single use holds only per shared ledger (recorded as a
GAP), and a kernel built with no guard at all can still be called directly (the existing GAP). The spine's other
open items (lifecycle, caller-built seams, coverage of ZTS, Sentinel OS and GSA-815) are untouched.
