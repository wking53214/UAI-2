# Implementing UAI-1 without CNS

> **Check of 2026-11-07.** Every test name and repository file this page cites was confirmed to exist in this repository. Claims about the outcome of earlier runs and about other repositories were not re-run or re-verified.
This is the guide for an engineering team that wants to implement UAI-1 in its own language and check the result, without
reading CNS source. It states what an implementation must do, how to test it, and what is **not** established.

Honest status: UAI-1 has two implementations, Python and Node, **written inside one project**. They agree with each other
(shared vectors, a conformance suite, differential receiver tests). That is evidence the specification is precise enough
for two implementations from one team to agree. It is not evidence that a third party, working only from these documents,
would conform. **No independent implementation has been run.** If you build one, running the suite below and reporting every
disagreement is the most useful thing you can do: each is either a bug in yours, a bug in ours, or an ambiguity in the text.

## What you get

| File | What it is |
|---|---|
| `docs/interop/UAI-1.md` | the specification (envelope, identity, trust, manifest, exchange, disclosure, decision, receiver rules) |
| `contracts/uai1/schema.json` | JSON Schema for the envelope, every body, terms, approval, grants file and job. Shape only |
| `contracts/uai1/errors.json` | the versioned error registry: every refusal code, its layer, whether a retry can help, whether it spends the message |
| `contracts/uai1/conformance-suite.json` | 33 cases as plain data: valid, malformed, ambiguous, tampered, expired, replayed, unauthorized |
| `contracts/uai1/run_conformance.py` | stand-alone runner (standard library only) that drives your adapter program through the suite |
| `contracts/uai-vectors.json`, `contracts/digest-vectors.json` | signed envelopes and the canonical digest answer key |
| `docs/interop/SECURITY_PROFILES.md` | crypto and transport profiles, and what each does not give |
| `interop/conformance/reference_adapter.py`, `interop/node/conformance_adapter.mjs` | two example adapters (about 30 lines each) |

## Minimal implementation, in order

1. **Strict reading.** Parse UTF-8 JSON of at most 1 MiB. Refuse duplicate keys (including ones that differ only by a
   `\u` escape), floats, exponents, NaN and Infinity, integers beyond +/-(2^53 - 1), values nested past the limit, and
   anything that is not an object. Codes: `malformed`, `profile`.
2. **Canonical digest.** Implement the length-prefixed canonical encoding and SHA-256 and match every vector in
   `contracts/digest-vectors.json` before anything else. Everything signed depends on it.
3. **Identity and signature.** `uai:ed25519:` plus 64 lowercase hex of the public key. Sign `"uai/1 sig\n"` followed by the
   ASCII hex digest of the envelope without `sig`. Verification must be **strict**: canonical point encodings (key and R),
   `s` below the group order, and never accept a public key of small order. A library that accepts what these rules refuse
   will disagree with the reference on the `small-order-key` and `non-canonical-key` cases.
4. **The envelope check, in order:** fields and forms, version, kind, body profile, signature, not too far in the future,
   not expired, audience, then replay by `(from, id)`. Refusal codes are in `errors.json`.
5. **Trust.** Whether to deal with an identity is the receiver's decision. Pinned identities, endorsement and revocation are
   in the specification. Never treat a valid signature as trust or as permission.
6. **Run the suite** (below). Fix until it passes; report what disagreed.
7. **Then** the session (manifest, request, offer, accept, decision), disclosure, and the receiver rules for acting.

## Running the conformance suite

Write an adapter: a program that reads one JSON request per line on stdin and writes one JSON answer per line on stdout.

```
{"op": "reset"}                                                   -> {"ok": true}
{"op": "receive", "wire_text": "<raw text>", "now": <ms>,
 "trust": ["<identity>", ...] | null, "audience": "<identity>" | null,
 "kinds": ["<kind>", ...] | null, "ledger": true | false}
                                                                   -> {"accept": {"digest": "<hex>"}}  or  {"refuse": "<code>"}
```

`receive` is what a receiver does to arriving bytes: read strictly, open the envelope, admit the signer only if `trust`
names it (when not null), and when `ledger` is true, spend the message once. `reset` forgets every spent message. Then:

```
python contracts/uai1/run_conformance.py --cmd "your-adapter-command"
```

Exit status 0 means every case passed. A case marked `basis: "reference"` is one the two shipped implementations agree on
but the specification text does not fix. Report a disagreement there as a question. The runner has been shown to fail an
implementation that accepts everything and one that refuses everything.

## Security requirements (MUST)

- Check signatures strictly (step 3). Do not fall back to a lenient verifier.
- Judge every message's lifetime with a trustworthy clock. A receiver whose clock is set back accepts expired messages;
  this is a recorded deployment limitation, not something the protocol can fix.
- Keep the replay ledger durable and shared by every process that acts for the same identity. An in-memory ledger is a
  single process only.
- A signature is never permission. Act only under the receiver's own grants, bound to one decision, one action and one
  document, and require a person's approval where the grant says so. An approver is never the decider or the requester.
- Fail closed. If the ledger, the grant store or the audit record cannot give a definite answer, nothing is permitted.
- Do not log, store or return secrets. A key identifier is a label, not a secret.
- Choose a transport profile (`SECURITY_PROFILES.md`). Anything leaving the host or a trust boundary needs `tls13-mutual`.

## Examples

Runnable, using only the supported API: `interop/examples/quickstart.py`, `interop/examples/quickstart.mjs`,
`interop/examples/provider_adapter.py`. Signed example messages are in `contracts/uai-vectors.json`; the schema's
`$defs` name every body.

## What this package does not establish

That a third party can implement UAI-1 from it (no one has), that the specification is free of ambiguity beyond the 33
cases, that the two shipped implementations are correct against anything outside this repository, or anything about the
content a participant sends. Delegation is deliberately not specified.
