# UAI-1: the universal AI interface, version 1

> **Check of 2026-11-07.** Every test name and repository file this page cites was confirmed to exist in this repository. Claims about the outcome of earlier runs and about other repositories were not re-run or re-verified.
UAI-1 is how two independent systems exchange a request, agree terms, disclose what was agreed, and return a
decision the receiver can verify on its own. Neither system has to import the other, share a process, share a
language, or give up its own rules. This document is the specification. Two implementations follow it and share no
code:

| implementation | where | signatures | tests |
|---|---|---|---|
| Python reference | `cns_interop/` | RFC 8032 written out, stdlib only | `cns_interop/tests/` |
| Node | `interop/node/uai.mjs` | Node's built-in OpenSSL Ed25519 | `interop/node/test.mjs` |

Both are held to one answer key, `contracts/uai-vectors.json`, and `interop/demo.py` runs them against each other in
both directions.

## 1. Values and the digest

Every digest in UAI-1 is the CNS subject digest (`cns.gate.subject_digest`): SHA-256 over a length-prefixed
canonical encoding, already published for other languages in `contracts/digest-vectors.json`.

| value | encoding |
|---|---|
| null | `n:` |
| true, false | `b:1`, `b:0` |
| integer | `i:<decimal>:` |
| text | `s:<length in Unicode code points>:<text>` |
| list | `l:<count>:` then each item |
| mapping | `d:<count>:` then each key and value, keys sorted by code point |

The UAI-1 **value profile** is narrower than CNS: text, booleans, null, integers within plus or minus (2^53 - 1),
lists, and mappings with text keys, nested at most 32 levels. **No floats**: send a decimal as text or as an
integer in the smallest unit. Text must be valid Unicode (no unpaired surrogates).

## 2. The envelope

Every message is one JSON object with exactly these fields:

| field | value |
|---|---|
| `v` | `"uai/1"`. A receiver refuses any other value; it never guesses at a dialect. |
| `kind` | one of `manifest`, `endorsement`, `request`, `offer`, `accept`, `refuse`, `decision`, `revocation` (added in revision 2, see section 3) |
| `id` | 32 lowercase hex digits, random, unique per message |
| `from` | the sender's identity (section 3) |
| `to` | the one identity it is addressed to, or `""` for a broadcast |
| `conversation` | the `id` of the message that opened the exchange |
| `in_reply_to` | the digest of the whole envelope this answers (all fields including `sig`), or `""` |
| `issued_at` | integer milliseconds since the Unix epoch |
| `expires_at` | integer milliseconds after `issued_at`, or null |
| `body` | a mapping, in the value profile |
| `sig` | 128 lowercase hex digits |

**Signature.** `sig` is Ed25519 (RFC 8032, pure, no prehash) by the key `from` names, over the bytes
`"uai/1 sig\n"` followed by the ASCII hex subject digest of the envelope **without** `sig` (with `v`).
Verification is strict, identically in every implementation: the public key and R must be canonical point encodings
(y below p, and no sign bit where x is 0), s must be below the group order, and a public key of small order (the
eight 8-torsion points, listed in `interop/node/uai.mjs`) never verifies, since anyone can sign for one.

**Wire.** JSON text, UTF-8, at most 1 MiB, one envelope per line on stream transports. A reader refuses duplicate
keys, any number with a fraction or exponent, NaN and Infinity, and anything that is not a JSON object. Key order and
spacing do not matter; the signature is over the canonical digest.

**Checking a received envelope**, in this order, each failure a refusal with the stable code shown:

1. exactly the fields above, each in its form (`malformed`); `v` is `uai/1` (`version`); `kind` is one this step
   accepts (`kind`); `body` is in the profile (`profile`)
2. the signature verifies as `from` (`signature`)
3. `issued_at` is not more than the allowed skew (default 120 s) in the future (`not_yet_valid`)
4. now is before `expires_at` (`expired`)
5. `to` is this receiver, where an audience is expected (`audience`)
6. this `(from, id)` has not been accepted before, from the receiver's ledger (`replayed`)

Messages in a session (request, offer, accept, refuse, decision) must expire, and may claim at most 24 hours of
life. A receiver keeps each ledger entry only until its message would be refused as expired (on a shared PostgreSQL ledger,
`keep_ms` after that, by the database's clock; section 7c), so a sender cannot make a receiver remember it forever. A manifest carries at most 8 endorsements and 64 capabilities.

## 3. Identity and trust

An identity is `uai:ed25519:` followed by the 64 lowercase hex digits of an Ed25519 public key. It is
self-certifying: nothing is looked up to check a signature.

Whether to **deal** with an identity is the receiver's decision alone. Two ways in:

- **Pinned**: the receiver lists the identity.
- **Endorsed**: an `endorsement` envelope, body exactly `{"subject": <identity>, "domain": <text>}`, `to` the
  subject, signed by an authority the receiver recognises **for that domain**, with an `expires_at` (one without
  expiry is refused). Endorsement is one level deep.

- **Revocation and rotation statements** (revision 2): a `revocation` envelope, body exactly `{"subject", "action",
  "successor", "reason", "effective_at"}`. `subject` is an identity or an endorsement id; `action` is `revoke` or
  `rotate`; `successor` is `""` for a revoke and another identity for a rotate. The subject may sign either; a
  receiver-listed authority may sign `revoke`; nobody else is heard. A revoke only reduces trust. A rotate can add it,
  so a receiver follows one only if it chose to (`follow_rotation`) and only from a pinned predecessor, and an
  authority's revoke of a key that already rotated withdraws the successor. There is no un-revoke. The receiver stores
  statements itself (`cns_interop.revocation.RevocationStore`) and may bound their staleness: past
  `max_staleness_ms`, or never refreshed, it refuses as `unavailable`. An implementation that does not know the
  `revocation` kind refuses it as `malformed`, which fails closed. See `docs/migrations/uai-1-revision-2.md`.

A receiver may revoke identities and endorsement ids; revocation beats every yes. A receiver admits an endorsed
sender once, when it reads that sender's manifest, and remembers the admission until the endorsement lapses; a sender
it does not admit leaves nothing behind.

## 4. Discovery: the manifest

A `manifest` (broadcast, `to` is `""`) has body exactly:

```
name, implementation    text
protocols               list of versions spoken; a reader that shares none refuses (version)
capabilities            list of capabilities
endorsements            list of endorsement envelopes (may be empty)
```

A capability is exactly `name` (lowercase name), `version` (positive integer), `summary` (text), `accepts` (field
names it can use), `requires` (field names it must see, a subset of accepts), `evidence` (evidence kinds it can
return), `max_ttl_ms` (positive integer). A lowercase name matches `[a-z0-9][a-z0-9._-]{0,63}`.

A manifest is a claim. The contract is the offer.

## 5. The exchange

```
requester -> decider   request    capability, version, subject, offer_fields, require_evidence, max_ttl_ms
decider   -> requester offer      {"terms": ...}         or refuse {"code", "reasons"}
requester -> decider   accept     {"terms_digest", "disclosure"}
decider   -> requester decision   section 7              or refuse
```

`subject` is `{"identity": <document name>, "digest": <document digest, section 6>}`.

**Terms**, set by the decider:

| field | value |
|---|---|
| `capability`, `version` | from the request |
| `decider`, `requester` | the two identities |
| `subject` | from the request |
| `disclose` | sorted: fields offered AND accepted. Every required field must be offered, or the decider refuses (`terms`). |
| `evidence` | exactly `require_evidence`, each one the capability returns, or refuse (`terms`) |
| `decision_ttl_ms` | the smaller of the capability's `max_ttl_ms` and the request's |

The requester checks the terms before disclosing anything and refuses terms that name other parties, another
document, another capability, fields it did not offer, other evidence, or a longer life. `terms_digest` is the
subject digest of the terms. An offer accepts one accept, before the offer expires.

## 6. Selective disclosure

Each field of the document is committed separately:

```
commitment(name) = digest({"field": name, "salt": salt, "value": value})     salt: 32 random hex digits per field
document digest  = digest({"commitments": {name: commitment, ...}})            over every field
```

The accept's `disclosure` is exactly `{"commitments": {every field}, "disclosed": {name: {"salt", "value"}}}`.
The decider refuses (`disclosure`) unless the commitments produce the subject digest, every opening matches its
commitment, every agreed field is opened, and **no other field is opened**. Over-disclosure is refused, not
ignored. Undisclosed fields stay hidden; the decision still names the whole document.

**Nothing to disclose.** When the terms disclose no field (the requester offered none, or the capability accepts
none), the accept's `disclosure` is `null` and anything else is refused (`disclosure`). The decider judges the
document by its identity and digest from what it already holds, and the decision is bound to them as named. This is
how a party that will act on a decision (a kernel, a store) asks the roster that judged the document, without
sending it again.

## 7. The decision

A `decision` answers the accept (`in_reply_to` is the accept's digest), is addressed to the requester, and expires no
later than `decision_ttl_ms` after it is issued. Body exactly:

| field | value |
|---|---|
| `verdict` | `"pass"`, `"retry"` or `"terminal_breach"` (CNS `GateOutcome`) |
| `terms_digest` | the terms it was made under |
| `subject` | the terms' subject |
| `reasons` | list of text |
| `evidence` | list of `{"kind", "content", "digest"}`, `digest` the subject digest of `content`; a pass carries exactly the kinds the terms name, any verdict carries none the terms did not name |
| `cns_root` | the SuperGate root when a CNS roster made the decision, else `""` |

A verifier refuses a decision not signed by the terms' decider (`untrusted`), and a requester does not close its
pending accept until a decision from that decider verifies, so a third party cannot use the accept up. It also
refuses one answering another accept, under other terms, about another document, living too long (`terms`, `subject`), with evidence that does not match its digest
(`malformed`), or already accepted (`replayed`). A decider whose capability fails issues a signed
`terminal_breach` saying so.

**Acting on a decision.** Single use is enforced per audience: the decision is addressed to one identity, every
other receiver refuses it at `audience`, and every process acting for that identity shares one ledger
(`cns_interop.ledger.FileLedger` on one host). `cns_interop.decision.RemoteDecisionGuard` opens once, for the
judged document only, also under concurrent calls. Its configuration is its own and never comes with the job: the
identity it acts for (terms for anyone else are refused), the capability it protects as a `(name, version)` pair
(a decision negotiated for another capability or version is refused as `terms`, so an approval to `ingest` a
document cannot open an action guarded for something else), the deciders it trusts (a decider the terms name but the
guard does not trust is refused), and its ledger. `interop/act.py` takes all four on its command line
(`--acting-for`, `--capability`, `--capability-version`, `--trust`, `--ledger`). `capability` is a required keyword
of `RemoteDecisionGuard`; code written before it was added must pass it.
A running guard stops trusting a decider with `guard.revoke(agent)`: a decider revoked before `authorize` is refused as
`untrusted`, and one revoked after it closes the guard, so the next call answers False.

## 7a. What this receiver permits (receiver-side, not on the wire)

A verified decision is not permission. `cns_interop.grants.GrantTable` is the receiver's own policy, default deny:
a `Grant` names the capability (a purpose is a capability name that carries it, e.g. `income-screen.loan-underwriting`,
so no wire field is added), the version, the requester it is for, the deciders it accepts, the actions it permits, a
ceiling on the fields it will disclose, an optional expiry, and optional approvers. `check_terms` runs on an offer before
anything is disclosed; `permit(action, verified, terms)` runs before an action.

What `permit` enforces, in revision 3: the terms handed to it must hash to the `terms_digest` the decider signed (terms
the decision was not made under are refused as `terms`, even when a grant matches them); the permit is **single use**, a
lease on `(decision, action)` in the permit ledger that `complete()` spends and `abort()` returns (a second permit for the
same decision and action is `replayed`); a withdrawal written to a `GrantStore` survives a restart and is seen by every
process sharing it; the audit record chains onto the real last entry under a file lock, so several writers keep one
unbroken chain; an unreadable store, ledger or audit refuses (`unavailable`) and a permit whose audit write fails gives
its lease back. Refusals: `no_grant`, `grant_expired`, `withdrawn`, `decider`, `action`, `disclosure`,
`approval_required`, `approval`, `refused`, `terms`, `replayed`, `unavailable`.

**Where it is enforced.** `RemoteDecisionGuard(grants=, action=)` opens only for a live Permit, and `interop/act.py`, the
process that performs the action, takes the receiver's policy from its command line and **refuses to start without it**
(`--grants`, `--grant-store`, `--action`, `--audit`). `--decision-only` keeps the revision 2 behavior, in which a
signature alone opens the action; it says so on stderr and is not receiver-authorized. A refusal a person or operator can
cure (no approval yet, a grant added later) does not burn the decision, because the decision is leased while policy is
checked; a replay does.

An action that needs a person needs an `Approval` signed by a listed approver, bound to one decision, one action and one
document, with an expiry; an approver is never the decider or the requester. Every outcome is appended to a hash-chained
audit record. Delegation is not implemented: a grant is for the requester it names. A manifest remains an advertisement;
nothing a sender signs adds to a grant. The Node implementation does not yet have grants (planned, Tier 3).

## 7b. What a receiver spends before it knows the sender (receiver-side)

Verification is never weakened; whether to spend it is the receiver's call. `Decider` drops a message from a sender it has not
admitted before checking its signature and signs nothing for it (`unknown_sender="drop"`, default; `"refuse"` restores the signed
refusal), refuses a message with more than `Limits.max_nodes` values before the signature (default 20000), and can be given a
`RateLimiter` (a global bucket that holds against rotating claimed identities, and a per-sender bucket) that is consulted
before anything else. `wire.loads(max_bytes=)` lets a receiver read less than the 1 MiB ceiling. Measurements and method:
`docs/interop/bench/preauth-2026-10-31.json`.

## 7c. Clock trust on a shared ledger (receiver-side, not on the wire)

Nothing on the wire changes. This section is what a production-secure receiver does about the clock it judges lifetimes by;
the requirements, the test that shows each, and the limits are in `SECURITY_PROFILES.md` ("Clock trust in the
production-secure receiver"). In short:

- A shared PostgreSQL ledger judges a message's lifetime by the **database's** time, and refuses (`expired`) a message that has
  expired by it before writing anything. It forgets a row `keep_ms` (120 s) after the message expired. *Implemented, tested.*
- Under `UAI_PROFILE=production` both runners require `--max-clock-skew-ms`, strictly below `keep_ms` (otherwise `config`),
  read the database's time at start-up and for every decision, and judge every lifetime by it. *Implemented, tested.*
- The failures are typed with registered codes: `unavailable` (no definite or plausible answer from the database),
  `clock_skew` (host and database disagree by more than the tolerance), `config` (an invalid or missing setting). They
  consume nothing, and are audited where a record is reachable and always written as one structured line. *Implemented,
  tested.*
- Not proved: more than one host (one machine, one clock), and a database host whose own operating-system clock drifts
  (the tests make the server answer a wrong time instead). The reference is one database clock; keeping it correct is the
  operator's duty.

## 8. What remains open

UAI-1 is a foundation, not the whole interface. Not specified or implemented here:

- **Confidentiality and sessions.** Envelopes are authenticated, not encrypted. Run them over TLS or another
  confidential channel. There is no key agreement or session layer.
- **Federation beyond one level.** No endorsement chains, delegation or published revocation lists (statements are
  signed and stored by each receiver; how they reach it is its own business). The Node implementation pins only.
- **A shared ledger across hosts.** Single use holds per audience on one host (`FileLedger`, `SqliteLedger`);
  several hosts acting for one identity need `CoordinatedLedger` over a linearizable store the receiver owns, and
  refuse (`unavailable`) when that store gives no definite answer. No real store adapter ships: the in-memory
  coordinator is a test stand-in, and a real backend must pass `cns_interop/ledger_conformance.py` and its own
  partition tests. Guarantee by ledger: `MemoryLedger` one process; `FileLedger` and `SqliteLedger` one host;
  `CoordinatedLedger` many hosts only as far as its coordinator is linearizable. Two local ledgers on two hosts accept
  one decision twice. `reserve`, `commit` and `release` (leases) make an action recoverable after a crash and
  at-least-once, so the action must be idempotent on the idempotency key (`RemoteDecisionGuard.idempotency_key`).
- **Model and vendor adapters.** The protocol is model-agnostic; no adapter wraps a specific model API yet, and the
  reference agents decide by rule.
- **Policy negotiation beyond fields, evidence and lifetime**, such as purpose limitation, retention or jurisdiction.
- **Registries and search.** Manifests are exchanged directly; there is no directory.
- **Signing hardening.** The default Ed25519 is the pure-Python RFC implementation, which is not constant time.
  `cns_interop.crypto_backend` adds an optional `cryptography` (OpenSSL) backend, chosen explicitly
  (`UAI_CRYPTO_BACKEND=cryptography`, no fallback if missing) and required for local seeds under
  `UAI_PROFILE=production`. Both backends accept exactly the same signatures (strict checks first, then a differential
  test); no side-channel resistance is claimed or measured. For keys that must never be in this process, use
  `Signer.external` with a keystore or HSM function. A `Signer` refuses pickling and copying. The only algorithm is
  `ed25519`, named in the identity; any other is refused, never mapped.


## 9. Revision 4 (what was added, and what did not change)

The wire format, signatures, digests and every existing refusal code are unchanged. Added: a frozen cryptographic profile
(`UAI_PROFILE=production` needs `UAI_CRYPTO_BACKEND=cryptography`, read once); security and transport profiles with an
implemented TLS 1.3 mutual-authentication profile (`SECURITY_PROFILES.md`); a Node receiver with the same authorization rules
as Python (`interop/node/grants.mjs`); a selectable ledger backend and a shared PostgreSQL policy and audit store for the
action runner; a JSON Schema, a versioned error registry and a conformance suite for independent implementers
(`contracts/uai1/`); OpenAI and Copilot provider clients. Migration: `docs/migrations/uai-1-revision-4.md`. Assessment:
`UAI1_R4_ASSESSMENT.md`. Open: no live call to Gemini, OpenAI or Copilot (Anthropic was called live on 2026-11-04 and
every real answer was refused by the strict reader, see the assessment), no independent implementation, no multi-machine run, delegation
deliberately not specified.
