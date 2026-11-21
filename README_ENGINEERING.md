# UAI: engineering specification and implementation guide

For engineers, protocol designers, reviewers and anyone implementing the contract independently.
[README.md](README.md) is the introduction; this page is the detail behind it. The two describe the same system.

Checked on 2026-11-18 at commit `c6c1033`. Names in `code font` are the real names in source. Where this page says
something was "run", it was executed on that date in one Linux container (Python 3.13.18, Node 22.23.5, PostgreSQL 16
server binaries, CNS `v4.0.0`), with no live provider call. Everything else was read from source.

Contents: [A. Overview](#a-technical-overview) ·
[B. Contracts](#b-protocol-and-contract) ·
[C. Provider abstraction](#c-provider-abstraction) ·
[D. UAI-1 implementation](#d-uai-1-implementation) ·
[E. UAI-2 implementation](#e-uai-2-implementation) ·
[F. CNS](#f-cns-integration) ·
[G. Security](#g-security-and-integrity) ·
[H. Testing](#h-testing-and-conformance) ·
[I. Implementing it yourself](#i-independent-implementation-guide) ·
[J. Limitations](#j-known-limitations-and-open-questions) ·
[K. Source cross-reference](#k-source-cross-reference)

## A. Technical overview

The repository contains two layers with different maturity. They should be judged separately.

| | Layer A: provider-neutral model interface ("UAI-2") | Layer B: signed decision protocol ("UAI-1") |
|---|---|---|
| Purpose | call several model providers through one request and response shape | let two separate systems request, sign and verify a decision |
| Code | `uai/` (5 files), `cns_interop/providers.py` | `cns_interop/` (Python), `interop/node/` (Node) |
| Written specification | none; section B1 of this page describes the code | [docs/interop/UAI-1.md](docs/interop/UAI-1.md) |
| Implementations | one, Python | two, Python and Node, written by the same project |
| Conformance suite | none | 72 cases, covering the receive operation |
| Wire version | none | `uai/1` |

"UAI-2" is not a protocol version. It is the name of this repository and of the provider-interface work in it, whose
modules were first named `uai2_*`. The installable package is `uai`, version 0.1.0.

How the layers join:

```
   requester                                decider
   ---------                                -------
   commit(document)                         capability + judge
        |                                        |
        |-- request ---------------------------->|
        |<------------------------------ offer --|   terms set by the decider
        |-- accept (agreed fields only) -------->|
        |                                        |-- render_prompt --> provider client --> model
        |                                        |<-- text (untrusted) -------------------------
        |                                        |   parse_recommendation   (strict, repairs nothing)
        |                                        |   policy(...)            (the decider's own code)
        |                                        |   issue(...)             (signed by the decider's key)
        |<--------------------------- decision --|
   verify_decision                               
        |
   RemoteDecisionGuard + GrantTable         (receiver's own permission, separate from the signature)
```

Component responsibilities:

| Component | Responsibility | Does not |
|---|---|---|
| `uai.connect` | choose a provider client by name, read its key from the environment | infer a provider from whichever key is set; send anything |
| `cns_interop.providers` | the only module that opens a connection to a provider; bounded, no redirects, records each call | sign, decide, or hold authority |
| `cns_interop.adapter` | read a model's output strictly; apply the decider's policy | repair output; let a model's pass stand without the policy |
| `cns_interop.session` | the two roles, `Decider` and `Requester` | share state between them; everything crosses as a signed envelope |
| `cns_interop.envelope`, `wire` | the message shape, strict reading, signature check, time and audience checks | check replay (that needs a ledger) |
| `cns_interop.ledger*` | remember accepted messages; single use; leases | provide consensus across hosts |
| `cns_interop.grants` | the receiver's own permission to act | accept a signature as permission |
| `cns` (external) | the digest function and the verdict vocabulary | anything else on this path (section F) |

## B. Protocol and contract

### B1. The typed model contract (Layer A)

Defined in [uai/protocol.py](uai/protocol.py). Pure data, no I/O. There is no separate specification document; this
section and the source are the contract.

`ModelRequest` (frozen dataclass):

| Field | Type | Constraint enforced at construction |
|---|---|---|
| `model` | `str` | non-empty after stripping |
| `system_instruction` | `str` | any string |
| `user_messages` | `tuple[str, ...]` | non-empty tuple; each non-empty after stripping |
| `max_output_tokens` | `int` | positive; `bool` refused |
| `generation_settings` | mapping of `str` to `str`, `int`, `float`, `bool` or `None` | names non-empty after stripping; floats finite; stored read-only |

`ModelResponse` (frozen dataclass):

| Field | Type | Constraint |
|---|---|---|
| `content` | `str` | any string |
| `provider` | `str` | non-empty after stripping |
| `model` | `str` | non-empty after stripping |
| `completion_status` | `CompletionStatus` | one of `complete`, `max_tokens`, `stopped`, `unknown` |
| `usage` | `TokenUsage` or `None` | `input_tokens`, `output_tokens`: non-negative integers |
| `request_id` | `str` or `None` | non-empty after stripping, if present |
| `native_response` | object or `None` | provider-specific data, kept apart from the normalized fields |

`ModelProvider` is a `typing.Protocol` with one method: `generate(request: ModelRequest) -> ModelResponse`. It is
synchronous. There is no streaming, tool calling, multi-turn conversation, or image input in the contract.

**The portable profile.** The only implementation, `uai.bridge.PortableTextProvider`, accepts a narrower request than
the dataclass allows, so that one request means the same thing on every provider:

| Rule | Failure |
|---|---|
| `request.model` equals the configured model | `ValueError` |
| `system_instruction` is empty | `ValueError` |
| exactly one user message | `ValueError` |
| `max_output_tokens` is exactly 512 (`PORTABLE_MAX_OUTPUT_TOKENS`) | `ValueError` |
| `generation_settings` is empty | `ValueError` |

These are checked before anything is sent. A request outside the profile is a caller error, not a provider failure.

**Execution status.** `completion_status` is derived from the provider's own finish reason in
`uai/connect.py`: `end_turn`, `STOP`, `stop` map to `complete`; `max_tokens`, `MAX_TOKENS`, `length` map to
`max_tokens`; anything else, including a provider that does not report a reason, maps to `unknown`. `stopped` is
defined in the enum and is not produced by the current code.

**Errors.** Any failure of the provider call leaves the bridge as `ProviderExecutionError(category, reason)`. The
original exception is deliberately not chained, so nothing a provider library put in its own exception travels with
it. Categories produced today: `timeout`, `connection_error`, `rate_limit` (HTTP 429), `authentication` (401),
`permission` (403), `http_error` (any other non-2xx), `response_too_large`, `invalid_response`, `provider_error`,
and from the bridge itself `identity_mismatch`.

**Provider identity.** `ModelResponse.provider` and `.model` are the labels the caller configured. The bridge checks
that the result carries the same labels, which guards against a wiring mistake. It is not verification of which
service or model actually answered. What the provider itself reported is kept in
`native_response["model_reported"]`.

**Provenance record.** Each call appends a `cns_interop.providers.Provenance` row:
`provider`, `model_requested`, `model_reported`, `request_sha256`, `response_sha256`, `latency_ms`,
`finish_reason`, `call`, `outcome`, `reason`, `http_status`, `input_tokens`, `output_tokens`, `request_id`.
The two digests are SHA-256 of the exact request bytes sent and response bytes read. The typed bridge keeps no
record between calls; `Connection.log` keeps them for the decision path.

### B2. UAI-1 (Layer B)

The specification is [docs/interop/UAI-1.md](docs/interop/UAI-1.md). This is a summary with pointers, not a
replacement. Shapes are also in [contracts/uai1/schema.json](contracts/uai1/schema.json) (shape only: a schema cannot
check a signature, a time window, a digest or replay).

**Envelope.** One JSON object with exactly eleven fields:

| Field | Form |
|---|---|
| `v` | `"uai/1"` |
| `kind` | `manifest`, `endorsement`, `request`, `offer`, `accept`, `refuse`, `decision`, `revocation` |
| `id` | 32 lowercase hex digits |
| `from` | `uai:ed25519:` plus 64 lowercase hex digits |
| `to` | an identity, or `""` for a broadcast |
| `conversation` | 32 lowercase hex digits |
| `in_reply_to` | 64 lowercase hex digits (digest of the whole envelope answered), or `""` |
| `issued_at` | integer milliseconds since the Unix epoch, zero or more |
| `expires_at` | integer milliseconds, strictly later than `issued_at`, or `null` |
| `body` | a mapping in the value profile |
| `sig` | 128 lowercase hex digits |

**Value profile.** Text, booleans, null, integers within plus or minus (2^53 - 1), lists, mappings with text keys,
at most 32 levels counted from the body. No floats.

**Signature.** Ed25519 (RFC 8032, no prehash) by the key `from` names, over the bytes `"uai/1 sig\n"` followed by the
ASCII hex digest of the envelope without `sig`. Verification is strict: canonical encodings for the key and R, `s`
below the group order, and the eight small-order public keys never verify.

**Serialization and transport.** UTF-8 JSON, at most 1 MiB, one envelope per line on stream transports. Key order
and spacing do not matter, because the signature is over the canonical digest and not over the text. A reader refuses
duplicate keys, fractions and exponents, NaN and Infinity, a byte order mark, and anything that is not a JSON object.

**Check order for a received envelope**, each failure a refusal with a stable code:

1. exactly the eleven field names (`malformed`), then version (`version`), then a known kind (`malformed`) that this
   step accepts (`kind`), then each remaining field's form (`malformed`), then the body profile (`profile`)
2. signature (`signature`)
3. not issued more than the allowed skew in the future, default 120 s (`not_yet_valid`)
4. now is before `expires_at` (`expired`)
5. addressed to this receiver (`audience`)
6. trust, where the receiver restricts senders (`untrusted`)
7. not accepted before, by the receiver's ledger (`replayed`)

Two details of the code that the list above hides. Both implementations look at the version and kind before the
other fields' forms, so a text with a wrong version and a malformed `id` is refused as `version`; UAI-1.md lists
"each in its form" first, and its rule that the code is fixed only for a single defect covers the difference. And a
`Decider` by default drops a `request` or `accept` from a sender it has not admitted before it checks the
signature, answering `untrusted` without step 2 (UAI-1.md section 7b).

**Exchange.** `request`, then `offer` carrying the terms, then `accept` carrying the terms digest and the disclosure,
then `decision`. The decider may answer `refuse` with a code and reasons at either step. A requester that rejects an
offer raises locally and sends nothing.

Request body: `capability`, `version`, `subject`, `offer_fields`, `require_evidence`, `max_ttl_ms`.

Terms (set by the decider, checked by the requester before it discloses anything):
`capability`, `version`, `decider`, `requester`, `subject`, `disclose`, `evidence`, `decision_ttl_ms`.

Capability (in a manifest): `name`, `version`, `summary`, `accepts`, `requires`, `evidence`, `max_ttl_ms`.

**Selective disclosure.** Each document field is committed separately as
`digest({"field", "salt", "value"})`; the document digest is the digest of all commitments. The accept opens
exactly the agreed fields. Opening a field that was not agreed is refused, not ignored.

**Decision body.** `verdict` (`pass`, `retry` or `terminal_breach`), `terms_digest`, `subject`, `reasons`,
`evidence` (a list of `{"kind", "content", "digest"}`), `cns_root`. A pass carries exactly the evidence kinds the
terms name. What `verify_decision` checks, in order: the envelope, that the signer is the decider the terms name,
the reply binding, the body's exact keys, the terms digest, the subject, the verdict, the lifetime against the
terms, the reasons, each evidence digest, the evidence kinds against the terms, then single use through the ledger.

**Refusal codes.** [contracts/uai1/errors.json](contracts/uai1/errors.json) is the registry: 33 codes, each with its
layer, whether a retry can help, and whether the refusal spends the message.

| Layer | Codes |
|---|---|
| wire | `malformed`, `profile` |
| envelope | `version`, `kind`, `signature`, `not_yet_valid`, `expired`, `audience` |
| trust | `untrusted` |
| ledger | `replayed`, `lease_lost`, `fenced` |
| infrastructure | `unavailable`, `clock_skew` |
| pre-auth | `rate_limited` |
| session | `capability`, `terms`, `disclosure`, `subject`, `declined`, `refused` |
| adapter | `adapter_output`, `provider` |
| receiver-policy | `no_grant`, `withdrawn`, `grant_expired`, `decider`, `action`, `approval_required`, `approval`, `stale_policy`, `conflict` |
| operator | `config` |

## C. Provider abstraction

The whole provider dependency is one function shape: `complete(prompt: str) -> str`. Each client in
[cns_interop/providers.py](cns_interop/providers.py) returns such a function as a closure that holds the key.
Standard library only (`urllib`); no provider SDK.

All clients share: `https` only, except `http` to a loopback address; redirects never followed; one deadline for the
whole exchange, enforced on a worker thread; a response size cap of 262,144 bytes; a key containing whitespace or a
control character refused before any request is built; the key sent in one header.

Routes in the module, and their status:

| Client function | Route | Offered by `uai.connect` as | Key header | Default output limit | Called against the real service |
|---|---|---|---|---|---|
| `anthropic_complete` | Anthropic Messages API | `anthropic` | `x-api-key` | 16,000 | yes; rows in `evidence/live-runs/2026-11-11-raw/` |
| `gemini_complete` | Google Gemini `generateContent` | `gemini` | `x-goog-api-key` | none sent | yes; rows in `2026-11-11-raw/`, `2026-11-13-free-panel/`, `2026-11-13-live-signing/` |
| `groq_complete` | Groq (Chat Completions format) | `groq` | `authorization: Bearer` | 512 | yes; several folders |
| `cloudflare_complete` | Cloudflare Workers AI | `cloudflare` | `authorization: Bearer` | 512 | yes; several folders |
| `openai_complete` | OpenAI Chat Completions | `openai` | `authorization: Bearer` | 512 | **no** |
| `copilot_complete`, route `azure-openai` | Azure OpenAI deployment | `copilot-azure`, and `copilot` as an alias | `api-key` | 512 | **no** |
| `copilot_complete`, route `github-models` | GitHub Models | not offered | `authorization: Bearer` | 512 | no; the service was retired by GitHub on 2026-07-30 |
| `openrouter_complete` | OpenRouter (Chat Completions format) | not offered | `authorization: Bearer` | 512 | yes: `evidence/live-runs/2026-11-17-openrouter-adapter/` (1 of 2 calls valid) and as a juror in `2026-11-17-jury-current-prompt/` (23 rows) |

That is seven client functions, eight routes, six of them reachable through `uai.connect`. Other documents say
"seven routes": they count these without OpenRouter.

**What the live runs exercised.** Every committed live run called the client functions directly
(`interop/jury.py`, `interop/live_providers.py`, `interop/live_signing.py`). None went through `uai.connect`, the
typed bridge or `ProviderJudge`, and no live decision carries `provider-call` evidence. Those parts of Layer A have
been exercised against stand-ins only.

What is standardized across providers:

- the call shape and, through the bridge, the `ModelResponse` shape;
- failure categories;
- the provenance record;
- the transport rules above;
- strictness: exactly one text answer that ended normally, otherwise a refusal.

What remains provider-specific:

- the request body and endpoint each client builds;
- the default output limit when the decision path is used (`Connection.complete`): the table above shows they differ.
  Only the typed bridge forces 512 everywhere;
- whether truncation can be detected: older Workers AI catalog models do not report why an answer ended, so
  `uai.connect` marks that route `reports_finish=False` and the bridge reports `unknown`;
- model naming, account identifiers (Cloudflare account id, Azure resource and deployment);
- Anthropic "thinking" blocks are skipped; a `refusal` stop reason is a refusal;
- for OpenRouter, the model that answers can differ from the one asked for; both are recorded.

Adding a provider means one client function and one row in `uai.connect.PROVIDERS`.

## D. UAI-1 implementation

### D1. Python (`cns_interop/`)

| Module | Role |
|---|---|
| `envelope.py` | `seal`, `sign_envelope`, `open_envelope`, `check_profile`, `Refused` |
| `wire.py` | `dumps`, `loads`: strict JSON reading |
| `identity.py` | `Signer`, `agent_id`, `public_of`; `Signer.external` for a key held elsewhere |
| `ed25519.py` | RFC 8032 in pure Python, with the strict acceptance checks |
| `crypto_backend.py` | chooses pure Python or OpenSSL (`cryptography`); frozen under `UAI_PROFILE=production` |
| `trust.py`, `revocation.py` | `TrustPolicy`, endorsements, signed revocation and rotation statements |
| `manifest.py` | `Capability`, `Manifest`, `publish`, `read_manifest` |
| `negotiate.py` | `request_body`, `propose_terms`, `check_terms`, `terms_digest` |
| `disclosure.py` | `commit`, `Committed.reveal`, `open_disclosure` |
| `session.py` | `Decider`, `Requester`, `Judgment` |
| `decision.py` | `issue`, `from_super_gate`, `verify_decision`, `RemoteDecisionGuard` |
| `ledger.py` | `MemoryLedger`, `FileLedger`, `SqliteLedger`, `CoordinatedLedger` |
| `ledger_postgres.py`, `policy_postgres.py` | `PostgresLedger`, `PostgresGrantStore`, `PostgresAudit` |
| `grants.py` | `Grant`, `GrantTable`, `Approval`, `Permit`, hash-chained audit |
| `limits.py` | `Limits`, `RateLimiter`: what a receiver spends before it knows the sender |
| `transport.py` | the `tls13-mutual` profile |
| `adapter.py` | `parse_recommendation`, `AdapterJudge`, `render_prompt` |
| `providers.py` | provider clients (Layer A; it lives in this package for historical reasons) |

`cns_interop` imports only `cns`, `cns_composition`, itself and the standard library; a test enforces this.
`psycopg` and `cryptography` are optional extras.

### D2. Node (`interop/node/`)

`uai.mjs` is the protocol: its own canonical encoder, strict JSON reader and envelope checks, with Ed25519 from
Node's built-in OpenSSL binding. `agent.mjs` is a decider and requester; `grants.mjs`, `act.mjs`, `pg.mjs`,
`pg_policy.mjs` and `fencing.mjs` are the receiver side. It imports only Node built-in modules.

Known differences from Python: Node admits senders by pinning only, not by endorsement; Node has no provider
clients.

### D3. Validation model

A receiver validates in layers, and each layer fails closed with a registered code: strict reading, envelope checks,
trust, replay, then the step's own rules (terms, disclosure, decision). A failure before the sender is authenticated
gets no reply. After it, a trust, capability, terms or disclosure failure gets a signed `refuse`; a replay, or an
accept that matches no open offer, gets none. A capability that raises produces a signed
`terminal_breach`, never a pass.

### D4. Conformance tests

[contracts/uai1/conformance-suite.json](contracts/uai1/conformance-suite.json) holds 72 cases as plain data, run by
[contracts/uai1/run_conformance.py](contracts/uai1/run_conformance.py) (standard library only) against any adapter
program.

| Class | Count |
|---|---|
| `rejected` | 17 |
| `malformed` | 15 |
| `ambiguous-or-malformed` | 14 |
| `valid` | 9 |
| `tampered` | 8 |
| `replayed` | 4 |
| `unauthorized` | 3 |
| `expired` | 2 |

71 are marked `basis: "specification"`. 41 of those carry a `spec` field quoting the text of UAI-1.md that decides
them; the other 30 (the original valid, rejected and strict-reading cases) carry none. One is marked
`basis: "reference"` and illustrates a receiver without a ledger, which the specification says is not conforming.

**Scope.** Every case exercises one operation, `receive`: read the text strictly, open the envelope, apply trust if
given, spend the message if a ledger is requested. The suite does not exercise the request, offer, accept and
decision exchange, disclosure, `verify_decision`, grants, or ledger behaviour under failure. Passing it shows a
conforming receiver, not a complete implementation.

**Where the cases come from.** The signed messages derive from [contracts/uai-vectors.json](contracts/uai-vectors.json),
which the Python implementation generates. Where a case carries a `spec` field, its expected answer is tied to
specification text. A second answer key,
[contracts/uai-interop-vectors.json](contracts/uai-interop-vectors.json), is wider (digest, wire, envelope,
negotiation, decisions and message sequences): its generator imports none of the implementations, its expected
results were typed by hand with a reason each, and its signatures come from the OpenSSL command line. Both
implementations are run against it in `cns_interop/tests/test_interop_campaign.py`. It is not in the implementer kit.

## E. UAI-2 implementation

What Layer A adds on top of UAI-1.

**`uai.connect(provider, model, *, environ=None, log=None, timeout_s=None, base_url=None) -> Connection`.**
Looks the name up in `PROVIDERS`, reads the key from the provider's environment variable, and builds the client. It
raises `ValueError` naming the variable to set, never a key. No request is made. `uai.from_env()` reads
`UAI_PROVIDER` and `UAI_MODEL` (the older `UAI2_PROVIDER` and `UAI2_MODEL` are accepted as the same settings and may
not disagree).

**`Connection`** (frozen dataclass): `name`, `provider` (the provenance label), `model`, `complete`, `log`.
The key is held only inside the client closure, so it is not in the object's representation.

**`Connection.model_provider()`** returns a `PortableTextProvider`: text behind the typed contract, in the portable
profile. A truncated answer is returned with `CompletionStatus.MAX_TOKENS` instead of being refused, except on the
Cloudflare route: there a reported cut-off is refused, and an unreported one comes back as `unknown`.

**`Connection.judge(policy)`** returns a `ProviderJudge`, the object a `Decider` takes beside a capability. It is
`AdapterJudge` plus one thing: when the capability lists the evidence kind `provider-call`
(`uai.PROVIDER_CALL`), a pass carries the record of the call:
`provider`, `model_requested`, `model_reported`, `request_sha256`, `response_sha256`, `finish_reason`.
The model is shown the capability without that evidence kind, so an answer that claims it is refused. A pass with
anything other than exactly one successful call record is refused.

**The strict reader** (`adapter.parse_recommendation`). A model's answer must be one JSON object, read by the same
strict reader as the wire, with exactly the keys `verdict`, `reasons`, `evidence`, `escalate`; a verdict from the
three allowed; at most 16 reasons of at most 500 characters; `escalate` a boolean; evidence a mapping of kind to
mapping, with no kind the capability does not produce. Anything else is `adapter_output`. The written version of
this contract for one capability is [docs/interop/POLICY_CHAIN_SPEC.md](docs/interop/POLICY_CHAIN_SPEC.md).

**The policy** (`adapter.AdapterJudge`). `policy(capability, disclosed, subject, recommendation)` is the decider's
own function. A model's pass stands only if the policy keeps it. The code does not stop a policy from returning a
higher verdict than the model recommended: the policy is the decider's own code and is trusted. That a pass needs
both holds for the reference policy, not for `AdapterJudge` in general. `escalate: true` turns a pass
or retry into a retry that says a person must look; it never softens a `terminal_breach`.

**Legacy modules.** `uai2_bridge` and `uai2_factory` forward to `uai`. `uai2_gemini`, `uai2_groq` and
`uai2_cloudflare` raise `ImportError` on import: their clients followed redirects, which could send a key to another
host.

A worked example, about sixty lines, is [interop/examples/uai_quickstart.py](interop/examples/uai_quickstart.py).

## F. CNS integration

The full boundary is [UAI_CNS_INTEGRATION_BOUNDARY.md](UAI_CNS_INTEGRATION_BOUNDARY.md). In short:

- **Delegated to CNS:** the canonical digest function (`cns.gate.subject_digest`) and the verdict vocabulary
  (`cns.gate.GateOutcome`). Optionally, a decision made by a CNS gate roster can be exported through
  `decision.from_super_gate`, which carries the roster's root in `cns_root`.
- **UAI's own responsibility:** signing, verification, identity, trust, revocation, replay protection,
  authorization, transport, key handling and provider access.
- **Bridge and adapter.** There is no adapter layer between UAI and CNS beyond those imports. `from_super_gate`
  refuses any decision that a `SuperGate` in the same process did not issue, and sends a pass that the roster does
  not confirm as a `terminal_breach`.
- **Pin:** `cns @ git+https://github.com/wking53214/CNS.git@v4.1.0`, a tag, resolving to commit `c84ef8c` on
  2026-11-20.
- The Node implementation uses no CNS code.

## G. Security and integrity

One row per property. "Not provided" is as important as "provided".

| Property | Mechanism | Where | Evidence | Not provided, or assumed |
|---|---|---|---|---|
| Integrity | the signature covers a canonical digest of every envelope field except `sig`; replies name the digest of the exact envelope answered | `envelope.py`, `uai.mjs` | conformance classes `tampered`, `rejected`; `test_envelope.py` | integrity of anything outside the envelope, such as the document itself beyond its digest |
| Signing | Ed25519 by the sender's key; pure Python by default, OpenSSL through `cryptography` when selected | `ed25519.py`, `crypto_backend.py`, `identity.py` | `test_ed25519.py` (RFC 8032 vectors), `test_crypto_backend.py` (both backends accept exactly the same signatures) | constant-time operation is not claimed for either backend and was not measured. No hardware key has been used |
| Verification | strict: canonical key and R, `s` below the group order, small-order keys refused | same | conformance cases `reject-small-order-key`, `sig-s-plus-group-order`; `test_ed25519.py`, `test_crypto_backend.py` | the canonical-encoding checks for the key and R are implemented, but no suite case isolates them: the case named `reject-non-canonical-key` keeps a signature made by a different key, so any verifier refuses it. No dedicated test isolating a non-canonical R was found in this revision |
| Identity | an identity is the public key itself, so a valid signature shows possession of the key | `identity.py` | `test_envelope.py`, `test_trust.py` | no link to a person or organization. Who holds a key is outside the protocol |
| Authentication of a sender | signature verification, then the receiver's `TrustPolicy`: pinned, or endorsed by an authority the receiver recognizes for a domain | `trust.py` | `test_trust.py`, `test_revocation.py` | how a receiver learns which identities to pin is out of band. Endorsement is one level deep. Node pins only |
| Authorization | separate from the signature: the receiver's `GrantTable`, default deny, single-use `Permit`, optional signed `Approval` by a listed approver | `grants.py`, `decision.py::RemoteDecisionGuard`, `grants.mjs` | `test_grants_enforced.py`, `test_grants.py`, `test_node_receiver_parity.py`, `tests/test_grant_withdrawal.py` | delegation is not implemented. Receiver-side only, so it is not on the wire and not in the conformance suite |
| Replay protection | the receiver's ledger refuses a second `(from, id)`; session messages must expire and may live at most 24 hours | `ledger.py`, `ledger_postgres.py`, `pg.mjs` | conformance class `replayed`; `test_ledger.py`, `test_ledger_postgres.py`, `test_expiry_purge_replay.py` | holds only as far as every process acting for an identity shares one ledger. Two local ledgers on two hosts accept one decision twice |
| Freshness | `issued_at` skew limit, `expires_at`; under the production profile lifetimes are judged by the database's clock | `envelope.py`, `ledger_postgres.py` | `test_clock_matrix.py`, `test_clock_fail_closed.py`, `test_clock_trust_production.py` | a receiver with a wrong clock and no database check accepts expired messages. The database clock is trusted |
| Confidentiality | none at the message layer. The `tls13-mutual` transport profile encrypts the channel | `transport.py` | `test_transport.py` (real handshakes, throwaway PKI) | envelopes are signed, not encrypted. No key agreement or session layer |
| Revocation and rotation | signed statements stored by each receiver; a revoke only reduces trust; a rotate is followed only from a pinned predecessor and only if the receiver chose to | `revocation.py` | `test_revocation.py`, `tests/test_key_drill.py` | no distribution channel: how a statement reaches a receiver is the operator's business. A key's own revoke does not withdraw a successor it named, so a separate revocation authority is needed |
| Key management | `Signer` never exposes its seed and refuses pickling and copying; `Signer.external` signs through a function supplied by the host | `identity.py` | `test_crypto_backend.py` | a procedure for custody and compromise is a draft ([docs/KEY_CUSTODY.md](docs/KEY_CUSTODY.md)) with open choices. `Signer.external` has not been run against a real keystore or HSM |
| Provider credentials | key in one header, to the named `https` host; no redirects; never in a URL, body, record or error | `providers.py` | `tests/test_provider_layer.py`, `test_providers.py` | provider calls honour the machine's proxy settings |
| Provenance of a model answer | the decider's own record of request and response digests, optionally signed into a pass | `providers.py`, `uai/judge.py` | `tests/test_front_door.py` | the provider signs nothing. A dishonest decider can record anything |
| Failure handling | every layer refuses with a registered code; an unavailable ledger, grant store or audit record refuses and never permits | throughout | `test_redemption.py`, `test_ledger_postgres.py`, `test_grants_enforced.py` | availability. A stopped database means nothing is permitted |
| Denial of service before authentication | unknown senders dropped before the signature check by default; a bound on values per message; an optional rate limiter | `session.py`, `limits.py` | `test_preauth.py`; measurements in `docs/interop/bench/` | no protection at the network layer |

**Trust assumptions, stated plainly.** The decider's signing key is not compromised. The decider records provider
calls honestly. The receiver's ledger and grant store are available and not tampered with; a database administrator
is inside the trust boundary. The receiver's clock, or under the production profile the database's clock, is right.
Identities are exchanged out of band.

**Not to be conflated.** A digest binding shows that two things refer to the same bytes. A signature shows who
produced an envelope and that it is unchanged. Neither says the content is true, and neither permits an action. In
this design permission comes only from the receiver's own grant.

There is no formal security argument and no external security review. The only audit is the project's own:
[docs/AUDIT_2026-11-17.md](docs/AUDIT_2026-11-17.md).

## H. Testing and conformance

### H1. How to run

Prerequisites: Python 3.10 or later; Node 22 (run here on 22.23.5; the Node receiver imports the built-in `node:sqlite`
module, so an older Node will not do);
PostgreSQL server binaries on the machine (the ledger tests start throwaway clusters; they do not need a running
server); git and network access to GitHub to install CNS.

```
python -m pip install -e ".[dev]"
python -m pytest -q
python contracts/uai1/run_conformance.py --cmd "python interop/conformance/reference_adapter.py"
python contracts/uai1/run_conformance.py --cmd "node interop/node/conformance_adapter.mjs"
python -m ruff check .
python -m mypy cns_interop uai
```

These are the commands CI runs ([.github/workflows/ci.yml](.github/workflows/ci.yml)), on Python 3.10 to 3.13.

### H2. What was observed on 2026-11-18

| Command | Observed |
|---|---|
| `python -m pytest -q` | 1660 passed, 0 failed, 0 skipped, 51 warnings, about 9 minutes |
| conformance, Python adapter | 72 of 72 (71 specification, 1 reference) |
| conformance, Node adapter | 72 of 72 |
| `node --test` over the five Node test files | 44 passed, 0 failed |
| `python -m ruff check .` | clean |
| `python -m mypy cns_interop uai` | no issues in 74 source files |
| `python interop/demo.py` | exit 0: both directions, replay and tamper refused |
| `python interop/examples/quickstart.py` | exit 0 |
| `python interop/examples/uai_quickstart.py groq <model>` with no key | prints `NOT EXECUTED`, exit 3 |
| `python contracts/uai1/build_kit.py --out <file>` | 12 files, no implementation source |
| `python interop/live_signing.py --recheck evidence/live-runs/2026-11-13-live-signing/live-signing.jsonl` | 40 of 40 accepted by Python and by Node |

One difference from the CI recipe: CNS was installed from a local copy of the `v4.0.0` tag, and the suite was run
from the repository root without an editable install. Python 3.13 only. CI run #187 on `c6c1033` concluded
"success" on GitHub; its logs were not read.

Not run on that date: any live provider call, the long soaks, the Go differential harness, Python 3.10 to 3.12.

### H3. Test architecture

58 Python test files: 42 under `cns_interop/tests/`, 16 under `tests/`. `conftest.py` makes any skipped test fail
the run, so a missing prerequisite is a failure and not a silent pass.

| Kind | What it is | Where |
|---|---|---|
| Unit | one module against its own contract | `test_envelope.py`, `test_ed25519.py`, `test_ledger.py`, `test_grants.py`, `tests/test_protocol.py`, `tests/test_uai2_bridge.py`, and others |
| Contract | implementations held to a published answer key | `test_uai_vectors.py`, `test_uai1_package.py`, `test_interop_campaign.py`, `test_ledger_conformance.py`, `test_node_ledger_conformance.py` |
| Adversarial | forged, replayed, malformed and hostile inputs | `test_session.py`, `test_adversarial_r4.py`, `test_preauth.py`, `test_clock_matrix.py`, `tests/test_fuzz_policy.py`, `tests/test_diff_fuzz.py` |
| Stand-in provider | provider clients against local HTTP servers that speak each provider's wire format. Three of the files say "EVERY SERVER HERE IS A STUB"; the other two say the same in other words | `test_providers.py`, `tests/test_provider_layer.py`, `tests/test_front_door.py`, `tests/test_jury.py`, `tests/test_live_signing.py` |
| Live provider | none in the test suite and none in CI. Live runs are made by hand with `interop/live_providers.py`, `interop/jury.py` and `interop/live_signing.py`, and their output is committed under `evidence/live-runs/` | `evidence/` |
| Cross-language integration | Python and Node processes exchanging real messages | `test_two_systems.py`, `test_node_receiver_parity.py`, `test_node_postgres.py`, `test_node_act_postgres.py` |
| Database integration | real throwaway PostgreSQL clusters: races, hard stops, partitions, standby failover | `test_ledger_postgres.py`, `test_act_postgres.py`, `test_policy_postgres.py`, `test_node_quorum.py`, `tests/test_soak_smoke.py` |
| Transport | real TLS 1.3 handshakes with a throwaway PKI | `test_transport.py` |
| Evidence and documentation consistency | committed evidence files match their recorded SHA-256; stated counts match the code | `tests/test_evidence_consistency.py`, `tests/test_doc_claims.py`, `tests/test_jury_regression.py`, `tests/test_key_drill.py` |
| Independent implementations | none | |

Two things the evidence-consistency tests do and do not do. They detect a committed evidence file being edited
after the fact. They do not authenticate where a file came from: the file and its recorded hash are committed by the
same party.

## I. Independent implementation guide

The aim is an implementation written without reading `cns_interop/` or `interop/node/`.

### I1. Get the documents alone

```
python contracts/uai1/build_kit.py --out uai1-kit.zip
```

The kit has twelve files and no implementation source: the specification, the security profiles, the implementer
guide, a disagreement report template, the schema, the error registry, the conformance suite and its runner, the two
vector files, a kit README and a SHA-256 manifest. Give a team the kit, not the repository.

### I2. Which text is normative

UAI-1.md does not mark normative and informative text itself. The following is a reading of the documents, offered
as guidance; a place where it is wrong is worth reporting.

| Material | Treat as |
|---|---|
| UAI-1.md sections 1 to 7 (values and digest, envelope, identity and trust, manifest, exchange, disclosure, decision) | the wire protocol. Normative |
| Conformance cases with `basis: "specification"` | normative; 41 of the 71 quote the sentence that decides them |
| `contracts/digest-vectors.json`, `contracts/uai-vectors.json` | normative answer keys. If the text and a vector disagree, report it |
| `contracts/uai1/errors.json` | normative for code names and meanings |
| `contracts/uai1/schema.json` | normative for shape only |
| UAI-1.md sections 7a, 7b, 7c | what a receiver does on its own side. They are labelled receiver-side. Requirements for a safe receiver, but two conforming implementations can differ here |
| Python class and module names inside UAI-1.md (for example `cns_interop.grants.GrantTable`) | illustrative: they say where the reference does it |
| UAI-1.md sections 8 and 9 | status and open items. Informative, and partly out of date |
| The one conformance case with `basis: "reference"` | illustrative |
| `docs/interop/SECURITY_PROFILES.md` | normative for anyone claiming a named profile |
| Example programs, this page, README.md | illustrative |

### I3. Order of work

1. **Strict reader.** UTF-8 JSON up to 1 MiB; refuse duplicate keys (compared after unescaping), fractions,
   exponents, NaN, Infinity, integers beyond plus or minus (2^53 - 1), a byte order mark, non-objects.
2. **Canonical digest.** Match every vector in `contracts/digest-vectors.json` before anything else.
3. **Identity and strict Ed25519 verification.** Many libraries are more lenient than UAI-1 requires; check the
   small-order, non-canonical and `s`-range cases.
4. **Envelope checks**, in the order given in section B2.
5. **An adapter program** that reads one JSON request per line on standard input and writes one answer per line:

   ```
   {"op": "reset"}                                          -> {"ok": true}
   {"op": "receive", "wire_text": "...", "now": <ms>,
    "trust": [...] | null, "audience": "..." | null,
    "kinds": [...] | null, "ledger": true | false}          -> {"accept": {"digest": "<hex>"}} or {"refuse": "<code>"}
   ```

6. **Run the suite:** `python contracts/uai1/run_conformance.py --cmd "<your adapter>"`. Exit status 0 means every
   case passed.
7. **Then the exchange:** manifest, request, offer, accept, decision and disclosure. `contracts/uai-vectors.json`
   gives signed examples of a request, an offer and a manifest, one disclosure commitment set and one terms digest.
   It has no accept or decision envelope, and the suite does not cover this part, so the kit holds no answer key for
   the last two steps of the exchange.
8. **Report every disagreement** with `docs/interop/implementers/DISAGREEMENT_REPORT.md`, as an issue on the
   repository. Each one is a defect in your implementation, a defect in the reference, or a sentence that needs
   fixing.

The fuller guide is [docs/interop/implementers/README.md](docs/interop/implementers/README.md).

### I4. Places where the text is known to be thin

An independent implementer is likely to hit these. They are listed so the result is informative and not a surprise.

- **The digest's full definition is in another repository.** UAI-1.md section 1 has a short table. The complete
  rules for implementers are CNS's
  [contracts/DIGEST.md](https://github.com/wking53214/CNS/blob/v4.0.0/contracts/DIGEST.md), which is not in the kit.
  The section 1 table does not say that the rendering is encoded as UTF-8 before hashing; the vectors settle it.
- **Two defects in one text.** The refusal code is fixed only when a text has one defect. For two, either
  `malformed` or `profile` conforms, and the two shipped implementations differ.
- **Very deep nesting.** The code is fixed through 100 levels; beyond that it depends on the reader's stack.
- **Canonical point encodings are not isolated by any suite case.** `docs/EVIDENCE.md` says no valid signature can be
  built with a non-canonical R, so the suite cannot require refusing one. That reasoning was not checked in this
  revision, and no dedicated in-repository test for it was found.
- **The exchange has no conformance suite.** The wider answer key that covers negotiation, decisions and sequences
  (`contracts/uai-interop-vectors.json`) is in the repository but not in the kit.
- **Receiver-side rules are specified in prose only**, with the reference's class names.
- **The model-answer contract** ([docs/interop/POLICY_CHAIN_SPEC.md](docs/interop/POLICY_CHAIN_SPEC.md)) covers one
  capability. The author of the Go reader written from it listed nine places where a guess was needed
  ([interop/policy_go/README.md](interop/policy_go/README.md)).
- **The provider interface (Layer A) has no specification to implement from.** Section B1 of this page is the
  nearest thing.

## J. Known limitations and open questions

Limitations:

1. No one outside the project has implemented, reproduced or reviewed any of it.
2. All code, both implementations, the tests and the earlier reviews were produced by one author directing AI models
   of one family. Agreement between the implementations is therefore weaker evidence of a clear specification than
   agreement between unrelated teams would be.
3. The conformance suite covers the receive operation only.
4. The provider interface has no written specification, one implementation, and works through one narrow profile.
5. Two of the six front-door routes (OpenAI, Azure OpenAI) have never been called against the real service, and no
   live run has gone through `uai.connect`, the typed bridge or the `provider-call` record (section C).
6. Every test and soak ran on one machine. Nothing has been shown across hosts on a real network.
7. Live evidence is a set of small, internal runs on synthetic documents. They are snapshots, not rates.
8. The provider-call record is the decider's own statement.
9. Key custody and compromise recovery are a draft procedure, exercised only in a software simulation.
10. Messages are authenticated, not encrypted.
11. The default Python signer is not constant time.
12. The CNS dependency is pinned by a movable tag.
13. No comparison with existing standards and protocols has been written (see README.md, "Relation to existing
    work").
14. There is no tagged release. Cite a commit.

Open questions a reviewer could answer:

- Can a team implement a conforming receiver from the kit alone, and where does the text force a guess?
- Do independently written receivers agree with each other on inputs outside the 72 cases?
- Does the strict reader plus a decider policy hold against adversarial model output designed by someone other than
  the author?
- Is the receive order in section B2 the right one? The specification verifies a signature before consulting trust,
  while the reference `Decider` by default drops unadmitted senders before the signature check. Which should be
  required, and should the specification say so in one place?
- Is single use sound across hosts with the PostgreSQL ledger under a real partition?
- Is the narrow portable profile a useful common denominator, or too narrow to be worth standardizing?
- Does the CNS dependency earn its cost for someone using UAI alone
  ([UAI_CNS_INTEGRATION_BOUNDARY.md](UAI_CNS_INTEGRATION_BOUNDARY.md) section 10)?

## K. Source cross-reference

| Topic | Source | Specification or guide | Tests |
|---|---|---|---|
| Typed model contract | `uai/protocol.py` | this page, B1 | `tests/test_protocol.py` |
| Portable bridge | `uai/bridge.py` | this page, B1 | `tests/test_uai2_bridge.py` |
| Provider selection | `uai/connect.py` | [docs/QUICKSTART.md](docs/QUICKSTART.md) | `tests/test_front_door.py` |
| Provider clients | `cns_interop/providers.py` | this page, C | `tests/test_provider_layer.py`, `cns_interop/tests/test_providers.py` |
| Model answer to verdict | `cns_interop/adapter.py`, `uai/judge.py` | [docs/interop/POLICY_CHAIN_SPEC.md](docs/interop/POLICY_CHAIN_SPEC.md) | `cns_interop/tests/test_adapter.py`, `tests/test_fuzz_policy.py` |
| Envelope and wire | `cns_interop/envelope.py`, `wire.py`; `interop/node/uai.mjs` | UAI-1 sections 1, 2 | `cns_interop/tests/test_envelope.py`; conformance suite |
| Signatures | `cns_interop/ed25519.py`, `crypto_backend.py` | UAI-1 section 2 | `test_ed25519.py`, `test_crypto_backend.py` |
| Identity, trust, revocation | `identity.py`, `trust.py`, `revocation.py` | UAI-1 section 3 | `test_trust.py`, `test_revocation.py` |
| Manifest and negotiation | `manifest.py`, `negotiate.py` | UAI-1 sections 4, 5 | `test_negotiation.py` |
| Disclosure | `disclosure.py` | UAI-1 section 6 | `test_negotiation.py`, `test_session.py` |
| Session roles | `session.py`; `interop/node/agent.mjs` | UAI-1 section 5 | `test_session.py`, `test_two_systems.py` |
| Decision and guard | `decision.py` | UAI-1 section 7 | `test_redemption.py`, `test_session.py` |
| Grants and approvals | `grants.py`; `interop/node/grants.mjs` | UAI-1 section 7a | `test_grants.py`, `test_grants_enforced.py`, `test_node_receiver_parity.py` |
| Ledgers | `ledger.py`, `ledger_postgres.py`; `interop/node/pg.mjs` | UAI-1 sections 7c, 8; [docs/interop/CONSISTENCY.md](docs/interop/CONSISTENCY.md) | `test_ledger.py`, `test_ledger_postgres.py`, `test_ledger_conformance.py` |
| Transport | `transport.py` | [docs/interop/SECURITY_PROFILES.md](docs/interop/SECURITY_PROFILES.md) | `test_transport.py` |
| Conformance | `contracts/uai1/` | [docs/interop/implementers/README.md](docs/interop/implementers/README.md) | `test_uai1_package.py`, `tests/test_outsider_kit.py` |
| CNS boundary | `cns_interop/decision.py::from_super_gate` | [UAI_CNS_INTEGRATION_BOUNDARY.md](UAI_CNS_INTEGRATION_BOUNDARY.md) | `test_partial_decision_export.py`, `test_uai_vectors.py` |
| Evidence | `evidence/` | [docs/EVIDENCE.md](docs/EVIDENCE.md), [CLAIM_EVIDENCE_CROSSWALK.md](CLAIM_EVIDENCE_CROSSWALK.md) | `tests/test_evidence_consistency.py` |

Test files named without a directory are under `cns_interop/tests/`.

Other documents, and how to read them:

| Document | Read as |
|---|---|
| [docs/EVIDENCE.md](docs/EVIDENCE.md) | the run-by-run record |
| [docs/RELEASE_READINESS.md](docs/RELEASE_READINESS.md) | the checklist before a first tag |
| [docs/AUDIT_2026-11-17.md](docs/AUDIT_2026-11-17.md) | a self-audit; it says it is not independent |
| [docs/KEY_CUSTODY.md](docs/KEY_CUSTODY.md) | a draft procedure with open choices |
| [docs/interop/ADVERSARIAL_R4.md](docs/interop/ADVERSARIAL_R4.md), [LEDGER_PARITY.md](docs/interop/LEDGER_PARITY.md) | topic notes |
| [docs/interop/SCORECARD.md](docs/interop/SCORECARD.md), [UAI1_R4_ASSESSMENT.md](docs/interop/UAI1_R4_ASSESSMENT.md), [UAI1_ADVANCEMENT_ASSESSMENT.md](docs/interop/UAI1_ADVANCEMENT_ASSESSMENT.md), [UAI1_8_0_CLOSURE_PLAN.md](docs/interop/UAI1_8_0_CLOSURE_PLAN.md) | internal working notes. Their numeric scores are self-assigned. The "external assessment" and "independent review" that `SCORECARD.md` mentions were AI sessions run by the author. Not evidence |
