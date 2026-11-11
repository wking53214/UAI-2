# UAI-1 8.0 closure campaign: Phases 1 to 3 (nothing modified)

> **Status check of 2026-11-07.** This is a plan written on a dated baseline. Several files it proposes to add are not on
> `main` today: `contracts/uai-authz-vectors.json`, `contracts/uai-errors.json`, `docs/interop/ERRORS.md`,
> `docs/interop/TRANSPORT.md` and `docs/interop/DELEGATION.md`. The probe scripts it cites live in a scratch folder
> outside the repository, not in it. The plan is kept as written so its reasons stay readable.

## Phase 1: verified baseline

- `origin/main` = `279e7ffad64c82fc0dee23201af60f9960421f77` (merge of PR #73). Unchanged since the previous campaign; no newer commits.
- The local branch held only already-merged history, so it was reset to `origin/main` (no code change).
- Executed on that commit: `pytest` 1986 passed, 0 failed, 0 skipped; Node 23 passed; `ruff` and `mypy cns_interop` clean; `make_interop_vectors.py --check` reproducible.
- Environment (what could and could not be exercised): 4 vCPU, 16 GB, Linux 6.18, Python 3.13.18, Node 22.23.4. Installed and used: Redis 7.0.15 server, PostgreSQL 16.15 server (started locally as `postgres`), OpenSSL CLI. Not available: etcd and SoftHSM (apt cannot locate them), any OS keyring, TPM, docker daemon. Toolchains present for a blind implementation: rustc 1.97, go, ruby, php, java, gcc. Provider access: **no provider API key is set**. `api.anthropic.com` and `generativelanguage.googleapis.com` are reachable through the proxy; `api.openai.com` is not. The only credential in the environment is the harness's own `ANTHROPIC_BASE_URL`, which is not a credential I was given for product use and which I did not use.
- Probe scripts (read-only, outside the repo): `scratchpad/{preauth.py,preauth.mjs,flood.py,nodeflood.mjs,failover.py,dudect.py,authz_probe.py}`.

### A correction to my own previous assessment
The last report scored receiver-side authorization 6.5 and called F-12 and F-13 closed. Reading the enforced path this time shows that was overstated. `GrantTable` exists and is tested, but **nothing that actually performs an action calls it**: `interop/act.py` and `chains/evidence_spine.py` rely on `RemoteDecisionGuard` alone (grep: `GrantTable` and `.permit(` appear only in `interop/demo_adapters.py`, tests and `grants.py`). So today a signed, verified decision does independently authorize a protected action, which is exactly what the architectural boundary forbids. Four further defects in `GrantTable` itself were reproduced below.

### Baseline scorecard (explicit criteria; evidence class in brackets)

Evidence classes: **X** executed by me, **I** inspected only, **D** documented only, **E** externally validated (none).

| Dimension | Now | Evidence | Why not higher |
|---|---|---|---|
| 1 Protocol correctness | 6.5 | X: 137-case answer key through both implementations, mutation-checked | No JSON Schemas, no machine-readable error registry; terms not bound at `permit` (G-01) |
| 2 Cryptographic integrity | 6.0 | X: strict verification differential across two backends; **X: timing leak measured in the pure signer** | Pure signer is the default; production profile is switchable at runtime (G-17); no HSM executed |
| 3 Identity and trust | 6.5 | X: signed revocation and rotation in both languages | Node stores are in memory; endorsements Python only |
| 4 Receiver-owned authorization | **3.5** | X: four defects reproduced; I: not in the enforced path | **Critical failure, ceiling applies** |
| 5 Replay and distributed consistency | **4.5** | X: single host exactly-once; X: lease clock-skew defect; X: Redis failover loss | No real backend; no fencing; **critical until closed** |
| 6 Cross-language interoperability | 6.5 | X: campaign | Two implementations by one author |
| 7 AI-provider interoperability | 2.0 | X: contract and hostile-output tests with a script | No provider adapter, no live call, no provenance record |
| 8 Human authority and approval | 4.0 | X: approval binding tests in Python | Not in the enforced path; Node none; one approval yields unlimited permits |
| 9 Operational resilience | 4.0 | X: pre-auth costs measured | No rate limiting; withdrawal lost on restart; audit breaks with two writers |
| 10 Independent validation | 1.5 | none | No outside implementer; same author wrote everything |
| **Average** | **4.5** | | **Overall capped at 5.0** while G-01 to G-05 and G-07 to G-09 stand |

## Phase 2: gap register

Status: CONFIRMED (reproduced by execution), PARTIAL, NOT REPRODUCED, UNKNOWN. Severity: Critical, High, Medium, Low. "Evidence" cites the probe that produced it.

| ID | Symbols | Observed | Consequence | Evidence | Sev | Status |
|---|---|---|---|---|---|---|
| G-01 | `grants.GrantTable.permit`, `check_terms`; `decision.Verified` | `permit` takes caller-supplied `terms` and never compares `subject_digest(terms)` with the decision body's `terms_digest`. A decision made under capability X was permitted against a grant for capability Y by passing different terms | Receiver authorization bypass wherever terms and decision travel separately (they do in `act.py` jobs) | `authz_probe.py` P-A | **Critical** | CONFIRMED |
| G-02 | `interop/act.py`, `chains/evidence_spine.py`, `decision.RemoteDecisionGuard.__call__` | The action boundary needs only a verified decision; no grant, purpose, approval or audit is consulted | "A decision is not permission" is not enforced where actions happen | grep over the repo | **Critical** | CONFIRMED |
| G-03 | `grants.GrantTable.permit`, `Permit` | The same decision plus the same approval yields unlimited permits; a `Permit` is not consumed or tied to guard redemption | One human approval can authorize repeated actions | P-B | High | CONFIRMED |
| G-04 | `GrantTable._withdrawn`, `__init__` | Withdrawal is an in-memory set; a restart reloads the grant and it permits again | "What happens when permission is withdrawn" is answered wrongly after any restart | P-C | High | CONFIRMED |
| G-05 | `GrantTable._record`, `_last`, `verify_audit` | Each process tracks the chain tip in memory; two writers break the chain, after which `GrantTable(...)` cannot be constructed (`unavailable`), so authorization goes down | Self-inflicted denial of authorization; evidence unreliable | P-D | High | CONFIRMED |
| G-06 | `decision.Verified` | Plain frozen dataclass; an in-process caller can `replace(verdict="pass")` and `permit` accepts it | Same trust domain, so low; but `Permit` should bind to terms digest and decision id | P-E | Low | CONFIRMED |
| G-07 | `ledger.CoordinatedLedger._run`, `Reservation`, `Coordinator` | Lease expiry is judged by each caller's own clock. Host B with a clock 61 s ahead reserved a message host A held under a 60 s lease | Concurrent redemption across hosts under clock skew | `Probe L1` (in-process, deterministic) | **Critical** | CONFIRMED |
| G-08 | `ledger.Reservation` | Random token only; no monotonic fencing value a protected target can check. A holder that stalls past its lease can still act while a new holder acts | At-least-once with no way to reject the stale holder's effect | Probe L2 | High | CONFIRMED |
| G-09 | No real backend | Only `InMemoryCoordinator` exists. A real Redis 7.0.15 with an async replica **lost an acknowledged reservation on failover** (partition proxy, primary killed, replica promoted); host B then reserved the same message. `WAIT 1 300` honestly reported 0 confirmations | Redis alone cannot be the consistency authority; no supported backend is demonstrated | `failover.py` (an earlier attempt that did not truly partition was discarded) | **Critical** | CONFIRMED |
| G-10 | `CoordinatedLedger` | Committed entries are never pruned or TTL'd | Unbounded coordinator growth | I | Medium | CONFIRMED (inspection) |
| G-11 | `interop/node/uai.mjs` | No `Grant`, approval, audit or `check_terms`; ledger and revocation store are in memory only | No Node receiver authorization; restart forgets spent decisions | grep: 0 hits; no file I/O | High | CONFIRMED |
| G-12 | `session.Decider.handle`, `agent.mjs` | Signature is verified **before** the sender is checked, and an unknown-but-valid sender gets a **signed** refusal. Pure backend: 182 msg/s/core, 5.5 ms each; cryptography backend 1329 msg/s/core; Node 3075 msg/s/core | Anyone can mint keys and saturate a core while receiving signed output | `flood.py`, `nodeflood.mjs` (single thread, 300 messages) | High | CONFIRMED |
| G-13 | `wire.loads`, `envelope.check_profile`, `agent.mjs strictParse` | Worst case within the 1 MiB cap, before authentication: Python 1 MiB list of small ints 621 ms (about 600 times a valid envelope), 60k keys 154 ms; Node 1 MiB string 182 ms, 500k ints 108 ms. The cost is per message, linear, bounded by 1 MiB | One 1 MiB message ties up a core for 0.1 to 0.6 s; no rate limit exists | `preauth.py`, `preauth.mjs` (n=3 to 5 per case, medians) | High | CONFIRMED |
| G-14 | `uai.mjs strictParse` | Suspected quadratic number parsing | Not seen: 50k, 100k, 500k numbers cost 6, 17, 108 ms | `preauth.mjs` | n/a | NOT REPRODUCED |
| G-15 | `ed25519._mul`, pure `Signer` | A dudect-style test (secret scalar Hamming weight <=110 vs >=146, 1500 samples per class) detected a timing difference: Welch t = -8.06 (mean 3212 vs 3348 us). The `cryptography` backend showed none at 6000 samples per class (t = -1.47), which is not proof of constant time. The earlier 5-seed probe missed the leak; it was too small | The pure signer leaks secret-dependent timing in-process | `dudect.py` (shared VM, in-process, so noisy; t exceeds the 4.5 threshold) | Medium | CONFIRMED (pure); UNKNOWN (cryptography) |
| G-16 | `crypto_backend.use`, `production()` | `use("pure")` can be called at runtime and `UAI_PROFILE` is read on each call | A profile can be downgraded after startup | I | Medium | CONFIRMED (inspection) |
| G-17 | No keystore code | `Signer.external` exists; no keystore or HSM adapter was ever run. SoftHSM, TPM and keyring are absent here | HSM claim is documentation only | tool check | Medium | CONFIRMED; **not executable in this sandbox** |
| G-18 | No transport code | No TLS code anywhere; docs only say "use TLS" | Confidentiality and peer authentication undemonstrated | grep | High | CONFIRMED |
| G-19 | `docs/interop/UAI-1.md`, `contracts/` | No JSON Schemas; refusal codes appear in code (about 25) but there is no registry | An outside implementer must read prose and our code to learn the errors | grep | Medium | CONFIRMED |
| G-20 | `adapter.py` | Contract and strict parser only. No provider adapter, no timeout or provider-error mapping, no provenance record of what was asked, returned, accepted and rejected | Real-provider interop unproven | I | High | CONFIRMED |
| G-21 | Delegation | Not present | See the threat model below: need not established | analysis | Low | see D-1 |
| G-22 | Independent implementation | None; I cannot engage an outside implementer | No third-party validation | n/a | High | CONFIRMED |

Revalidation of the eight gaps you listed: (1) CONFIRMED and worse (G-07, G-08, G-09). (2) CONFIRMED (G-22). (3) CONFIRMED (G-20, no key available). (4) CONFIRMED (G-11). (5) assessed in D-1. (6) PARTIAL: the pure signer leak is now measured, the HSM is not executable here. (7) CONFIRMED (G-18). (8) PARTIAL: 3.9 ms reproduces as about 3.6 ms; the larger exposure is parse cost and signed-reply amplification (G-12, G-13).

## Phase 3: implementation plan (awaiting your authorization)

Rules: branch from `main`, one commit per step, narrow tests first, then `pytest`, `node --test`, `ruff`, `mypy`, no em dashes, no existing test weakened (any exact-behavior edit listed). Tiers are ordered; **Tier 0 must land before any score above 5.0 can be claimed.**

### Tier 0: receiver authorization actually enforced (closes G-01 to G-06)

| Step | Change | Files and symbols | Compat | Failure behavior | Acceptance |
|---|---|---|---|---|---|
| T0-1 | `permit` binds to the decision: require `subject_digest(terms) == verified.envelope.body["terms_digest"]`; add `Verified.terms_digest`; `Permit` carries it | `grants.py: GrantTable.permit/check_terms`, `decision.py: Verified` | none for correct callers; wrong terms now `terms` | refuse | P-A refused; shared vector |
| T0-2 | Permits become single-use and tied to redemption: spend `(decision_id, action)` through a `TwoPhaseLedger`; `Permit.consume()` | `grants.py: GrantTable`, `Permit` | additive; `GrantTable(permit_ledger=)` optional in revision 2, required in 3 | `unavailable` | P-B refused; crash between permit and action recovers via lease |
| T0-3 | Persistent grant state: `GrantStore` (SQLite) holds withdrawals and expiries; `withdraw` writes atomically | `grants.py: GrantTable._withdrawn` -> `GrantStore` | additive | unreadable store = refuse | P-C refused after restart |
| T0-4 | Audit safe for several writers: lock, re-read the tip under the lock, then append (the `FileLedger` pattern); `verify_audit` unchanged; start-up refuses only on a damaged chain, with an explicit `--audit-recover` that opens a new signed segment | `grants.py: _record`, `verify_audit` | additive | fail closed | P-D: two processes, chain verifies |
| T0-5 | **Put grants in the enforced path.** `RemoteDecisionGuard` gains `grants=` and `action=`; with them, `__call__` also requires a live `Permit`. `act.py` gains `--grants`, `--action`, `--audit`, `--approver` and **refuses by default without a grants file**; the old decision-only behavior survives only as `--decision-only`, printing a warning and documented as not receiver-authorized. `chains/evidence_spine.py` moves to the new mode | `decision.py: RemoteDecisionGuard`, `interop/act.py`, `chains/evidence_spine.py` | **Breaking default for `act.py`**: a versioned change ("revision 3") with `docs/migrations/uai-1-revision-3.md`; `RemoteDecisionGuard` stays source compatible | refuse | adversarial test: a valid decision with no grant, wrong purpose, no approval, withdrawn grant, replayed permit each refuses at `act.py`; STACK spine tests updated only as the step requires, listed |

### Tier 1: distributed replay protection (closes G-07 to G-10)

Consistency model to be written into `docs/interop/CONSISTENCY.md` first: reservation is **at-most-once while the coordinator is linearizable and its leader is unique**; delivery is **at-least-once** after a lapsed lease; protected actions must be **idempotent on the idempotency key**; **exactly-once business effects** only when the target enforces the fencing value or commits in the same transaction. No exactly-once claim otherwise.

| Step | Change | Files and symbols | Acceptance |
|---|---|---|---|
| T1-1 | Time authority moves to the coordinator: `Coordinator.now()`; `CoordinatedLedger` takes lease times from it, never from the caller | `ledger.py: Coordinator, CoordinatedLedger._run` | skew test (clock +-10 min on either host) cannot double-reserve; fails the way L1 failed before the change |
| T1-2 | Fencing token: monotonic `Reservation.fence` from a coordinator counter, bumped on every grant or takeover; `FencedTarget` helper that rejects an action whose fence is below the highest seen | `ledger.py: Reservation`, new `fencing.py` | stale holder after lease takeover is rejected by a fenced target |
| T1-3 | `PostgresLedger` over `psycopg` (optional extra `cns[postgres]`): one-row `INSERT ... ON CONFLICT DO NOTHING`, lease time from `now()`, fence from a sequence, optional `commit_in(txn)` so a business write and the commit share a transaction. HA claim only with quorum synchronous replication, checked at start-up (`synchronous_standby_names`, `synchronous_commit`) | new `ledger_postgres.py`, `pyproject.toml` | verified here: 32 concurrent inserts gave 1 winner, server-clock lease takeover works; still to do: conformance suite, kill -9 of a client mid-transaction, immediate server stop and restart, primary plus synchronous standby behind the partition proxy showing commits block and the ledger answers `unavailable` (fail closed) |
| T1-4 | Redis is not shipped as an authority. The failover-loss evidence goes into the consistency document as the reason | docs only | n/a |
| T1-5 | Pruning/TTL contract for committed entries (`expires_at + keep`) | `Coordinator` contract, Postgres cleanup | growth bounded test |
| T1-6 | Conformance suite additions: skewed clocks, fencing monotonicity, subprocess crash, coordinator restart | `ledger_conformance.py` | every backend passes |

Limits to state plainly: single-node Postgres here proves the primitives, not multi-host HA; HA needs a real standby or consensus store, and CI needs a Postgres service container (a workflow change you must approve).

### Tier 2: pre-authentication resource controls (closes G-12, G-13; no weakening of cryptography)

| Step | Change | Acceptance |
|---|---|---|
| T2-1 | Cheap early gate: check the claimed `from` against the receiver's admitted set before verifying; unknown senders get **no signed reply** (counted and dropped, or a rate-limited unsigned error) in `Decider.handle` and the Node agent | unknown-sender cost falls from about 5 ms to microseconds in `flood.py`; shared vector; no verification step removed for admitted senders |
| T2-2 | Receiver `Limits(max_bytes, max_nodes, max_depth)` enforced while reading (default 64 KiB for session kinds; the 1 MiB wire ceiling does not change), Python and Node | worst-case CPU per rejected byte falls at least 10 times; the 1 MiB list case drops from 621 ms |
| T2-3 | Token-bucket limiter before verification, per claimed sender and global, for replies too | flood harness shows a bounded rate; bypass attempts (many identities) hit the global bucket |
| T2-4 | Cache the strict public-key precheck (pure function of 32 bytes, LRU) | `cryptography` verify drops from 0.6 ms |
| T2-5 | Commit the benchmark harness and a results file with hardware, runtime, sample sizes | reproducible numbers |

### Tier 3: Node receiver parity (closes G-11)
New `contracts/uai-authz-vectors.json` (hand-authored, with the P-A to P-D cases) run by both implementations. Node: `Grant`, `GrantStore`, `Approval` (bound to decision, action and document), audit chain, `permit`, persistence for ledger, revocation and grants through `node:sqlite` (to be confirmed available without an experimental flag in Node 22.23). Acceptance: both languages give identical outcomes and refusal codes on every vector, and a mutation experiment kills at least one deliberate break per rule.

### Tier 4: independent validation (G-19, G-22)
I cannot engage an outside implementer from here. Plan: (a) publish `contracts/schemas/*.json` (JSON Schema for envelope, body kinds, terms, grants) and `contracts/uai-errors.json` plus `docs/interop/ERRORS.md`; state which rules a schema cannot express (signature, canonical digest). (b) A blind challenge: fresh sub-agents given **only** the spec, schemas and vectors implement a verifier in Rust and in Go with no CNS source. Every disagreement is logged as a specification defect. It is labeled INTERNAL and scores nothing as independent. (c) A packaged challenge kit (`run_conformance.py --cmd <binary>`) so a real outside team can be handed the same task. Credit for dimension 10 only after (c) is run by someone else.

### Tier 5: provider adapters (G-20)
`cns_interop/providers/anthropic.py` and `google.py` on the standard library (no SDK dependency), behind `PromptedModelAdapter`: timeouts, response size cap, strict provider-error mapping, no retries that change meaning, model confidence never read. A `ProvenanceRecord` (provider, model as returned, request digest, response digest, latency, finish reason, parse result, accepted or rejected with reason) goes into the audit chain. Injection, malformed output, fabricated authority and bypass-the-grant tests run against local HTTP stubs **labeled STUB**. `interop/live_providers.py` runs the live call and writes evidence JSON; **without keys it prints NOT EXECUTED and exits non-zero** so it is never counted. OpenAI is unreachable from this sandbox, so the two ecosystems I can reach are Anthropic and Google Gemini. **I need API keys for both and a spend limit from you.**

### Tier 6: crypto and transport (G-15 to G-18)
- C-1: freeze the profile and backend after start-up (`crypto_backend.freeze()`), read `UAI_PROFILE` once; downgrade attempts raise.
- C-2: `KeyStore` protocol with a file store (mode 0600, never logged) and a PKCS#11 signer. The PKCS#11 path **cannot be executed here** (no SoftHSM or token); it ships as tested-against-a-stub and labeled NOT EXECUTED against a token.
- C-3: commit `interop/bench/timing.py` (the dudect-style test). Pure signer: leak measured. `cryptography`: nothing detected at the tested sample size, and constant time stays unclaimed pending specialist validation.
- C-4: `docs/interop/TRANSPORT.md` (mandatory: authenticated encrypted channel for anything beyond a local pipe; TLS 1.3 only, no downgrade, peer certificate pinned by SPKI hash mapped to the expected UAI identity; optional: channel binding; deployment-dependent: rotation, CA use) and a reference `cns_interop/transport.py` over `ssl` plus a Node `tls` mirror. Tests on loopback: TLS 1.2 refused, wrong or unpinned certificate refused, plaintext refused, Python-to-Node and Node-to-Python handshakes. This proves the profile on one machine, not a deployed network.

### D-1: delegation threat model (no implementation proposed)
Where delegation could be needed: (1) an agent acting for an institution; (2) a deputy approver; (3) a decider handing work to a sub-decider. (1) is already handled by the receiver naming the agent's own identity as `requester` in a grant, and (2) by listing several approvers. (3) is the dangerous one: it would let a remote party mint authority chains the receiver must evaluate, widening the attack surface and risking escalation, and no use case here needs it. Recommendation: **do not build delegation now**; record the threat model in `docs/interop/DELEGATION.md` with unblock criteria (a concrete cross-organization case, a non-escalation proof sketch, revocation cascade tests).

### Sequencing and dependencies
T0 (1 to 5) first. T1-1 and T1-2 before T1-3. T2 independent of T1, can run in parallel with T3. T3 needs T0 vectors. T4 schemas wait for T0 and T2 so the spec stops moving. T5 needs keys. T6 independent.

### Score ceiling after this plan
If everything executable lands: roughly 6.5 to 7.0 overall. 8.0 additionally requires work I cannot do alone: an outside implementer's pass (dimension 10), live provider evidence (7), a multi-host Postgres or consensus deployment (5), and an HSM or token execution (2). I will not award 8.0 on any of those without the evidence.

### Decisions I need
- **A.** Approve Tier 0 first, with T0-5 as a versioned breaking default for `act.py` (recommended), or keep decision-only as the default?
- **B.** Approve a Postgres service container in CI (workflow change)?
- **C.** Approve optional dependencies: `psycopg` (`cns[postgres]`), `jsonschema` (dev only), `python-pkcs11` (optional)?
- **D.** Provide two provider API keys and a spend cap, or accept Tier 5 as boundary plus stubs labeled NOT EXECUTED?
- **E.** Approve the blind internal implementation challenge (several sub-agents; token cost), and say whether a real outside implementer can be engaged.
- **F.** Separate from this plan: `stack` and `chains` still fail on `main` because of a Warden pin conflict. Want that fixed?
