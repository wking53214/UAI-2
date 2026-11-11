# UAI-1 revision 3 (in progress): receiver policy is enforced where actions happen

> **Check of 2026-11-07.** The files and test names this page cites were checked against the repository. It describes a past revision, so it is kept as written.
Revision 3 changes no wire format. It changes what a receiver does with a verified decision.

## Tier 0 (this step): what changed

| change | breaking? | who must act |
|---|---|---|
| `interop/act.py` refuses to start without `--grants`, `--grant-store`, `--action` and `--audit` (exit 2, `config`) | **yes, by design** | every caller of `act.py`. Give it the receiver's policy, or pass `--decision-only` to accept that a signature alone opens the action (stderr says so) |
| `GrantTable.permit` requires terms that hash to the decision's `terms_digest` | only for callers that passed other terms (that was a bypass) | none for correct callers |
| permits are single use (`Permit.complete()`, `abort()`, `idempotency_key`) | a second permit for one decision and action is now `replayed` | callers that relied on reusable permits |
| `GrantStore`, `GrantTable(store=, permit_ledger=, audit_recover=)`, `load_grants` | additive | pass a store to make withdrawals durable |
| audit append is locked and chains onto the file's real last entry | additive | none |
| `RemoteDecisionGuard(grants=, action=)`, `authorize(approval=)` | additive | none |

## Defects this closes (found by the 8.0 closure baseline, all reproduced before the fix)

P-A terms not bound to the decision at `permit`; P-B one decision and approval gave unlimited permits; P-C a withdrawal
was lost on restart; P-D two audit writers broke the chain and then no table could start; and the finding that nothing
that performs an action consulted a grant.

## Existing tests and callers edited (CLAUDE.md rule 5)

- `cns_interop/tests/test_session.py::run_act` now passes `--decision-only`: those tests assert revision 2 decision-only
  semantics (ledger, capability), which `--decision-only` preserves. Nothing else about them changed.
- `cns_interop/tests/test_two_systems.py::test_a_third_process_acts_once_on_the_one_document`: `act_first` used to equal
  `{"permitted": True}`; it now carries the permit, so the line asserts `permitted` is true and the permit names the grant.
- `interop/demo.py::act` and `chains/evidence_spine.py::act_elsewhere` now run `act.py` under a generated grants file
  (action `ingest`, and `register-root`). **The spine edit was not executed locally**: the spine needs the sibling
  repositories (`ccc` and others) and runs only in the `chains` workflow, which was already red on `main` for an unrelated
  Warden pin conflict. The same `act.py` command path is covered by `test_act_policy.py`.

## Rollback

`--decision-only` restores the revision 2 behavior of `act.py` per caller; each tier is its own commit.

## Tier 1 (consistency core): what changed

| change | breaking? | who must act |
|---|---|---|
| `Coordinator` gains `now()` and `next_fence()`; `CoordinatedLedger` judges every lease by `Coordinator.now()` and ignores the caller's `now` unless `allow_caller_time=True` | **yes for a custom coordinator** (it must provide both, or `CoordinatedLedger` raises `ValueError`) | implementers of `Coordinator` |
| `Reservation.fence` (0 from `FileLedger` and `SqliteLedger`), `fencing.FencedTarget` | additive | targets that can check a fence should |

Closes the lease clock-skew defect (a host 61 s ahead took a live 60 s lease). `docs/interop/CONSISTENCY.md` states the model.
Existing test setups edited (assertions unchanged): the conformance suite's coordinated factory passes
`allow_caller_time=True` because its generic properties drive time with `now=`; the `Flaky` coordinator wrapper in
`test_redemption.py` delegates `now` and `next_fence`.

## Tier 2 (pre-authentication controls): what changed

| change | breaking? | who must act |
|---|---|---|
| `Decider(unknown_sender="drop")` is the default: a sender not already admitted costs no signature check and gets **no signed reply** (`Refused("untrusted")`, counted in `dropped`). `"refuse"` keeps the revision 2 signed refusal | **yes, by design**: an unadmitted peer no longer learns why | peers that relied on the signed refusal; pass `unknown_sender="refuse"` to keep it |
| `Limits(max_bytes=65536, max_nodes=20000)` on `Decider`: more than `max_nodes` values is refused (`profile`) before the signature; `wire.loads(max_bytes=)` reads less than the 1 MiB ceiling | **yes for messages above 20000 values**; the 1 MiB wire ceiling does not change | raise `max_nodes` where larger messages are legitimate |
| `RateLimiter` (global and per claimed sender, bounded state), opt-in via `Decider(limiter=)` | additive | operators |
| strict public-key precheck cached (`ed25519._public_point`) | none; a pure function of 32 bytes | none |
| Node agent: the pinned-sender gate runs before the signature check and answers with an unsigned error; `maxNodes` 20000; `boundedNodes` | same as Python | peers of the Node agent |

Measured (`interop/bench/preauth.py`, results in `docs/interop/bench/preauth-2026-10-31.json`, 4 vCPU shared VM, Python 3.13,
medians, n=200 for the flood rows and 3 for the 1 MiB rows): unknown sender with a valid signature, pure backend, 6.55 ms
before and 0.0017 ms now; `cryptography` backend 0.91 ms before and 0.0018 ms now. A 1 MiB list of small integers, 363 ms
before and 7.6 ms with `max_nodes=20000` (pure), 424 ms and 13.9 ms (`cryptography`). A rate limiter fed 5000 messages from 5000
claimed identities in one instant let through exactly its global burst of 50. These are single-core CPU costs, not network
throughput. Verification of an ADMITTED sender is unchanged and not weakened.

Existing tests edited (CLAUDE.md rule 5; each assertion changed only as the step requires):

- `test_session.py::pair` accepts extra `Decider` keywords; `test_an_unadmitted_requester_is_told_no_and_learns_why` passes
  `unknown_sender="refuse"`, so its assertions are unchanged; `test_an_endorsed_requester_is_admitted_once_and_until_the_endorsement_lapses`
  now expects the lapsed sender to be dropped (`untrusted`, `dec.dropped == 1`) instead of refused.
- `test_revocation.py::test_a_revoked_requester_is_refused_by_a_decider_using_the_same_store` now expects the drop.
- `test_two_systems.py`: `stranger_reply` is now `dropped`; `interop/demo.py` records the drop.
- `interop/node/agent.test.mjs`: the test I added in S6 that expected a signed refusal for an unadmitted sender now asserts the
  unsigned error and that nothing is signed.
- `test_uai_vectors.py`: the expected Node pass count is 24.

## Chains workflow repaired (found by running the spine against the sibling repositories at their default branches)

The `chains` workflow was red on `main` before any revision 3 work. Cause: CCC #51 ("single write funnel") made `ingest`
refuse a conclusion (`CCC-EPISTEMIC-001`) and made CCC ask its write permission before seventeen more doors. The spine
ingested HERALD's reading as INFERENCE and did not name those doors, so its own check (`ccc_doors_all_named`) went red, as
designed. Fixes in `chains/evidence_spine.py`: `ccc_ingest` takes the document in as `UNKNOWN` (CCC accepts that from a model;
a conclusion is made later by `derive`, `infer` or `interpret`); the seventeen doors are named in `WRITES_NO_DOCUMENT`, with the
reason, so under the roster's permission they stay shut. `tests/test_chains.py` pins that policy list on purpose, so its
expected set was updated in the same reviewed change. Executed here against the siblings at their default branches
(Governance_Gateway 771952c, DGK 8d8d25f, DIT c801374, URE 0e5751c, interconnected_* afda263/59ab926/811c2f2/931c097,
Ecology 3e90010, HERALD d08c36f, TIE 9d86041, Conservation_Kernel bf0e49b, ccc 84ffa5d): `full_chain`, `spine_run` and
`ecology_answer` pass unchanged, and `evidence_spine` exits 0 with 38 scenarios ok, including the `act.py` grants-mode path.

## Tier 1 (real coordinator): `PostgresLedger` (T1-3)

Additive. `cns_interop/ledger_postgres.py`, optional extra `cns[postgres]` (`psycopg[binary]>=3.1`, imported only inside it; the
core still has no dependencies; `dev` includes it so CI exercises it). CI gains one step that makes the PostgreSQL server
binaries explicit: the ledger tests start real throwaway clusters with `initdb` and `pg_ctl`, never a mock, and FAIL (not skip)
if they are missing.

Executed against real PostgreSQL 16.15 clusters started by the tests (17 tests): the shared conformance properties; exactly one
winner among 16 processes; leases judged by the server's clock (a lying caller clock gains nothing); fences that grow; a business
write and the spend in one transaction, and a client killed mid-transaction leaving neither (exactly one effect after the retry);
a message that survives a hard server stop, and `unavailable` while the server is down; a network partition behind a proxy that
drops traffic (refusal in bounded time, nothing granted); and a primary with a real synchronous standby, the standby partitioned,
the primary killed and the standby promoted: the commit the standby could not confirm was refused, the acknowledged reservation
survived the failover, and the one unacknowledged request could be granted again.

Findings made on the way, both kept as tests: `statement_timeout` does NOT interrupt a COMMIT that is waiting for the standby (the
backend stays in `SyncRep`), so a client-side cancel timer is required; and a cancelled wait is answered with SUCCESS plus the
notice "canceling wait for synchronous replication", which the ledger now refuses as `unavailable`. Taking that success at face
value is the acknowledged-write-lost failure measured with Redis.

What this does NOT show: a multi-host deployment (one machine), the behavior of a managed PostgreSQL service, or that a given
production configuration of `synchronous_standby_names` is correct. `require_sync_replication=True` is a configuration check plus
the timeout behavior above; it is not a proof of the server's replication.

Existing test edited (rule 5): the import allow-list in `test_uai_vectors.py` also permits `psycopg` in `ledger_postgres.py`.

## Provider boundary (D, in place of live keys)

Additive: `cns_interop/providers.py` (Anthropic Messages and Google Gemini `generateContent` clients on the standard library, a
`ProvenanceLog`), `AdapterJudge(observer=)`, and `interop/live_providers.py`.

**Nothing in this repository has called a live model provider.** There is no API key in the environment, `api.openai.com` and the
model hosts (Hugging Face, Ollama) are unreachable from the sandbox, and no model runtime could be installed, so a real local model
was not possible either. What is real and was executed: both clients against local servers that speak each provider's actual wire
format (labeled STUB in `test_providers.py`, 45 tests): timeouts, HTTP 401/429/500, non-JSON and oversized answers, truncated or
filtered or multi-block or tool-call answers, redirects (not followed, so a key cannot be sent elsewhere), the key kept in a
header only and absent from every URL, body, record and error, and a provenance record per call (provider, model requested and
reported, request and response digests, latency, finish reason, accepted or rejected and why). Hostile outputs (a stated human
approval, a confidence offered as authority, an unsupported action request, an instruction to the receiver, prose around the
object, an unsupported evidence kind) are refused by the strict reader and signed as a failure; a model fooled into a pass cannot
override the decider's policy, and an escalation stays a retry.

`interop/live_providers.py` runs one real exchange per provider that has `*_API_KEY` and `*_MODEL` set, writes the evidence, and
otherwise prints `NOT EXECUTED` and exits 3, so it cannot be mistaken for a pass. `ProviderInfo.live` is never set by library code.
**Provider interoperability stays UNEXECUTED until someone supplies a key and runs it.**
