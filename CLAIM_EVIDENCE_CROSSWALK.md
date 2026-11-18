# Claim to evidence crosswalk

Each architectural claim this repository makes, the code behind it, the text that specifies it, the evidence for it,
and what the evidence does not reach.

This page works at the level of claims. The run-by-run record (dates, counts, file hashes) is
[docs/EVIDENCE.md](docs/EVIDENCE.md), and this page points into it instead of repeating it. Where the two differ on a
run detail, `docs/EVIDENCE.md` is the record.

Checked on 2026-11-18 at commit `c6c1033`. "Run" means executed on that date in one Linux container (Python 3.13,
Node 22, PostgreSQL 16, CNS `v4.0.0`), with no live provider call. Every file and test named here was confirmed to
exist at that commit.

## Status labels

| Label | Meaning |
|---|---|
| IMPLEMENTED | the code exists and was read; no test or run is cited for the claim |
| TESTED | an automated test in this repository checks it, and the suite passed when run (1660 passed, none failed, none skipped) |
| DEMONSTRATED | shown at least once outside the test suite, against a real service or in a recorded long run, with the record in `evidence/` |
| INFERRED | a conclusion drawn from the above, not shown directly |
| NOT ESTABLISHED | no evidence |
| OUT OF SCOPE | deliberately not claimed |

Three limits apply to every TESTED row and are not repeated in each:

1. The tests were written by the same project that wrote the code, largely by the same AI model family
   (see [README.md](README.md), "Project status").
2. They were run on one machine.
3. A passing test shows the tested case holds. It is not a proof of the general claim.

## 1. The provider-neutral model interface (UAI-2)

| Claim | Source implementation | Specification | Test or evidence | Evidence status | Limitation |
|---|---|---|---|---|---|
| One typed request and response shape is used for every provider | `uai/protocol.py`, `uai/bridge.py`, `uai/connect.py` | none written. The contract is the code and [README_ENGINEERING.md](README_ENGINEERING.md) section B1 | `tests/test_protocol.py`, `tests/test_uai2_bridge.py`, `tests/test_front_door.py::test_every_provider_answers_in_the_one_typed_shape` | TESTED against local stand-in servers | holds only in the "portable profile": one user message, no system instruction, exactly 512 output tokens, no settings. One implementation. No conformance suite |
| The same call reaches six provider routes | `uai/connect.py::PROVIDERS`, `cns_interop/providers.py` | none | `tests/test_front_door.py`, `tests/test_provider_layer.py`; live rows under `evidence/live-runs/` | TESTED for all six against stand-ins. Four of the underlying client functions DEMONSTRATED live (Anthropic, Gemini, Groq, Cloudflare Workers AI) | no live run went through `uai.connect` or the typed bridge: the live runners call the client functions directly. OpenAI and Azure OpenAI have never been called against the real service. Neutrality across six routes is not compatibility with every provider |
| Every provider failure is reported in one set of categories and never as a pass | `cns_interop/providers.py`, `uai/bridge.py::ProviderExecutionError` | `contracts/uai1/errors.json` (code `provider`) | `tests/test_provider_layer.py::test_every_failure_is_a_refusal_with_a_category_a_status_and_no_key`, `tests/test_front_door.py::test_a_failure_has_the_same_category_whichever_provider_it_came_from` | TESTED against stand-ins | the categories are this project's own; real services may fail in ways the stand-ins do not imitate |
| An API key is sent in one header, to the named host only | `cns_interop/providers.py` (`_NoRedirect`, `_check_url`, `_check_key`) | none | `tests/test_provider_layer.py::test_no_redirect_is_followed_so_the_key_reaches_no_second_host`, `::test_the_key_is_in_one_header_and_in_no_url_body_record_or_error` | TESTED against stand-ins | provider calls honour the machine's proxy settings, which is outside these tests |
| Each call is recorded with digests of the exact bytes sent and received | `cns_interop/providers.py::Provenance` | none | `tests/test_provider_layer.py::test_the_request_digest_is_the_digest_of_the_bytes_that_were_sent`, `::test_the_response_digest_is_the_digest_of_the_bytes_that_came_back` | TESTED | the record is the caller's own statement. No provider signs its answers |
| A truncated answer is detected | `uai/connect.py`, `cns_interop/providers.py` | none | `tests/test_provider_layer.py::test_a_cut_off_answer_is_refused_unless_the_caller_asked_for_text_and_then_the_record_says_it_was_cut_off` | TESTED for routes that report why an answer ended | older Cloudflare Workers AI catalog models do not report it, so truncation there cannot be detected |
| The provider interface can be implemented independently | `uai/protocol.py` | none | none | NOT ESTABLISHED | no written specification, no suite, no second implementation |

## 2. A model's answer on its way to a decision

| Claim | Source implementation | Specification | Test or evidence | Evidence status | Limitation |
|---|---|---|---|---|---|
| A model's output is read strictly and nothing is repaired | `cns_interop/adapter.py::parse_recommendation` | [docs/interop/POLICY_CHAIN_SPEC.md](docs/interop/POLICY_CHAIN_SPEC.md) | `cns_interop/tests/test_adapter.py`, `tests/test_fuzz_policy.py`; a Go reader written from the specification in `interop/policy_go/` | TESTED | the written contract covers one capability. The Go comparison is not part of CI and was not re-run on 2026-11-18 |
| A model cannot produce a final pass the decider's policy does not keep | `cns_interop/adapter.py::AdapterJudge` | `docs/interop/POLICY_CHAIN_SPEC.md` | `tests/test_fuzz_policy.py`; `tests/test_jury_regression.py`; live rows in `evidence/live-runs/2026-11-11-raw/`, `2026-11-13-free-panel/`, `2026-11-17-jury-current-prompt/` | TESTED. DEMONSTRATED on synthetic documents with internal panels | the policy checks the fields it is shown, so a forged document with plausible values clears. The live panels are small and were run by the project |
| The model is never given a key, a ledger, a grant or an approval | `cns_interop/adapter.py`, `uai/judge.py` | [docs/interop/UAI-1.md](docs/interop/UAI-1.md) section 8 | `tests/test_front_door.py::test_a_pass_carries_the_record_of_the_provider_call_signed_by_the_decider_not_the_model`, `::test_the_model_is_not_told_about_that_evidence_and_is_refused_if_it_claims_it` | TESTED | a property of this code's structure. Another implementation could be written differently |
| A pass can carry a signed record of the provider call | `uai/judge.py` (evidence kind `provider-call`) | [docs/QUICKSTART.md](docs/QUICKSTART.md) | `tests/test_front_door.py` | TESTED | it proves what the decider says it sent and received. It is not proof against a decider that lies. No live run has produced one |
| A live model's answer has been taken to a signed decision that a second implementation verified | `interop/live_signing.py` | UAI-1 section 7 | `evidence/live-runs/2026-11-13-live-signing/`; re-verified from the stored rows (run): 40 of 40 accepted by Python and by Node | DEMONSTRATED once | 8 documents per model, 5 models, no Claude model. The signed verdict was the expected one on 26 of 40; the other 14 failed closed |

## 3. The signed protocol (UAI-1)

| Claim | Source implementation | Specification | Test or evidence | Evidence status | Limitation |
|---|---|---|---|---|---|
| A changed, forged or truncated message is refused | `cns_interop/envelope.py`, `ed25519.py`, `crypto_backend.py`; `interop/node/uai.mjs` | UAI-1 section 2 | conformance suite classes `tampered` and `rejected`; `cns_interop/tests/test_envelope.py`, `test_ed25519.py`, `test_crypto_backend.py` | TESTED | the default Python signer is not constant time. No side-channel measurement was made |
| Ambiguous text is refused the same way by both implementations | `cns_interop/wire.py`; `interop/node/uai.mjs` | UAI-1 sections 1 and 2 | conformance suite classes `malformed` and `ambiguous-or-malformed`; `tests/test_diff_fuzz.py`; `evidence/audit/2026-11-17-diff-fuzz/` | TESTED for accept or refuse | when a text has two defects the two implementations can give different refusal codes. The specification now allows either |
| Two implementations give the same answer on every published case | Python and Node | UAI-1 | `contracts/uai1/run_conformance.py` against both adapters: 72 of 72 each (run) | TESTED | both come from one project, and the suite's signed messages derive from vectors the Python implementation generates. The suite exercises receiving a message only (section 4 below) |
| Both implementations match an answer key that no implementation produced | Python and Node | UAI-1 | `contracts/uai-interop-vectors.json` (expected results typed by hand, signatures from the OpenSSL command line, generator imports neither implementation); `cns_interop/tests/test_interop_campaign.py` | TESTED | written by the same project. Wider than the conformance suite (digest, wire, envelope, negotiation, decisions, sequences), but not in the implementer kit |
| A replayed message is refused | `cns_interop/ledger.py`, `ledger_postgres.py`; `interop/node/pg.mjs` | UAI-1 section 2, step 6 | conformance suite class `replayed`; `cns_interop/tests/test_ledger.py`, `test_expiry_purge_replay.py` | TESTED | depends on a ledger shared by every process acting for the identity |
| Trust is the receiver's decision | `cns_interop/trust.py`, `revocation.py` | UAI-1 section 3 | `cns_interop/tests/test_trust.py::test_pinned_and_endorsed_are_the_two_ways_in`, `test_revocation.py` | TESTED | the Node implementation supports pinning only, not endorsement |
| Terms are agreed before anything is disclosed, and only agreed fields are opened | `cns_interop/negotiate.py`, `disclosure.py`, `session.py` | UAI-1 sections 5 and 6 | `cns_interop/tests/test_negotiation.py`, `test_session.py` | TESTED | not in the conformance suite |
| A valid signature is not permission to act | `cns_interop/grants.py`, `decision.py::RemoteDecisionGuard`; `interop/node/grants.mjs` | UAI-1 section 7a | `cns_interop/tests/test_grants_enforced.py`, `test_node_receiver_parity.py`, `tests/test_grant_withdrawal.py` | TESTED | receiver-side behaviour, not on the wire, and not in the conformance suite |
| One decision is used at most once under process and server failure | `cns_interop/ledger_postgres.py`; `interop/node/pg.mjs` | UAI-1 sections 7c and 8; [docs/interop/CONSISTENCY.md](docs/interop/CONSISTENCY.md) | `cns_interop/tests/test_ledger_postgres.py::test_exactly_one_of_sixteen_processes_wins_a_message`; soak reports in `evidence/live-runs/2026-11-16-soak-mid-commit/` and `2026-11-17-soak-mid-commit-3x25min/` | TESTED. DEMONSTRATED in recorded soak runs | one machine. No real network partition between hosts, no clock drift between hosts. The soaks were not re-run on 2026-11-18 |
| A compromised key can be revoked and replaced | `cns_interop/revocation.py`, `trust.py` | UAI-1 section 3 | `cns_interop/tests/test_revocation.py`; `tests/test_key_drill.py`; `evidence/drills/2026-11-17-key-drill/` | TESTED in software | the operating procedure is a draft ([docs/KEY_CUSTODY.md](docs/KEY_CUSTODY.md)) and has never been exercised by people |
| Messages can be carried over an authenticated, encrypted channel | `cns_interop/transport.py` | [docs/interop/SECURITY_PROFILES.md](docs/interop/SECURITY_PROFILES.md) | `cns_interop/tests/test_transport.py` | TESTED | the envelope itself is signed, not encrypted. Confidentiality comes only from the channel |
| Messages are confidential | | UAI-1 section 8 | | OUT OF SCOPE | the protocol authenticates and does not encrypt |

## 4. Conformance and independent implementation

| Claim | Source implementation | Specification | Test or evidence | Evidence status | Limitation |
|---|---|---|---|---|---|
| A conformance suite exists that any implementation can be run against | `contracts/uai1/conformance-suite.json`, `contracts/uai1/run_conformance.py` | [docs/interop/implementers/README.md](docs/interop/implementers/README.md) | `cns_interop/tests/test_uai1_package.py::test_both_shipped_implementations_pass_the_conformance_suite_through_the_standalone_runner` | TESTED | the 72 cases exercise one operation: receiving a message (read, signature, time, audience, trust, replay). The exchange, disclosure, decision verification, grants and ledgers under failure are not in it |
| The implementer kit contains no implementation source | `contracts/uai1/build_kit.py` | the kit's own `KIT_README.md` | `tests/test_outsider_kit.py`; kit built (run): 12 files | TESTED | no outside team has used it |
| UAI-1 can be implemented from the documents alone | the kit | UAI-1 | none in this repository | NOT ESTABLISHED | earlier documents mention Go and Rust implementations written from the documents. They were AI sessions run by the author; their source is not in this repository and the result cannot be reproduced from it |
| Someone outside the project has implemented or reviewed UAI-1 | | | none | NOT ESTABLISHED | the largest gap, and the reason for the request in [README.md](README.md) |

## 5. CNS

| Claim | Source implementation | Specification | Test or evidence | Evidence status | Limitation |
|---|---|---|---|---|---|
| Every digest is the CNS subject digest | `cns.gate.subject_digest` (CNS `v4.0.0`); `interop/node/uai.mjs` | UAI-1 section 1; CNS `contracts/DIGEST.md` | `contracts/digest-vectors.json`; `cns_interop/tests/test_uai_vectors.py` | TESTED | the full implementer description is in the CNS repository, not here |
| A decision made by a CNS gate roster can leave the process as a signed UAI-1 decision | `cns_interop/decision.py::from_super_gate` | UAI-1 section 7 (`cns_root`) | `cns_interop/tests/test_session.py`, `test_partial_decision_export.py`, `test_two_systems.py`; `interop/demo.py` (run) | TESTED | a receiver cannot check what `cns_root` refers to |
| Depending on CNS benefits UAI | | | none | NOT ESTABLISHED | no comparison has been run. Design in [UAI_CNS_INTEGRATION_BOUNDARY.md](UAI_CNS_INTEGRATION_BOUNDARY.md) section 10 |

## 6. Claims this repository does not make

Listed so that their absence is not read as an oversight.

| Not claimed | Why |
|---|---|
| Compatibility with every AI provider or model | six routes, one narrow profile, four routes run live |
| Readiness for production use | a reference design, version 0.1.0, untagged |
| Formal verification or a security proof | there is none. The evidence is tests, fuzzing and recorded runs |
| A security audit or certification | the only audit is the project's own ([docs/AUDIT_2026-11-17.md](docs/AUDIT_2026-11-17.md)), which says it is not independent |
| Independent reproduction | every run recorded here was made by the project |
| Adoption by anyone | no outside user is known |

## 7. Wording changed in the 2026-11-18 documentation revision

| Earlier wording | Where | Now |
|---|---|---|
| "Supported providers" listing all six | `README.md` | split into routes run against the real service and routes tested only against local stand-ins |
| "It works the same on every supported provider" | `docs/QUICKSTART.md` | "It uses the same call and returns the same shape", with the two known differences named |
| Go and Rust implementations "written from the kit alone" | `README.md` | described as AI sessions run by the author, from the documents, with source not published |
| "A second implementation ... sharing no code" | `README.md` | "separately written, by the same project"; never "independent" |
| "CNS defines the gate contract this builds on" | `README.md` | the exact imports, with a link to the boundary page |
| Last full run cited as CI run #126 | `docs/EVIDENCE.md`, `docs/RELEASE_READINESS.md` | CI run #187 on `c6c1033`, and the 2026-11-18 local run |

Stale statements that were left in place, because this revision changed no source, data or specification text:

- [docs/interop/UAI-1.md](docs/interop/UAI-1.md) section 9 says "790 live calls". The raw rows found later show 3,698
  rows with 1,679 answered (`docs/EVIDENCE.md` section 5). That section already says `docs/EVIDENCE.md` is current
  where the two differ.
- `contracts/uai1/run_conformance.py` and the suite's `note` field point to `contracts/uai1/README.md`, which does not
  exist. The adapter protocol is in `docs/interop/implementers/README.md`.
- `contracts/uai1/schema.json` has a `$id` under a CNS URL from before the move.
- `uai/bridge.py` describes the typed contract as "the CNS typed contract". The contract UAI uses is `uai/protocol.py`.
- `docs/interop/SCORECARD.md` and `docs/interop/UAI1_R4_ASSESSMENT.md` carry numeric scores, which are self-assigned.
  `SCORECARD.md` also uses the words "external assessment" and "independent review"; those were AI sessions run by
  the author.
