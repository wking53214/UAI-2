# Evidence map

Every claim this repository makes, the test or run that backs it, and what is still unproven. Written for a reviewer who
has only the repository: each row names a file and a test you can run yourself.

How to read the status column:

- **Tested**: an automated test in this repository checks the claim, and `python -m pytest -q` runs it (CI runs it on
  every push, against real PostgreSQL clusters and the Node implementation, never mocks of them).
- **Live**: shown once against the real service with real keys, by the operator, on the date given. Not repeated by CI.
- **Partial**: tested, with a stated limit on what the test reaches.
- **Not shown**: no evidence yet. Listed so nobody mistakes silence for proof.

Run everything that is not live:

    python -m pip install -e ".[dev]"
    python -m pytest -q
    python contracts/uai1/run_conformance.py --cmd "python interop/conformance/reference_adapter.py"
    python contracts/uai1/run_conformance.py --cmd "node interop/node/conformance_adapter.mjs"

Last full run (2026-11-12, this branch): 1538 tests passed, none skipped; conformance 70 of 70 for Python and for Node.

## 1. The signed format (UAI-1)

| Claim | Evidence | Status |
|---|---|---|
| Python and Node give the same answer on every published case | `contracts/uai1/conformance-suite.json` through `run_conformance.py`, both adapters; `cns_interop/tests/test_uai1_package.py::test_both_shipped_implementations_pass_the_conformance_suite_through_the_standalone_runner` | Tested (70 cases; 69 decided by the specification, 1 illustration, see section 7) |
| Edited bodies, swapped senders, forged, truncated or bit-flipped signatures are refused | suite cases `reject-body-edited`, `reject-sender-swapped`, `sig-all-zeros`, `sig-last-bit-flipped`, `sig-one-hex-char-short`; `cns_interop/tests/test_envelope.py` | Tested |
| Weak and non-canonical Ed25519 keys are refused, and so is a signature whose `s` is not below the group order | suite cases `reject-small-order-key`, `reject-non-canonical-key`, `sig-s-plus-group-order`; `cns_interop/tests/test_ed25519.py`, `test_crypto_backend.py` | Tested. The suite cannot require refusing a non-canonical R, or a non-canonical key that is not of small order: no valid signature can be built with one, so a lenient verifier fails it anyway. Only the in-repo tests check that rule |
| Ambiguous text is refused the same way in both languages (duplicate keys, `\u` escapes, floats, huge integers, NaN, nesting, size, trailing data, byte order mark, lone surrogates, `__proto__`) | suite classes `ambiguous-or-malformed` and `malformed` | Tested |
| Expiry, not-yet-valid, and the exact expiry boundary | suite cases `reject-expired`, `reject-from-the-future`, `expired-exactly-at-expires-at`, `accepted-one-ms-before-expires-at`; `cns_interop/tests/test_clock_matrix.py`, `test_clock_fail_closed.py` | Tested |
| A replay is refused, including one re-sent in reformatted text | suite cases `replay-is-refused`, `replay-in-pretty-printed-text-is-refused`, `replay-with-reordered-keys-is-refused`; `cns_interop/tests/test_ledger.py`, `test_expiry_purge_replay.py` | Tested |
| Trust is the receiver's decision: pinned or endorsed, nothing else | `cns_interop/tests/test_trust.py::test_pinned_and_endorsed_are_the_two_ways_in`; suite cases `unauthorized-signer-is-refused`, `addressed-to-someone-else` | Tested |
| Revocation and key rotation: only the subject or a listed authority may revoke; rotation only from a pinned predecessor; a compromised key's named successor is withdrawn too; a stale revocation list refuses | `cns_interop/tests/test_revocation.py` (13 tests), `interop/node/revocation.test.mjs` | Tested |
| Negotiated terms are the intersection both sides agree on; overreach is refused; the decider sees exactly the agreed fields | `cns_interop/tests/test_negotiation.py` | Tested |

## 2. Signed is not the same as permitted (the receiver's grants)

| Claim | Evidence | Status |
|---|---|---|
| A verified decision permits nothing without the receiver's own grant, for the exact terms it was made under | `cns_interop/tests/test_grants_enforced.py` (P-A cases), `test_grants.py` | Tested |
| One decision gives one permit per action, across processes and across both languages | `test_grants_enforced.py::test_p_b_two_tables_sharing_a_permit_ledger_permit_one_action_between_them`; `test_node_receiver_parity.py::test_concurrent_attempts_on_one_decision_yield_one_permit_across_both_languages` | Tested |
| A withdrawal survives a restart and binds every process sharing the store | `test_grants_enforced.py::test_p_c_a_withdrawal_survives_a_restart_and_is_seen_by_another_process` | Tested |
| A grant withdrawn while an action is in flight: the permit already issued completes once; nothing is permitted after the withdrawal, including a retry after an abort or a lapsed lease; across four processes, no request that starts after `withdraw()` returns is granted | `tests/test_grant_withdrawal.py` (5 tests; with the withdrawal check removed from `grants.py`, 4 fail and the control passes) | Tested |
| A withdrawal or a spent decision made through one language binds the other | `test_node_receiver_parity.py::test_a_withdrawal_and_a_spent_decision_made_through_one_language_bind_the_other` | Tested |
| Every permit and refusal is in one hash-chained audit record, safe with several writers; a damaged record stops authorization | `test_grants_enforced.py` (P-D cases) | Tested |

## 3. The ledger under failure (PostgreSQL)

| Claim | Evidence | Status |
|---|---|---|
| Of sixteen processes racing to use one message, exactly one wins | `cns_interop/tests/test_ledger_postgres.py::test_exactly_one_of_sixteen_processes_wins_a_message` | Tested |
| The business write and the spend are one transaction: a client killed before COMMIT leaves neither | `test_ledger_postgres.py::test_the_business_write_and_the_spend_are_one_transaction_and_a_killed_client_leaves_neither`; `test_act_postgres.py`, `test_node_act_postgres.py` | Tested |
| A committed message survives a hard server stop; a stopped server means unavailable, never a grant | `test_ledger_postgres.py::test_a_committed_message_survives_a_hard_server_stop_and_a_stopped_server_means_unavailable` | Tested |
| A network partition makes the ledger refuse within its timeout and never grant (Python and Node) | `test_ledger_postgres.py::test_a_network_partition_makes_the_ledger_refuse_within_its_timeout_and_never_grants`; `test_node_quorum.py::test_a_network_partition_between_node_and_the_database_is_unavailable_in_bounded_time_and_never_grants` | Tested |
| With a synchronous standby, a partition refuses and a failover loses nothing anyone was told | `test_ledger_postgres.py::test_a_synchronous_standby_behind_a_partition_makes_the_ledger_refuse_and_a_failover_loses_nothing_anyone_was_told`; `test_node_quorum.py` | Tested |
| Leases follow the database server's clock, not the caller's; fences only grow and a stale holder is rejected | `test_ledger_postgres.py::test_the_servers_clock_decides_a_lease_and_the_callers_clock_is_ignored`, `::test_fences_only_grow_and_a_stale_holder_is_rejected_by_a_fenced_target` | Tested |
| All of the above across separate machines on a real network | the tests run real clusters and real processes, on one host | Partial |

## 4. The provider layer

| Claim | Evidence | Status |
|---|---|---|
| A redirect is never followed, so a key cannot be sent to another host | `cns_interop/tests/test_providers.py::test_a_redirect_is_not_followed_so_the_key_cannot_be_sent_elsewhere`; `tests/test_provider_layer.py` | Tested (local servers) |
| The key goes in a header only, never a URL, body, record or error; a key with hidden characters never reaches the network | `test_providers.py::test_the_key_goes_in_a_header_only_and_never_appears_in_a_url_a_body_a_record_or_an_error`, `::test_a_refused_key_never_reaches_the_network`; `tests/test_front_door.py::test_a_connection_holds_the_key_only_inside_its_client_closures_so_printing_it_shows_nothing` | Tested |
| Request and response digests are of the exact bytes sent and received | `tests/test_provider_layer.py::test_the_request_digest_is_the_digest_of_the_bytes_that_were_sent`, `::test_the_response_digest_is_the_digest_of_the_bytes_that_came_back` | Tested |
| Every failure is a categorized refusal, never a pass | `tests/test_provider_layer.py::test_every_failure_is_a_refusal_with_a_category_a_status_and_no_key`; `tests/test_front_door.py::test_a_provider_failure_becomes_a_signed_failure_and_never_a_pass` | Tested |
| The `live` flag is set only by the live runner | `tests/test_front_door.py::test_the_live_flag_is_never_set_by_this_package` | Tested |
| Anthropic, Gemini, Groq, Cloudflare Workers AI answer through the real service | `interop/live_providers.py`, 2026-11-12: `live=True` for `claude-haiku-5-5`, `gemini-3.5-flash`, `openai/gpt-oss-120b` on Groq, `@cf/meta/llama-3.3-70b-instruct-fp8-fast` | Live (4 of 7 routes) |
| OpenAI, GitHub Models, Azure OpenAI answer through the real service | no key was available | Not shown |

## 5. The model is an untrusted advisor

| Claim | Evidence | Status |
|---|---|---|
| A model's pass stands only if the decider's policy keeps it; a pass carries the provider-call record, signed by the decider, not the model | `cns_interop/tests/test_adapter.py`; `tests/test_front_door.py::test_a_pass_carries_the_record_of_the_provider_call_signed_by_the_decider_not_the_model` | Tested |
| A model recommendation becomes a decision Python signs and Node verifies | `tests/test_front_door.py::test_a_models_recommendation_becomes_a_decision_python_signs_and_node_verifies` | Tested |
| Against live models from four companies, hostile and edge documents produced no final pass that should not have happened | `interop/jury.py`; raw rows in [evidence/live-runs/2026-11-11-raw/](../evidence/live-runs/2026-11-11-raw/README.md): 3,698 rows over three runs, the provider answered on 1,679, 0 breaches; models were fooled, the policy lowered every one. Claude coverage in run 2 stops at round 8 of 30 (Anthropic calls began failing; the operator reports the credit ran out or expired), and run 3 failed entirely; see the folder's README | Live |
| For ANY model answer, hostile or malformed, the strict reader and the decider's policy never let a final pass leave for a document that does not clear (fuzzed: random hostile answers against random documents, checked against an independently written rule) | `interop/fuzz_policy.py`, `tests/test_fuzz_policy.py`: 500,000 cases over five seeds and 200,000 on another, 0 breaches, 0 crashes; the same search finds each of 10 deliberately broken policies. It also found one real flaw, now fixed: a model's `escalate` flag softened its own `terminal_breach` into a `retry` | Tested (random search plus mutation check, not a proof). Limits: the policy checks declared fields, so a forged document with true-looking numbers clears; documents are plain JSON values; the receiver's grants and keys are not covered |

## 6. Not shown yet

| Gap | What would close it |
|---|---|
| An implementation by anyone outside this project | someone builds UAI-1 from `docs/interop/UAI-1.md` and `contracts/uai1/` alone and runs the suite |
| Three of seven provider routes live | keys for OpenAI, GitHub Models and Azure OpenAI, then `python interop/live_providers.py` |
| The ledger across separate machines | the section 3 tests run with the database and the processes on different hosts |
| Signing-key custody and compromise recovery as an operating procedure | written procedure: where keys live, who can use them, how a compromise is detected, revoked and rotated (the code for revocation and rotation is tested; the procedure is not written) |
| Long-running load and soak | a sustained run with mixed traffic, failures injected, and the ledger and audit checked afterwards |

## 7. A note on `reference` cases

69 of the 70 conformance cases are `basis: "specification"`. Each of the 32 promoted on 2026-11-12, and each of the 7 boundary cases added after the blind Go and Rust implementations, carries a `spec`
field quoting the words in `docs/interop/UAI-1.md` that decide its answer. Two of them were settled by adding a sentence
to the specification that matches what both implementations already did: `issued_at` is zero or more, and a byte order
mark is refused, not skipped.

One case stays `basis: "reference"` on purpose: `replay-needs-the-ledger-so-without-it-both-are-accepted`. It shows
what a receiver with no replay ledger does (it accepts a replay). The specification now says such a receiver is not
conforming, so the case is an illustration that the ledger is what refuses a replay, not a requirement to copy.
