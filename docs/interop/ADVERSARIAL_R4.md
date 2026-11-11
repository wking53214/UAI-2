# UAI-1 revision 4: adversarial campaign

> **Check of 2026-11-07.** Every test name and repository file this page cites was confirmed to exist in this repository. Claims about the outcome of earlier runs and about other repositories were not re-run or re-verified.
Each row is a threat, the setup that tests it, what must happen, what happened when the test ran in this campaign
(EXECUTED, 2026-10-31, see the run record in `UAI1_R4_ASSESSMENT.md`), whether the attack succeeded, and where it lives. "Class" is
IMPL (an implementation defect), SPEC (a specification gap) or DEPLOY (a deployment limitation the design states). Where an
attack succeeds, the test asserts that it does: a recorded gap is an assertion, never a skip.

| # | Threat | Setup | Expected | Actual | Attack succeeded? | Test and source | Class |
|---|---|---|---|---|---|---|---|
| 1 | Forged sender identity | envelope `from` swapped to another key | `signature` | `signature` in Python, Node, and the conformance suite | No | `contracts/uai-vectors.json` (sender-swapped), `test_uai1_package.py`; `envelope.py` | none |
| 2 | Invalid signature | `00..` signature on a decision job | refused alike by both receivers | same refusal | No | `test_node_receiver_parity.py` (forged) | none |
| 3 | Modified contents | body edited after signing | `signature` | `signature` | No | vectors (body-edited) | none |
| 4 | Digest substitution | `in_reply_to` replaced | `signature` | `signature` | No | `conformance-suite.json` | none |
| 5 | Terms-digest mismatch | terms altered after the decision | `terms` | `terms` in both receivers | No | `test_node_receiver_parity.py`; `grants.py` `permit`, `grants.mjs` | none |
| 6 | Replay of a consumed permit | same job twice | `replayed` | `replayed`, also across Python and Node on shared SQLite files | No | `test_node_receiver_parity.py`, `test_act_postgres.py` | none |
| 7 | Concurrent duplicate actions | 6 processes (PostgreSQL), 8 mixed Python and Node processes (SQLite) on one decision | exactly one permit | exactly one in each run | No | `test_policy_postgres.py`, `test_node_receiver_parity.py` | none |
| 8 | Revoked or withdrawn grant | withdrawal by another host or language | `withdrawn` | `withdrawn` across processes and languages | No | `test_policy_postgres.py`, parity test | none |
| 9 | Stale grants | a host's grants file differs from the published policy | host refuses to act | `stale_policy` | No | `test_policy_postgres.py`; `policy_postgres.py` | none |
| 10 | Conflicting policy updates | four operators publish version 1 at once | one wins | one winner, three `conflict` | No | `test_policy_postgres.py` | none |
| 11 | Unauthorized approver | approval from an unlisted key | `approval` | `approval` in both receivers | No | parity test | none |
| 12 | Sender or requester approves | grant naming a party as its own approver | cannot be built | refused at load in both languages (`config`) | No | parity test; `grants.py`, `grants.mjs` | none |
| 13 | Approval for another decision, action, or document | cross-bound approvals | `approval` | `approval` | No | `test_act_policy.py`, parity test | none |
| 14 | Expired approval | clock past the approval's expiry | `approval` | `approval` | No | parity test, `test_adversarial_r4.py` | none |
| 15 | Clock manipulation | receiver clock set back one hour | refuse the expired decision | the expired decision is accepted | **Yes**, unless the receiver checks its clock | `test_adversarial_r4.py`, `test_clock_trust.py` | DEPLOY: the receiver's clock must be trustworthy. PostgreSQL leases use the server clock, envelope lifetimes do not. With the PostgreSQL backend, `--max-clock-skew-ms` refuses to act when the receiver's clock disagrees with the database's (tested end to end in Python and Node) |
| 16 | Ledger failure | database stopped | nothing permitted | `unavailable`; recovers after restart, replay still refused | No | `test_act_postgres.py` | none |
| 17 | Database partition and failover | proxy-cut standby, promotion | fail closed; no acknowledged write lost under quorum commit | as designed; asynchronous standbys can lose a write | Partly (async standby) | `test_ledger_postgres.py`, `CONSISTENCY.md` | DEPLOY |
| 18 | Crash during reservation | client killed mid-transaction | no half-spent message | none | No | `test_ledger_postgres.py` | none |
| 19 | Crash after action, before completion | process killed with a live permit (real PostgreSQL) | refused while leased; later offered again | as expected, with the same idempotency key | At-least-once by design | `test_adversarial_r4.py` | DEPLOY: the target must deduplicate on the key |
| 20 | Audit manipulation | edit or remove a row or line | detected | detected in files (Python, Node) and PostgreSQL; the receiver will not start on a damaged chain | No (edit, middle removal). A cut-off tail is **not** detected | `test_policy_postgres.py`, `grants.test.mjs`, `test_grants.py` | DEPLOY: anchor the head digest externally |
| 21 | Cross-language parsing differences | duplicate keys, `\u` escapes, floats, NaN, huge ints, nesting, size | same refusal | both pass all 33 cases | No | `conformance-suite.json` | none |
| 22 | Oversized and deeply nested payloads | over 1 MiB, 200 levels | `malformed` | `malformed` in both | No | suite | none |
| 23 | Rate-limit bypass | repeated unknown-sender traffic | no signature work, no signed reply | as designed | No | `test_preauth.py` (earlier revision) | none |
| 24 | Cryptographic profile downgrade | `use('pure')` in production; editing the environment after start | refuse; ignore the edit | refused; ignored | No | `test_crypto_backend.py` | none |
| 25 | Transport downgrade | TLS 1.2-only client; plain TCP at a TLS server and the reverse | refused | refused; each protection removed in turn makes a test fail | No | `test_transport.py` | none |
| 26 | Identity spoofing over TLS | valid certificate for A, object signed by M | `untrusted` | `untrusted` | No | `test_transport.py` | none |
| 27 | Malformed provider responses | 11 failure modes for each of 5 client configurations | refusal, never a pass | refusal, with provenance recording why | No | `test_providers.py` | none |
| 28 | Provider timeout and interruption | slow server, early close | refusal | refusal | No | `test_providers.py` | none |
| 29 | A model claims approval or authority | extra keys in the model's answer | refused by the strict reader | refused; a fooled `pass` is lowered by the decider's policy | No | `test_providers.py` | none |

## Not covered

Live provider behaviour (no keys), a multi-machine deployment (everything ran on one machine, with processes standing in for
hosts), and a third-party implementation. Node under PostgreSQL was added later and tested on one machine. Each of these caps a
score; see the assessment.
