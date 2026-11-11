# Node and Python PostgreSQL ledger parity

> **Check of 2026-11-07.** Every test name and repository file this page cites was confirmed to exist in this repository. Claims about the outcome of earlier runs and about other repositories were not re-run or re-verified.
RACE-02 I-08 (R2-C-06). Verified from source on branch `race02-parity` (based on `race02-clock`), and every row below
marked "tested" names the test that runs it against a real PostgreSQL 16 server started by the test. Labels used:
**implemented** (code exists), **tested** (a test exercises it here), **experimental** (works, but not hardened or not
exercised beyond the named tests), **planned** (not done), **BLOCKED** (cannot be shown here, and why).

Scope: the receiver-side storage contract of a UAI-1 receiver on PostgreSQL. Python is `cns_interop/ledger_postgres.py`,
`policy_postgres.py`, `fencing.py`, `grants.py`, `interop/act.py`. Node is `interop/node/pg.mjs`, `pg_policy.mjs`,
`fencing.mjs`, `grants.mjs`, `act.mjs`. Node reaches PostgreSQL through the `psql` binary and adds no npm dependency; Python
added no dependency either. `cns/` is untouched. CNS grants no permission here: this is the receiver's storage.

## What now has the same contract

The ledger tables are the ones Python already created. The policy and audit tables are Python's. No column was added,
no existing table changed, no existing audit digest changed (a golden chain computed from the unchanged Python code is pinned
in `test_node_policy_postgres.py`). No migration is needed: a Node receiver pointed at an existing Python database finds the
tables it expects and creates the missing ones with Python's own DDL (`CREATE ... IF NOT EXISTS`). Rolling back is removing
the Node receiver; the data is Python-readable.

| # | Contract element | Python | Node | Status | Test |
|---|---|---|---|---|---|
| 1 | Decision and permit ledger: spend, reserve, commit, release, lease takeover, growing fence, database clock | `ledger_postgres.PostgresLedger` | `pg.mjs` `PostgresLedger`, same SQL and table | implemented, tested | `test_node_ledger_conformance.py` (every generic property, Node alone and a Python+Node pair; five PostgreSQL-specific properties on Python, Node and the pair) |
| 2 | Withdrawals shared across hosts | `PostgresGrantStore.withdraw/is_withdrawn` | `pg_policy.mjs` `PostgresGrantStore` as a `GrantTable` store | implemented, tested | `test_node_policy_postgres.py` (both directions, through the receiver's own grant check, alternating, database time) |
| 3 | Audit chain in the database | `PostgresAudit` | `pg_policy.mjs` `PostgresAudit`, same table, same digest | implemented, tested | `test_node_policy_postgres.py` (each verifies the other's chain; altered, removed, reordered, garbage and changed-digest rows refused as `unavailable` by both; 8 concurrent writers of both languages, one unbroken chain; golden digests) |
| 4 | Policy version publish and require | `publish_policy`, `require_policy`, `policy_digest` | `publishPolicy`, `requirePolicy`, `policyDigest` | implemented, tested | `test_node_policy_version.py` (same digest for the same grants, next-version-only, one winner among 8 mixed publishers, `stale_policy`, `conflict`, outage `unavailable`) |
| 5 | The receiver runner under the shared policy backend | `act.py --policy-backend postgres` | `act.mjs --policy-backend postgres`, `--publish-policy` | implemented, tested | `test_node_policy_version.py` (act.mjs acts under the published policy, writes the chain act.py verifies, honours Python's withdrawal, refuses stale policy and audits it in the shared chain) |
| 6 | Quorum-durable commit | `require_sync_replication`, `_require_quorum` | `requireSyncReplication`, `act.mjs --require-sync-replication` | implemented, tested | `test_node_quorum.py`: refusal on a single node with Python's reason text; and with a REAL streaming standby (a second server process on this machine): success path, a partition making the ledger refuse within the bound, failover keeps the acknowledged write |
| 7 | Atomic business write plus commit | `commit_in(connection, reservation)` | `commitIn(reservation, sql, vars)` | implemented, tested | `test_node_quorum.py` (spend and caller SQL in one transaction; a lost lease runs none of the caller's SQL; a failing statement rolls the spend back) |
| 8 | Fencing check | `FencedTarget` | `fencing.mjs` `FencedTarget` | implemented, tested | `test_node_policy_postgres.py` (one 13-step sequence, identical answers; a stale fence issued by either language's ledger is refused by the other's target) |
| 9 | Error codes | registry | `fenced`, `stale_policy`, `conflict` now emitted by Node | implemented, tested | `contracts/uai1/errors.json` says `both`; `test_uai1_package.py` keeps the registry equal to what each source emits |
| 10 | Partition between the receiver and the database | `test_ledger_postgres.py` | Node via a TCP proxy | tested (one machine, a proxy, not a network) | `test_node_quorum.py` |
| 11 | Node enforces the production profile | `act.py` | `act.mjs`: PostgreSQL ledger, `--policy-backend postgres` (or `--decision-only`), `--max-clock-skew-ms` | implemented, tested | `test_clock_trust_production.py`, `test_node_policy_version.py` |

## What was found, and what was not

- Step 2 found NO divergence in the ledger: the Node ledger already passed every generic conformance property and the five
  extra PostgreSQL-specific ones. That was a result, not a gap, and no fix was made for it.
- Accidental differences, now removed: rows 2 to 9 above (they were absent in Node).
- R2-C-16 (found, fixed): `act.py` ignored `--publish-policy` unless `--policy-backend postgres` was also given, so an
  operator could believe a policy had been published. Now `config`, exit 2, in both runners.
- Found in Node's own new code before it shipped, and handled: a `psql` killed at its bound leaves the server backend
  waiting on an unreachable standby, holding its row (measured). Python cancels that wait from inside; Node now asks the server
  to cancel the backend named by a per-call `application_name`. The row is then committed locally as for Python.

## Differences that remain, and why each is intentional

| Difference | Why it stays |
|---|---|
| Client: Node uses the `psql` binary, Python uses psycopg | Node has no PostgreSQL client in its standard library and a dependency was ruled out. The contract is the SQL and the table, not the client. |
| Connection options: Node maps a fixed list of libpq options and refuses the rest (`config`); psycopg takes any | Refusing is safer than silently dropping an option such as a TLS setting. |
| No `tcp_user_timeout` in Node; the whole call is killed at `connect + 2 x statement_timeout + 2 s` | `psql` gives no per-socket control. Both fail closed as `unavailable`. With a synchronous standby behind a partition, Node refuses after up to that bound (about 11 s by default) and Python after `statement_timeout` (about 3 s). |
| A commit stuck on a standby is cancelled from outside (second `psql`) in Node, from inside in Python | Same end state (committed on the primary, refused to the caller, row held until the lease lapses), reached a moment later in Node. |
| `commitIn(reservation, sql, vars)` instead of `commit_in(connection, reservation)` | `psql` holds no caller transaction. The guarantee (both persist or neither) is the same; a business-statement error surfaces as `unavailable` instead of the driver's own error. |
| Audit entry text bytes (Node: sorted compact JSON; Python: `json.dumps(sort_keys=True)`) | Verification re-parses and re-derives the digest in both languages, so the bytes are not part of the contract; the digests are identical. Node's parser is also strict (duplicate keys, floats refused), Python's is not; neither can produce such an entry. |
| Node appends to the shared chain optimistically (read head, hash, conditional insert under the same advisory lock, up to 64 tries); Python holds the lock across the read | The digest is computed in Node between two `psql` calls. Under extreme contention Node can refuse (`unavailable`, nothing written) where Python would wait. Fail closed. |
| Local audit file: Python locks with `flock`, Node with a lock file; `audit_recover` is Python only | Unchanged single-host behaviour. The file is not a production backend. Do not point both languages at one file. |
| `--diagnostics` and `--ledger-backend file` exist only in `act.py` | Operator convenience and a development backend; neither affects safety. `--diagnostics` is planned for Node. |
| `FencedTarget` in both languages is an in-memory reference check | A real target keeps the highest fence in the same transaction as its write; that is the integrator's, in both languages. |
| Signed revocations and rotations | A file or in-memory store in both languages. Neither has a PostgreSQL store. Not a difference. |

## Deployment guidance for a Node receiver on PostgreSQL

1. Install the `psql` client on the host (PostgreSQL 16 client was the only version run). Give the DSN through an environment
   variable named by `--ledger-dsn-env`; it is never on a command line.
2. Production profile: `UAI_PROFILE=production`, `--ledger-backend postgres`, `--policy-backend postgres`,
   `--max-clock-skew-ms` (below the ledger's 120000 ms retention), and `--require-sync-replication` where a lost write is
   unacceptable. An operator publishes the grants file with `--publish-policy <next version>` (from either language); a host
   whose grants differ refuses to start and the refusal is in the shared chain.
3. Anchor `PostgresAudit.head()` somewhere the database operator cannot write: a hash chain does not detect the newest entries
   being cut off (tested, in both languages).
4. The first start creates tables, so the role needs `CREATE` once. The database administrator is inside the trust boundary.
5. Do not use the Node receiver against a database that other hosts reach through a pooler in statement mode: each call is
   one `psql` session and one transaction, and the advisory locks are transaction-scoped. Not tested here.

## What is NOT proven

Multi-host operation is NOT proven. Everything above ran on one machine with one clock: separate processes stand in for
hosts, a TCP proxy stands in for a network, and the "standby" is a second PostgreSQL process on the same host. These
scenarios were not run and nothing here claims them:

- a network partition on a real network (asymmetric loss, delay, a half-open connection) between receiver hosts and the
  database, or between the primary and a standby on another machine;
- a database failover with clients that must find the new primary (the tests promote a standby and connect to its address
  directly);
- a database restart combined with a host restart across two machines, and recovery ordering;
- clock behaviour across machines (one clock here, so the skew and tolerance logic is shown only with an injected shift);
- TLS to the database, a connection pooler, a managed service, a PostgreSQL version other than 16, and a `psql` other than 16;
- load beyond the 8 to 16 concurrent writers the tests use.

Status: multi-host parity is **BLOCKED** (it needs at least two machines). Single-machine contract parity is implemented and
tested as marked above.
