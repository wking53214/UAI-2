# UAI-1 security profiles

> **Check of 2026-11-07.** Every test name and repository file this page cites was confirmed to exist in this repository. Claims about the outcome of earlier runs and about other repositories were not re-run or re-verified.
A profile is a named set of protections a deployment commits to, so a reader knows what it does and does not get. This
page says what each profile provides, which deployment conditions it suits, and what is **not** provided. Where something
is an operator's configuration rather than code, that is said. Transport security and object security are separate: a
signature proves who made an object and that it is unchanged and encrypts nothing; TLS protects the channel and says
nothing about the object; neither is permission to act.

## Object layer (every profile)

Every UAI-1 object is an Ed25519-signed envelope, read strictly, checked for freshness, and judged by a receiver that
keeps its own authority. This holds whatever carries the bytes.

| Property | Provided | Where |
|---|---|---|
| Authorship and integrity of each object | Yes | `envelope.py`, `interop/node/uai.mjs` |
| Confidentiality of the object | **No** (signed, not encrypted) | use a transport profile |
| Freshness and replay refusal | Yes, by the receiver's ledger | `ledger*.py`, `grants.mjs` |
| Permission to act | **No**, never from the signature | the receiver's grants |

## Cryptographic profile

| Profile | What it is | Suits | Not provided |
|---|---|---|---|
| default | pure-Python Ed25519, or OpenSSL if `UAI_CRYPTO_BACKEND=cryptography`. `crypto_backend.use()` may be called until `freeze()` | development, tests, benchmarks | no protection against a process being reconfigured |
| production (`UAI_PROFILE=production`) | `UAI_CRYPTO_BACKEND=cryptography` must be named; the profile and backend are read once, frozen at first use, and cannot be changed in the running process; a local signing seed on the pure backend is refused | any real deployment signing in-process | key material is in process memory; no HSM or OS keystore support is implemented or tested |

`crypto_backend.diagnostics()` (Python) and `cryptoDiagnostics()` (Node) report what is in force so an operator can compare
it with what was approved. Neither claims constant-time operation: no timing measurement was made. A key that must not
live in process memory belongs behind `Signer.external` with a keystore or HSM function; that hook exists, and no hardware
implementation was run here.

## Transport profiles

Defined and implemented in `cns_interop/transport.py`.

| Profile | Channel protection | Suits | Not provided |
|---|---|---|---|
| `local-process` | The operating system's (pipes, Unix socket, file permissions). No channel authentication, no encryption | one host the operator controls | anything across a network or a trust boundary |
| `tls13-mutual` | TLS 1.3 **only**, both sides present certificates, each verified against a CA the receiver chose, each certificate bound to a UAI identity, optional CRL check, rotation by `reload()` | any traffic that leaves the host or a trusted segment | OCSP, certificate transparency, revocation freshness, hardware-held keys, post-quantum security, traffic analysis resistance |

There is no weaker network profile: TLS 1.2 and below and plain TCP are refused, not negotiated. An implementation that
offers a profile not listed here is outside UAI-1 and must say so.

**Identity binding.** The peer's UAI identity is read from the verified certificate (`subjectAltName` URI equal to the
identity text, exactly one). Objects received on the connection must be signed by that identity (`open_bound`). The
identity a peer is expected to have is the receiver's configuration, never something the peer says.

**Failure behaviour.** A handshake, certificate, identity, frame size, timeout or early-close failure is a refusal
(`untrusted` or `unavailable`). A CRL that is configured and unusable fails the handshake, so revocation checking is never
skipped quietly. A reload with unusable files raises and changes nothing. Existing connections keep the certificate they
were authenticated with until they close.

## Receiver state profiles

| Profile | Decisions and permits | Withdrawals | Audit | Suits | Not provided |
|---|---|---|---|---|---|
| single host (files) | `FileLedger` | SQLite `GrantStore` | hash chain in a file under `flock` | one host, development | any other host seeing state |
| single host (SQLite, either language) | `SqliteLedger` | SQLite `GrantStore` | hash chain in a file (lock file in Node) | one host, Python or Node | multi-host; do not point Python and Node at one audit file |
| shared (PostgreSQL, Python or Node) | `PostgresLedger` (server-clock leases, fences) | `PostgresGrantStore` | one `PostgresAudit` chain, written and verified by either language | several receiver hosts | consensus; availability beyond one primary; detection of a cut-off tail of the chain |

Under `UAI_PROFILE=production`, `interop/act.py` and `interop/node/act.mjs` refuse the single-host backends and require the PostgreSQL ledger
**and** policy backend, and both runners require the clock check (next section). A shared policy version (`--publish-policy`) makes a host with stale or divergent grants refuse to
start. Asynchronous standbys can lose an acknowledged write on failover; `--require-sync-replication` makes the ledger
refuse unless the server demands quorum-durable commit, which is a configuration check, not a proof of the server's
replication. A database administrator is inside the trust boundary of these stores.

## Clock trust in the production-secure receiver

A receiver judges every lifetime (`expires_at`, a grant's expiry, an approval's expiry) by a clock. If that clock is the
receiver's own, a receiver set back far enough accepts an expired decision, and on a shared ledger that forgets old rows it
can accept it again. The production-secure receiver therefore judges lifetimes by the **ledger database's** time. Labels:
**implemented** (the code does it), **tested** (a test in this repository shows it, named), **planned** (not done),
**limit** (stated, not a defect to be fixed here).

| Requirement | Status |
|---|---|
| The PostgreSQL ledger refuses (`expired`) a message that has expired by the database's clock, before any write, in Python and Node. A row it has forgotten can never be spent again, whatever any receiver's clock says | implemented, tested (`test_expiry_purge_replay.py`) |
| `--max-clock-skew-ms` is mandatory under `UAI_PROFILE=production`, in `act.py` and `act.mjs`; without it the receiver refuses to start (`config`, exit 2). `--diagnostics` in `act.py` acts on nothing and still runs | implemented, tested (`test_clock_trust_production.py`) |
| The tolerance must be strictly below the ledger's retention window `keep_ms` (120000 ms in both runners). At or above it, the start is refused as `config` and audited. The reason: the ledger forgets a row `keep_ms` after expiry, so every receiver within tolerance must already see that message as expired | implemented, tested (`test_expiry_purge_replay.py`, `test_clock_fail_closed.py`) |
| The database's time is read at start-up and again for every decision, and carried between readings on the host's monotonic clock, so the host's wall clock (set back or forward) does not move it | implemented, tested |
| Fail closed: the database unreachable, a statement past the timeout (3 s by default), no time, NULL, text, `NaN`, a float, negative, before 2000, beyond 2^53-1: `unavailable`. The host and the database disagreeing by more than the tolerance (plus half the measured round trip): `clock_skew`. Nothing is read from the job or spent. The decision stays unspent and can be presented again | implemented, tested (`test_clock_fail_closed.py`, `test_clock_matrix.py`, `interop/node/clock.test.mjs`) |
| The ledger itself refuses (`unavailable`) when the database's clock gives no usable time, instead of treating "not comparable" as "not expired" | implemented, tested (found and fixed in RACE-02 step 4) |
| The Node receiver enforces the production profile as Python does: PostgreSQL ledger required, host-local withdrawals and audit refused, the clock check required, all before any file or table is created | implemented, tested |
| Error codes are the registered ones (`unavailable`, `clock_skew`, `config`), and the registry (`contracts/uai1/errors.json`) lists `config` as emitted by both implementations; a test keeps the registry equal to what each source emits | implemented, tested (`test_uai1_package.py`) |

**What is audited.** Every refusal to start or to sync that is not a permit decision (`config`, `clock_skew`,
`unavailable`) writes one structured line on stderr, `{"uai_audit": {..., "stage": "startup" | "decision", "recorded":
"file" | "postgres" | null, "audit_error": "..."}}`. It is also appended to the receiver's hash-chained audit record where
one is configured and reachable: the shared PostgreSQL chain in either language under `--policy-backend postgres`, otherwise the
`--audit` file in either language (one chain: a Python entry and a Node entry chain onto each other and verify). If the
record cannot be written, the line says so (`recorded: null`, the reason in `audit_error`); the refusal is unchanged and
nothing is swallowed. A clock that fails when re-read for a decision is recorded with stage `decision`. *Implemented, tested.*

Limits of that record, said plainly:

- A decision-only receiver (a production receiver in either language can take this form, with no receiver policy) has no audit record at all. Its
  refusals are the stderr line, which is only as durable as wherever the operator sends stderr, and is not hash-chained.
  *Limit.*
- When the database is what is down, the production audit sink (the same database) is down too: the refusal is the stderr
  line only. *Tested for Python in production.*
- The entry's `at` is the receiver host's clock, because the refusal may be about the database's clock. *Limit.*
- A caller that can start the receiver repeatedly with a bad configuration can add entries to the chain. The size growth was
  not measured. *Limit, not measured.*

**Honest limits of the clock design.**

- One reference. A database whose own clock is wrong by less than the tolerance is followed, and one wrong by more is
  refused; the code cannot know which clock is right. Disciplining the database host's clock (NTP or similar) is the
  operator's duty and is not checked. *Limit.*
- A tolerance has a price. With the database `t` ms behind real time (and `t` within the tolerance), a decision that expired
  up to `t` ms ago by real time is still live and is honoured **once**; it is never honoured twice, because the ledger keeps
  its row for `keep_ms`, far longer than the tolerance. *Tested* with the database 4 s behind, tolerance 5 s.
- The mandatory check is a property of the runners (`act.py`, `act.mjs`). A program that builds a `RemoteDecisionGuard` itself
  with a plain clock still gets the host's clock, and the ledger's own database-time refusal; it does not get the skew check
  unless it gives the guard a `TrustedClock`. No library-level refusal exists. *Planned, not done.*
- The tolerance cannot be set above the retention window from the runners, and the runners do not let a deployment change
  `keep_ms` (120000 ms). A library user who gives `PostgresLedger` another `keep_ms` must give `TrustedClock` the same
  value; the constructor enforces the inequality. *Implemented.*
- **Multiple hosts are NOT proved.** Every test here runs on one machine with one operating-system clock. The database's
  clock is moved inside the test server (a function that shadows `clock_timestamp()`), which shows what the receivers do
  when the server answers a wrong time; it is not a second host with its own drift. Separate processes stand in for hosts.
  A real multi-host run, with real clock drift between hosts and a network between them, remains to be done. *Planned.*
- Restart durability was tested for a clean server restart (`pg_ctl stop -m fast` then start), with a decision already
  honoured refused as `replayed` afterwards by both languages. A crash restart of the database was not tested with these scenarios (failover of the ledger is covered separately, see the guidance below).

## PostgreSQL deployment guidance for the shared ledger

Written from what the code does and what the tests above show. "Inspected" means read in the code, not exercised.

1. **Time.** Run the database host's clock under a disciplined time source and alert on drift. Set `--max-clock-skew-ms` as low
   as that discipline allows; the tests use 5000 ms. It must be below 120000 ms. A step of the database's clock larger than
   the tolerance makes every receiver refuse (`clock_skew`) at its next decision instead of silently following; that is the
   intended behaviour. *Tested* (an hour either way).
2. **One DSN, by variable name.** Both runners take `--ledger-dsn-env NAME`, the name of an environment variable; the
   connection string is not accepted on the command line (a Node test checks that it never appears on one). The Node
   receiver needs the `psql` client on the host.
3. **Timeouts.** Connect, statement and lock timeouts are bounded (3 s by default in both languages). In Python a commit
   waiting on a standby is cancelled and refused, not trusted (Node does the same from outside: it bounds the whole `psql` call and then asks the server to cancel the waiting backend; see docs/interop/LEDGER_PARITY.md). A database that answers after 5 s was refused as `unavailable` in
   under 25 s in a test.
4. **Replication.** `--require-sync-replication` (Python and Node) refuses to write unless the server is configured for
   quorum-durable commit. That is a configuration check, not a proof of the server's replication. Asynchronous standbys can
   lose an acknowledged redemption on failover. *Tested* against a real primary and standby in `test_ledger_postgres.py`: a synchronous standby behind a partition makes the ledger refuse, and after promotion nothing that was acknowledged is missing; and the same for the Node ledger in `test_node_quorum.py`. The standby is a second server process on the same machine, not a second machine. Not combined with the clock scenarios.
5. **Privileges.** The runners create their own tables (`CREATE TABLE IF NOT EXISTS`, a sequence and an index) on first
   start, so the first start needs the right to create them; a least-privilege role for steady state is a deployment
   choice. *Inspected, not tested.* A database administrator is inside the trust boundary of these stores.
6. **Transport to the database.** The connection options the clients map include `sslmode` and the certificate options;
   whether TLS to the database is on is the DSN's content. *Supported by the client libraries, not tested here.*
7. **Backups.** A ledger restored from a backup forgets every redemption made after the backup was taken, which re-opens
   replay for decisions still live at the restore. Treat a restore as an incident: refuse decisions issued before it until
   they have expired. *Guidance, not tested.*
8. **Audit files.** Python and Node entries chain onto each other in one audit file and verify (tested, written one after the
   other), but the two languages lock the file differently, so do not run both against one file at the same moment (stated
   above). The PostgreSQL audit chain has no such limit: either language appends under the database's lock (tested, with concurrent writers of both).

## Which profile for which condition

| Deployment | Minimum |
|---|---|
| Development, tests, one machine | default crypto, `local-process`, single-host files or SQLite |
| One production host, local callers | production crypto, `local-process`, PostgreSQL ledger and policy (`act.py` under `UAI_PROFILE=production` accepts nothing else, even on one host) |
| Production across hosts or networks | production crypto, `tls13-mutual`, PostgreSQL ledger and policy, synchronous replication where a lost write is unacceptable |
| Node receiver | SQLite on one host, or the shared PostgreSQL ledger (`act.mjs --ledger-backend postgres`, needs the `psql` client); with `--policy-backend postgres` withdrawals, the policy version and the audit chain are shared too, and `--require-sync-replication` is honoured. Under `UAI_PROFILE=production` it enforces the same profile as `act.py`: the PostgreSQL ledger, `--policy-backend postgres` (or `--decision-only`) and `--max-clock-skew-ms` are required. Multi-host operation is not proven; see docs/interop/LEDGER_PARITY.md |
