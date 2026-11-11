# UAI-1 replay protection: the consistency model

> **Check of 2026-11-07.** Every test name and repository file this page cites was confirmed to exist in this repository. Claims about the outcome of earlier runs and about other repositories were not re-run or re-verified.
What each ledger guarantees, what a protected action must do, and where the claims stop. Everything below was tested; the
tests are named. A guarantee that needs something the code cannot supply by itself says so.

## Four different things

| term | meaning here | who provides it |
|---|---|---|
| **At-most-once reservation** | of all callers, at most one holds a given message at a time | a linearizable coordinator with a unique leader |
| **At-least-once delivery** | a message whose holder crashed or stalled can be reserved again after the lease lapses | the lease; this is why the action must be idempotent |
| **Idempotent protected action** | doing the action twice with the same `Reservation.key` has the effect of doing it once | the protected action |
| **Exactly-once business effect** | the effect happens once | only a target that checks the **fence** or commits in the same transaction as the reservation commit |

UAI-1 makes no exactly-once claim for a target that cannot do either. A local ledger is not a distributed consensus system.

## Ledgers and their guarantees

| ledger | holds across | does not hold across | fence |
|---|---|---|---|
| `MemoryLedger` | threads of one process | restart, other processes | yes (per ledger) |
| `FileLedger` | processes on one host | other hosts, network filesystems | no (0) |
| `SqliteLedger` | processes on one host | other hosts | no (0) |
| `CoordinatedLedger` | hosts, **only as far as its `Coordinator` is linearizable, keeps the time and counts** | a coordinator that loses acknowledged writes | yes (from the coordinator) |

Two local ledgers on two hosts accept one decision twice. That is what a local ledger is.

## The coordinator contract (`ledger.Coordinator`)

`get`, `cas` (linearizable compare-and-set; `expected=None` means absent), **`now()`** (the coordinator's clock) and
**`next_fence()`** (a linearizable counter that only grows).

- **Time is the coordinator's.** `CoordinatedLedger` judges every lease by `Coordinator.now()` and ignores the caller's
  `now` unless a test stand-in is explicitly allowed (`allow_caller_time=True`). Before this rule, a host whose clock ran 61 s
  ahead took a live 60 s lease (reproduced in `test_consistency.py::test_p_l1`). Skew of up to +-10 minutes across eight hosts
  now yields exactly one holder.
- **A lease is not a lock against a stalled holder.** A holder that pauses past its lease can still act. The fence closes that
  for a target that checks it: each reservation gets a larger fence than every earlier one, and `fencing.FencedTarget` refuses
  a lower one (`test_a_stale_holder_whose_lease_was_taken_over_is_rejected...`).
- **Failure is refusal.** An exception, timeout or ambiguous write from the coordinator is `unavailable`: no authoritative
  state, no permission. After an ambiguous write the key may be held by the caller until its lease lapses; liveness returns
  when it does, and a retry meanwhile is refused (`test_an_ambiguous_write_never_lets_the_decision_through...`).

## Why Redis is not the authority

Measured on Redis 7.0.15 with one asynchronous replica behind a controllable proxy that dropped traffic (a first attempt
that merely froze the replica process did not truly partition, because the write was already in the kernel buffer, and was
discarded). The primary **acknowledged** the reservation; it was killed; the replica was promoted; the promoted replica did not
hold the key; a second host reserved the same message. `WAIT 1 300` reported 0 replicas had confirmed, so a client that insists
on `WAIT` before treating a reservation as granted can detect the loss, but Redis has no consensus, so even that is a detection
and not a guarantee. A Redis-backed coordinator is therefore not shipped.

## Choosing a backend

A coordinator must be a store with consensus or synchronous replication to a quorum: PostgreSQL with quorum synchronous
replication, etcd, Consul. PostgreSQL provides what is needed (verified here on a single node: `INSERT ... ON CONFLICT DO
NOTHING` gave one winner among 32 concurrent connections; lease expiry judged by the server's `now()`); a multi-host
high-availability claim needs a real standby and the failure tests in the plan. Until a backend passes
`ledger_conformance` and its own partition tests, no multi-host claim is made.

## What a protected action must do

1. Take the reservation (`reserve`), with a lease longer than the action can take.
2. Pass `Reservation.key` as the action's idempotency key.
3. Where the target can, check `Reservation.fence` (`FencedTarget`) in the target's own transaction.
4. `commit` when done, `release` when the action did not happen. If the process dies, the lease lapses and a retry is safe only
   because of step 2 or 3.


## Receiver policy and audit across hosts (revision 4)

A host-local lock is not multi-host coordination. For several receiver hosts, `cns_interop/policy_postgres.py` keeps
withdrawals, a compare-and-set policy version and one hash-chained audit record in the receiver's own PostgreSQL. Withdrawals
are visible to the next check on every host; a host whose grants differ from the published policy refuses to start; two
operators cannot publish the same version; concurrent permit attempts yield one permit; any edit or middle removal in the
chain is detected. It is the same trust and availability as the one primary: not consensus, asynchronous standbys can lose a
write, a cut-off tail of the chain is not detected (anchor the head digest elsewhere), and a database administrator is inside
the boundary. Tested on one machine with processes standing in for hosts. A crash after a permit and before completion
leaves the decision refused until the lease lapses and then offered again under the same idempotency key (at-least-once):
the target must deduplicate on that key.
