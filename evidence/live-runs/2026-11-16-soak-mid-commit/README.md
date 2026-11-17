# The 15-minute soak with commits cut off mid-flight, 2026-11-16

`soak-mid-commit.json` is the report `interop/soak.py --out` wrote, unaltered (SHA-256 `b1f8630a68a4faffb8d5f4b361f2358c8d738449f7001e7ecd09b89063d7857f`).

Command: `python interop/soak.py --seconds 900 --workers 10 --seed 7 --mid-commit 0.05 --out soak-mid-commit.json`

**Where it ran:** a Claude Code cloud workspace (Linux, 2 CPU cores, Python 3.13, local PostgreSQL), not the operator's machine. It
ran from the code in PR #33 (`interop/soak.py` with `--mid-commit`). One machine, so this still shows nothing about network faults,
clock drift between hosts or standby failover.

## What it shows

| Measure | Result |
|---|---|
| Duration | 900 s, 10 workers, message pool of 30, seed 7 |
| Messages committed | 8,749 (equal in the ledger and in the effects table) |
| Database server kills | 88 (`pg_ctl -m immediate`) |
| Worker kills | 79 |
| Commits cut off in flight (backend killed during COMMIT) | 215 |
| Messages left ambiguous | 263: 242 turned out committed, 21 rolled back |
| Contended attempts refused as replays | 219,231 |
| Late commits refused `lease_lost` | 783 |
| Findings | 0 |

Both outcomes of the cut-off window were reached, and in both cases the five invariants held: exactly one effect per message, spend
equals effect, every commit a worker was told succeeded is still there, the audit chain verifies (11,046 entries) and covers every
effect, and no lease is stuck.

## What it does not show

No real network faults or clock drift, no standby failover, one machine, and 15 minutes is not an hours-long soak. The earlier
15-minute run (2026-11-15, recorded in `docs/EVIDENCE.md`) did not use `--mid-commit` and its JSON report was never committed.
