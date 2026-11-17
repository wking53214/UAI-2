# Three 25-minute soaks with commits cut off mid-flight, 2026-11-17

Three **separate** runs (each on its own fresh PostgreSQL cluster), not one continuous 75-minute run: a restart of the workspace would have lost only one. The reports are unaltered
output of `interop/soak.py --out`. Code under test: commit `ca8ed3b` (the WS1 branch, `claude/uai2-ws1-soak-flake`), with `--min-cuts` left at 0.

Command (seeds 21, 22, 23): `python interop/soak.py --seconds 1500 --workers 10 --ids 30 --seed N --mid-commit 0.05 --out soak-seedN.json`

**Where it ran:** a Claude Code cloud workspace (Linux, 4 cores, Python 3.13, PostgreSQL 16.15, local), started 14:16:34Z and finished 15:31:49Z, with no other heavy job running. **One machine.**
Not CI, not the operator's machine. No network faults, clock drift between hosts or standby failover.

| File | SHA-256 | Server kills | Worker kills | Messages committed | Cut off in flight | Ambiguous (committed / rolled back) | Late commits refused `lease_lost` | Findings |
|---|---|---|---|---|---|---|---|---|
| `soak-seed21.json` | `2ae6685318f2f65568a88054f0365ef098c297315fcc68c62cc994dd0474b9ab` | 141 | 122 | 14,499 | 481 | 537 (484 / 53) | 1,302 | 0 |
| `soak-seed22.json` | `d0cb4a7f2fe1d74b0a0c27ad5fa07e2c3a133ec60939a02c4fb2d49bce743b9d` | 139 | 131 | 14,490 | 471 | 546 (510 / 36) | 1,245 | 0 |
| `soak-seed23.json` | `e5e827a9aab8bd00bb0c170ac65bf192c9af2f799dce047c4cffcf47c6169ef9` | 126 | 143 | 14,549 | 452 | 519 (473 / 46) | 1,284 | 0 |
| **Total** | | 406 | 396 | 43,538 | 1,404 | 1,602 (1,467 / 135) | 3,831 | **0** |

In every run the ledger's committed messages equal the messages with an effect, every commit a worker was told succeeded is present, the audit chain verified (54,950 entries in all) and
covered every effect, and no lease was left. Both outcomes of the cut-off window were reached in all three runs.

## What it does not show

- One machine: not separate hosts, a real network, clock drift or a standby failover.
- Three 25-minute runs, not hours. Rare timings that need much longer runs are not excluded.
- The kill delay is the changed one (`0.002 * u**2`), so these runs are not byte-comparable with the 2026-11-16 run (which used a uniform 0 to 2 ms); rollbacks were 8.4 percent of ambiguous outcomes here (135 of 1,602) against 8.0 percent there (21 of 263).
