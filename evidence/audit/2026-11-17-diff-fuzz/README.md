# Differential fuzz of the Python and Node UAI-1 readers, 2026-11-17

Two reports from `python interop/diff_fuzz.py --seed N --per-case 150 --out ...`, run on `main` at `e7919b5` plus the tool itself (cloud workspace, Python 3.13, Node 22,
one machine; **not CI**). Deterministic: the seed fixes every mutation and the adapters are deterministic, so rerunning gives the same bytes (seed 101 was rerun and matched).

| File | SHA-256 | Comparisons | Python accepted | Accept vs refuse disagreements | Code-only disagreements |
|---|---|---|---|---|---|
| `diff-fuzz-seed101.json` | `8cb2da429355aefebf9241a5f26a773e780ba5fd1289853f682b695cb47e8e6d` | 10,800 | 197 | **0** | 34 (one class) |
| `diff-fuzz-seed102.json` | `943d15b8c5c5315cccb0f8aef77bd054cdee08baba3c259b7334c2ee94f8d36d` | 10,800 | 208 | **0** | 26 (two classes) |

Each comparison sends one mutated suite message to both adapters and compares the answers. Mutations: deleted, replaced and inserted characters, escapes, byte order
marks, lone surrogates, number forms, truncation, duplicated slices.

## What it shows

- In 21,600 recorded comparisons (and 46,080 across five earlier scratch seeds) the two implementations never differed on whether to accept or refuse.
- They did differ on the refusal **code** in two classes, both on text with TWO defects: invalid JSON containing a dangling number token (`{"a":1.e0}`: Python `malformed`,
  Node `profile`), and a duplicate key together with an oversize integer (Python `profile`, Node `malformed`). The specification fixes the code for one defect at a time, not
  for two; see `docs/AUDIT_2026-11-17.md`.

## What it does not show

Anything about a third implementation, anything about the signature check beyond what mutated suite messages reach, or any property of messages built from scratch rather than
mutated from the suite. Both implementations were written inside this project.
