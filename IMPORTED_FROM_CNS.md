# Where the UAI-1 files came from

The UAI-1 implementation was developed in the CNS repository (github.com/wking53214/CNS) and moved here
unchanged. Its history before the move stays in CNS.

- Source commit: `03eca663c31d5626292074150b4e87cc75f00617` (CNS `main`, 2026-11-10)
- Moved byte for byte: `cns_interop/`, `interop/`, `contracts/uai1/`, `contracts/uai-vectors.json`,
  `contracts/uai-interop-vectors.json`, `docs/interop/`, `docs/migrations/uai-1-revision-{2,3,4}.md`,
  `conftest.py`, `LICENSE` and `contracts/digest-vectors.json` (the CNS digest answer key the Node suite reads).
- To check: at that CNS commit, `git ls-files` over the paths above, then compare each file with the copy here
  at the commit that added this note. Every file is identical.

This repository depends on CNS for the gate contract (`cns.gate`) and the gate chain
(`cns_composition.super_gate`). It pins the released tag `v4.0.0`; nothing here needs a newer CNS.
