# UAI-1 advancement: final assessment

Start `a564be25f5666642e4efe1bfcec8693bfc0733fc`, 1437 tests. End: 11 commits on `claude/uai1-advancement-8-0-2kc9u8`
(local, not pushed), 1986 Python tests and 23 Node tests, 0 failed, 0 skipped. ruff, `mypy cns_interop`,
`mypy cns_composition` and `mypy --strict cns/` are clean. Only Python 3.13 and Node 22 were run.

## Score: 6.1, not 8.0

| Dimension | Weight | Before | Now | Why it is not higher |
|---|---|---|---|---|
| Identity and cryptographic integrity | 15% | 5 | 6.5 | The default signer is still pure Python and not constant time. The hardened backend is differential-tested for identical accept sets but its side-channel behavior was not measured. No HSM or keystore integration was executed. |
| Trust, revocation, distributed replay | 20% | 4 | 6.5 | Cross-host exactly-once is demonstrated only against an in-memory coordinator stand-in, never a real distributed store. Revocation delivery is the receiver's problem. Leases make actions at-least-once. |
| Cross-language interoperability | 15% | 6 | 7.5 | Two implementations, not three. The same author wrote both and the generator. Node has no endorsements and no grants. |
| Capability negotiation and authorization | 15% | 5 | 6.5 | Grants and approvals exist in Python only. No delegation. |
| Selective disclosure and purpose | 10% | 5 | 6.0 | Purpose is a naming convention on the capability, enforced by the receiver, not a typed field. Retention is recorded, not enforced. |
| Real AI and agent interoperability | 15% | 2 | 4.0 | No model provider was ever called. The "model" is a deterministic script. The contract and its hostile-output handling are real. |
| Production engineering and resilience | 10% | 4 | 5.5 | No metrics or rate limiting; `FileLedger` still reads the whole file per spend; CI on 3.10 to 3.12 not observed. |
| **Weighted** | | **4.4** | **6.1** | |

An 8.0 needs at least a real provider integration run with credentials, a real coordinated store passing the
conformance suite under partition, and an implementation written by someone else.

## Findings

Closed (each with a regression test; the first four fail without the fix): F-02 torn-line wedge, F-03 ledger clock,
F-04 crash between permission and action (leases), F-07 seed leak through pickling, F-05 and F-06 signed revocation and
rotation, F-09 Python-only oracle, F-10 lenient UTF-8 in Node, F-11 Node parity, F-12 receiver-side purpose and
actions, F-13 human approval an agent cannot give. Four divergences the new campaign found and fixed: Node accepted a
zero ttl, Python accepted out-of-range integers at read time, Node decoded invalid UTF-8 leniently, Node buffered an
endless line.

Partly closed: F-01 (the mechanism and conformance suite exist; a real store does not), F-08 (algorithm registry
and vectors; no second algorithm exists to substitute).

Outstanding: F-14 pre-authentication CPU cost (about 3.9 ms per verify, left to the transport).

## What was executed versus not

Executed: every test above; 8 mutation experiments on the campaign (7 killed on the first run; the survivor, an emptied
Node small-order list, led to two forged-signature cases that now kill it and the Python equivalent); the before and
after probes (torn line fixed; 8-process exactly-once still holds; two local ledgers still accept twice, as a local
ledger must; pickling a `Signer` now raises); `interop/demo_adapters.py` end to end against the Node agent.

Not executed: any model provider; any real distributed store; an HSM; Python 3.10 to 3.12; Windows (the file ledger
needs POSIX locks); network partitions on real networks.

## Unverified and unimplemented

Constant-time behavior of either backend. Delegation. Transport confidentiality. A third language. Registries.
Endorsements in Node. Grants in Node.

## Compatibility

Revision 1 messages sign, serialize and verify exactly as before and every revision 1 vector passes. One wire
addition (`revocation` kind), which a revision 1 peer refuses as malformed. Behavior changes on purpose are listed in
`docs/migrations/uai-1-revision-2.md`, including the three existing tests edited under rule 5 (each assertion changed
only as the step required: the import allow-list, the Node test file list, the Node pass count).

## Next milestone

(1) Run a real provider through `PromptedModelAdapter` and record `live=True` evidence. (2) Put a real linearizable
store behind `Coordinator` and run `ledger_conformance` plus a partition test against it. (3) Get a second team to
implement against `contracts/uai-interop-vectors.json`. (4) Port grants to Node.
