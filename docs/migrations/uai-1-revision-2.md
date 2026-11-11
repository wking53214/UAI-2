# UAI-1 revision 2: the `revocation` kind, two-phase ledgers

> **Check of 2026-11-07.** The files and test names this page cites were checked against the repository. It describes a past revision, so it is kept as written.
Nothing here changes how a revision 1 message is signed, serialized or verified, and every revision 1 test vector
still passes unchanged.

## What was added

| change | wire-visible | who must act |
|---|---|---|
| `revocation` message kind (`cns_interop.revocation`) | yes: a new `kind` value | an implementation that wants to honor signed revocations adds it. One that does not refuses the kind as `malformed`, which fails closed. Nothing breaks. |
| `Ledger.spend(..., now=)`, `reserve`, `commit`, `release`, `SqliteLedger`, `CoordinatedLedger` | no | a custom ledger may add `now`; one that does not is still called without it |
| refusal code `unavailable`, `lease_lost` | no (local refusal codes) | callers that match refusal codes should treat `unavailable` as "no authoritative answer, try later" |
| `TrustPolicy(revocations=, max_staleness_ms=, follow_rotation=)` | no | optional, defaults keep revision 1 behavior |

| `cns_interop.crypto_backend`, optional extra `cns[crypto]` | no | nobody; default stays the pure backend |
| `Signer` refuses pickle and copy | no | code that pickled or copied a `Signer` must not (it leaked the seed) |

## Dependency justification

`cryptography` is optional, imported only inside `crypto_backend.CryptographyBackend`, and the core package still has
`dependencies = []`. Security reason: the pure-Python signer is not constant time and keeps the seed in
interpreter memory; a maintained OpenSSL binding is the practical hardened option short of an HSM. Interoperability
reason: none needed, Ed25519 is deterministic and both backends emit identical bytes.

## Behavior that changed on purpose

- A damaged `FileLedger` file used to raise a JSON error. It now refuses (`unavailable`) and spends nothing; a torn
  final line from a killed writer is cut off, since it was never acknowledged.
- A ledger that raises anything other than a refusal while a decision is verified now yields `unavailable` instead of
  propagating.

## Rollback

Each change is its own commit. Removing the `revocation` kind leaves receivers that stored statements with a SQLite
file they simply stop reading.

## Existing test edited (CLAUDE.md rule 5)

`cns_interop/tests/test_uai_vectors.py::test_cns_interop_imports_only_cns_cns_composition_itself_and_the_standard_library`
asserted no third-party imports at all. Step S5 adds one, so the assertion now also allows `cryptography` in
`crypto_backend.py` and nowhere else. Nothing else about the test changed.

Step S6 also adds `revocation.test.mjs` to the list of Node test files that `test_the_node_implementation_passes_the_same_answer_key`
runs, and its expected pass count goes from 9 to 23 (the 9 that existed, 12 in the new file, 2 new agent tests). Nothing else about the test changed.

## Node implementation: what changed (S6)

`PinnedTrust` takes `revocations`, `maxStalenessMs`, `followRotation`; `Ledger` prunes and leases; `RemoteDecisionGuard`
exists; `verifyDecision` checks that the terms are complete; the Node decider no longer writes a ledger entry for a
sender it does not admit. Endorsements are still Python only, and a peer admitted only by endorsement is refused.

## Found by the interoperability campaign (S7) and fixed

The independent answer key `contracts/uai-interop-vectors.json` (generator `interop/vectors/make_interop_vectors.py`,
signatures from the OpenSSL command line, 137 hand-reasoned cases) was run through both implementations. It found:

| finding | implementation | fix |
|---|---|---|
| a request with `max_ttl_ms` of 0 or `true` was accepted by `proposeTerms` and produced terms with a zero lifetime | Node | `readRequest` validates the capability name, the version, the ttl and the subject as the Python reader does |
| an integer outside +/-(2**53-1) was refused only later, by the envelope profile check, so a reader of any other job (`act.py`) accepted it | Python | `wire.loads` refuses it while reading, as Node always did (`profile`) |
| invalid UTF-8 was decoded to U+FFFD before parsing, so Node and Python could read different text out of the same bytes | Node | `strictParseBytes` with a fatal decoder; the agent reads stdin as bytes |
| a peer that never sent a newline made the Node agent buffer without limit | Node | the agent drops a line that passes 1 MiB |
