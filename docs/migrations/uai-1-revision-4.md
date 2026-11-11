# UAI-1 revision 4: migration

> **Check of 2026-11-07.** The files and test names this page cites were checked against the repository. It describes a past revision, so it is kept as written.
Revision 4 adds; it removes nothing. Existing integrations keep working. Behaviour changes only where noted.

| Change | Who is affected | Action |
|---|---|---|
| `crypto_backend.use()` raises under `UAI_PROFILE=production` and after `freeze()`. `UAI_PROFILE` is read once. Production requires `UAI_CRYPTO_BACKEND=cryptography` to be set | production deployments that relied on the default or called `use()` | set `UAI_CRYPTO_BACKEND=cryptography` in the environment before start |
| `interop/act.py`: `--ledger` is no longer required (the postgres backend takes none); new `--ledger-backend {file,sqlite,postgres}`, `--ledger-dsn-env`, `--ledger-prefix`, `--require-sync-replication`, `--policy-backend`, `--publish-policy`, `--diagnostics` | operators of the action runner | none; defaults are unchanged (`file`, local grant store and audit). Under `UAI_PROFILE=production` the file and local backends are now refused |
| New `interop/node/grants.mjs`, `act.mjs`; `RemoteDecisionGuard` in Node accepts `grants`, `action`, and `approval` | Node integrations | optional; without `grants` the Node guard behaves as before |
| New `cns_interop.policy_postgres`, `transport`; `PgGuard` split out of `PostgresLedger` unchanged | none (additive) | `pip install 'cns[postgres]'` for the PostgreSQL pieces |
| New provider clients `openai_complete`, `copilot_complete`; `live_providers.py` now prints four `NOT EXECUTED` lines without keys | scripts parsing that output | expect four lines, not two |
| New `contracts/uai1/` package and `jsonschema` in the `dev` extra | contributors | `pip install -e '.[dev]'` |

Deliberately not changed: the wire format, signatures, digests, existing refusal codes and every existing vector.
Intentional limits: Node has no PostgreSQL support; do not point Python and Node at one audit file; a Node receiver uses
`node:sqlite`, which Node 22 labels experimental.
