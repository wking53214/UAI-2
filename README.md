# UAI-2 multi-provider interface proof

A small, stdlib-only proof that three hosted model providers (Google Gemini,
Groq, Cloudflare Workers AI) can sit behind the single CNS typed model
contract without the caller knowing which one is configured.

## Layout

| File | Role |
|---|---|
| `uai2_bridge.py` | Provider-neutral bridge into the CNS `ModelProvider` contract. Enforces the portable request profile and sanitizes failures. |
| `uai2_gemini.py` | Native Gemini adapter. |
| `uai2_groq.py` | Native Groq adapter. |
| `uai2_cloudflare.py` | Native Cloudflare Workers AI adapter. |
| `uai2_factory.py` | Environment-driven provider selection. |
| `tests/` | Unit tests. All HTTP is served by local in-process stubs, so no network or credentials are needed. |

## Dependency on CNS

The proof imports `cns_composition.providers.protocol` from a CNS checkout.
CNS is a read-only reference and is not vendored here. `conftest.py` finds it
in this order:

1. `UAI2_CNS_PATH`, if set, pointing at the root of a CNS checkout.
2. A directory named `CNS` beside this repository.
3. The original local reference path used when the proof was written.

Do not modify CNS files from this repository.

## Running the tests

```
pip install pytest
UAI2_CNS_PATH=/path/to/CNS python -m pytest -q
```

If CNS is checked out beside this repository the variable can be omitted.

## Configuring a provider

`create_provider` reads these variables:

| Variable | Meaning |
|---|---|
| `UAI2_PROVIDER` | `gemini`, `groq`, or `cloudflare`. |
| `UAI2_MODEL` | Model identifier passed through unchanged. |
| `GEMINI_API_KEY` | Required when the provider is `gemini`. |
| `GROQ_API_KEY` | Required when the provider is `groq`. |
| `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN` | Required when the provider is `cloudflare`. |

Keep credentials outside the repository. The ignore rules already exclude
`.env` files, keys, and certificates.
