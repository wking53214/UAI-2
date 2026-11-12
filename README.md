# UAI: the Universal AI Interface

Any AI model can recommend. Your policy decides. The decision leaves signed, and anyone you trust can verify it, in
Python or in Node.

**Start here: [docs/QUICKSTART.md](docs/QUICKSTART.md)** (ten minutes, one environment variable, one working example).

## What is in this repository

| Part | Where | What it is |
|---|---|---|
| The way in | `uai/` | `uai.connect(provider, model)`: one call, seven provider routes |
| The provider layer | `cns_interop/providers.py` | The only module that talks to a model provider |
| UAI-1, the signed format | `cns_interop/`, spec in `docs/interop/UAI-1.md` | Signed envelopes, receiver-decided trust, revocation, replay protection, negotiated terms, selective disclosure |
| A second implementation | `interop/node/` | Node, sharing no code with the Python one, held to the same answer key |
| For other implementers | `contracts/uai1/` | Schema, error registry, a 69-case conformance suite and its runner |

Supported providers: Anthropic, Google Gemini, OpenAI, GitHub Models and Azure OpenAI (Copilot), Groq, Cloudflare
Workers AI.

## The rule everything here follows

A model is an untrusted advisor. A model recommends, the decider's policy decides, a grant permits, a person approves.
No model is ever handed a signing key, a ledger, a grant or an approval.

## How it relates to CNS

CNS (github.com/wking53214/CNS) defines the gate contract this builds on. This repository depends on the released
tag CNS v3.0.0 and nothing newer. UAI-1 was developed inside CNS and moved here unchanged;
[IMPORTED_FROM_CNS.md](IMPORTED_FROM_CNS.md) records the source commit and how to check the copy.

## What has and has not been shown

**[docs/EVIDENCE.md](docs/EVIDENCE.md)** maps every claim here to the test or live run behind it, and lists what is not
shown yet.

- The test suite runs every provider client against local servers that speak each provider's wire format. That
  checks this code, not any provider.
- A live call needs a key: `python interop/live_providers.py`. It prints `NOT EXECUTED` for each provider without one.
- No team outside this project has yet implemented UAI-1 against the conformance suite.

## Older names

`uai2_bridge` and `uai2_factory` still import and forward to `uai`. `uai2_gemini`, `uai2_groq` and `uai2_cloudflare`
are retired and say so when imported: their clients followed redirects, which could send an API key to another host.

## Running the checks

    python -m pip install -e ".[dev]"
    python -m pytest -q
    python contracts/uai1/run_conformance.py --cmd "python interop/conformance/reference_adapter.py"
    python contracts/uai1/run_conformance.py --cmd "node interop/node/conformance_adapter.mjs"

The ledger tests start real throwaway PostgreSQL clusters and need its server binaries; several tests need Node.
