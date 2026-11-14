# Changelog

The wire format has its own version (`uai/1`) and does not change with the package version.

## 0.1.0 (not yet tagged)

Added
- `uai.connect` and `uai.from_env`: one way in, seven provider routes.
- `cns_interop.providers`: Groq and Cloudflare Workers AI clients beside Anthropic, Gemini, OpenAI and Copilot.
- The `provider-call` evidence kind: a pass can carry the decider's signed record of the provider call.
- `docs/QUICKSTART.md` and `interop/examples/uai_quickstart.py`.
- UAI-1 (specification, Python and Node implementations, conformance suite), moved from CNS unchanged.
- `interop/jury.py`: the same documents through models from several companies, keeping each model's recommendation
  apart from the decider's final verdict.
- 30 adversarial conformance cases and 8 boundary cases (71 in all), agreed by both implementations.

Changed
- The request digest in a provenance record is the digest of the bytes sent.
- A provider address must be https, or http to a loopback address.
- A provider call has an overall time limit, not only a limit per read.
- Cloudflare Workers AI requests are sent as `messages` and its Chat Completions answers are read by the same rules as
  the OpenAI-compatible routes.

Retired
- `uai2_gemini`, `uai2_groq`, `uai2_cloudflare` (they followed redirects). `uai2_factory` and `uai2_bridge` forward.

Known limits: see `docs/RELEASE_READINESS.md` and `docs/EVIDENCE.md` section 6. OpenAI and Azure OpenAI have not been run live; GitHub Models is retired.
