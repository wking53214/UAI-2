# Live provider refresh, 2026-11-17

**Label: EXECUTED live, once, on 2026-11-17, two providers answered, free tiers, $0.** This refreshes the single-exchange live check
that `interop/live_providers.py` makes (a document that clears and one that does not), at the commit named below.

| File | What it is | SHA-256 |
|---|---|---|
| `live-providers.json` | what `interop/live_providers.py --out` wrote, **unaltered**: seven entries, five `executed: false` | `8ebf3070f25e13523b9256fe44efa3015a66347922eb901de9a70546b1d76f5d` |

It holds digests, not the bytes sent or received. It was scanned for key prefixes, bearer tokens, authorization headers and the operator's
Cloudflare account id: no matches.

- **Commit tested:** `0584addaedee67ecb2b9a3a7a36ca2f23b9df3d9`, built on `main` `3627d3c8e2ee86ac8aa71808c1626d89e676fddf`.
- **Command:** `python interop/live_providers.py --out live-providers.json`, with `GROQ_MODEL=openai/gpt-oss-120b`,
  `CLOUDFLARE_MODEL=@cf/meta/llama-3.3-70b-instruct-fp8-fast`, the Cloudflare account id supplied for the run, placeholder keys (the session's
  network proxy added the real ones), and every Anthropic variable unset. The runner sends `max_tokens` 512.

## Results

| Provider | Requested model | Provider-reported model | Document | HTTP | Latency | Tokens in/out | Strict reader | Final verdict (after the policy) |
|---|---|---|---|---|---|---|---|---|
| Groq | `openai/gpt-oss-120b` | `openai/gpt-oss-120b` | clears (512,000) | 200 | 1,749 ms | 540 / 512 | **REJECTED: `finish_reason length`, cut off** | **none: refused** |
| Groq | `openai/gpt-oss-120b` | `openai/gpt-oss-120b` | does not clear (100,000) | 200 | 1,072 ms | 540 / 273 | accepted | `retry` |
| Cloudflare | `@cf/meta/llama-3.3-70b-instruct-fp8-fast` | `@cf/meta/llama-3.3-70b-instruct-sd` | clears | 200 | 2,213 ms | 504 / 78 | accepted | `pass` |
| Cloudflare | same | `@cf/meta/llama-3.3-70b-instruct-sd` | does not clear | 200 | 1,143 ms | 504 / 54 | accepted | `retry` |

Request and response SHA-256 digests for each call are in `provenance` in the file.

## What this does and does not show

- **Cloudflare: 2 of 2 calls returned a valid answer** and both verdicts are the right ones for the documents.
- **Groq: 1 of 2.** The first call was **not** a valid response: the model is a reasoning model, spent the 512-token limit on reasoning and
  was cut off, so the strict reader refused it. It is recorded as a failed call, not as a pass, and no second attempt was made to replace it.
  The same model answered all 22 jury documents under the jury's 2,000-token limit (`../2026-11-17-jury-current-prompt/`). The finding is
  that the runner's 512-token limit is too small for a reasoning model; the runner was left as it is.
- **Gemini: NOT EXECUTED.** Its native endpoint refuses the Bearer key stored in this environment. UNKNOWN.
- **OpenRouter** is not in this run; it has its own evidence folder after its adapter is reviewed. OpenAI and Azure OpenAI: NOT EXECUTED, no keys.
- Cloudflare served `...-instruct-sd` for the `...-fp8-fast` name. The records keep both; read the reported one.
- One exchange per document per provider is a smoke check, not a measurement of how a model behaves.
