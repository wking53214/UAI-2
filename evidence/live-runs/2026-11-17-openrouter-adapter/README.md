# OpenRouter through its own client, live, 2026-11-17

**Label: EXECUTED live, once, two calls, one free model, $0. One call returned a valid answer and one did not.**

| File | What it is | SHA-256 |
|---|---|---|
| `live-providers.json` | what `interop/live_providers.py --out` wrote, **unaltered**: seven entries, six `executed: false` | `d9422205d41caefbf9c175fb1cb138eb29eb34d1870f2dc47eddfb9962c3a3e2` |

It holds digests, not the bytes sent or received. It was scanned for key prefixes, bearer tokens and authorization headers: no matches.

- **Commit tested:** `0584addaedee67ecb2b9a3a7a36ca2f23b9df3d9` (branch `claude/uai2-openrouter-adapter`, built on `main` `3627d3c8e2ee86ac8aa71808c1626d89e676fddf`), the commit that adds
  `openrouter_complete`. This evidence was therefore made against the adapter it is about, not against a different build.
- **Command:** `python interop/live_providers.py --out live-providers.json` with `OPENROUTER_MODEL=inclusionai/ling-3.2-flash:free` (a fixed id, no routing options),
  a placeholder key (the session's network proxy added the real one), and every Anthropic variable unset. The runner sends `max_tokens` 512.

## Results

| Document | HTTP | Latency | Tokens in/out | Model asked for | Model reported | Strict reader | Final verdict (after the policy) |
|---|---|---|---|---|---|---|---|
| clears (512,000) | 200 | 13,391 ms | 558 / 331 | `inclusionai/ling-3.2-flash:free` | `inclusionai/ling-3.2-flash:free` | accepted, `finish_reason stop` | `pass` |
| does not clear (100,000) | 200 | 13,965 ms | 558 / 512 | same | same | **REJECTED: `finish_reason length`, cut off** | **none: refused** |

Request and response SHA-256 digests for each call are in `provenance` in the file.

## What this does and does not show

- **EXECUTED:** the client sent a request to OpenRouter's real address, read a real answer strictly, kept the provider name `openrouter`, and recorded the model asked for next
  to the model reported (here the same). The record says `openrouter`, never `openai`.
- **The second call is a failed call, not a pass.** The model spent the 512-token limit and was cut off, so the strict reader refused it. No replacement call was made. The same
  model answered 21 of 22 jury documents under the jury's 2,000-token limit (folder `2026-11-17-jury-current-prompt/`, in the separate evidence PR; one more cut-off there). The runner's 512-token limit is too small
  for this model, as it was for Groq's reasoning model in folder `2026-11-17-provider-refresh/` (same separate PR); the runner was left as it is.
- **UNKNOWN:** which host served these calls. A free OpenRouter id is served by whichever host has room, and the response does not say which.
- **Not shown:** any failure mode against the real service (rate limit, bad model name, a malformed body), other models, the front door's `uai.connect` (it does not offer
  `openrouter` yet), or any behaviour on hostile documents beyond what the jury run records.
- OpenRouter is a router and a billing layer, not a model developer. The model id names `inclusionai` as the maker (INFERRED from the id).
- Other OpenRouter calls were made on 2026-11-17 on a different, unmerged branch while this was being prepared. They are not part of this evidence.
