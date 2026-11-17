# Failures caused on purpose against Cloudflare Workers AI, 2026-11-17

`induced-failures.json` is what `interop/induced_failures.py --out` wrote, unaltered, apart from one step the script takes itself: the
operator's Cloudflare account id, which sits in every request path, is replaced by `[account]` before the file is written (no
occurrence was found in it). SHA-256 `237d2c4cbe52a830da4b5b5a5af03d1fd1e4111f156a5bafb39bf5f3353b1404`. It was scanned for key
material, bearer tokens, authorization headers and the account id: no matches. Cost: $0 (the free allowance, six calls). The token was
held by the session's network proxy, which added it to each request; the process saw a placeholder.

## What was run, and on what

Six cases through `cloudflare_complete`, **this repository's own Cloudflare client** (with `--account-id`, the script uses it directly and
not the shared Chat Completions reader the other two runs used), against `https://api.cloudflare.com/client/v4` with
`@cf/meta/llama-3.3-70b-instruct-fp8-fast`.

| Case | What was done | What the client did | Real answer |
|---|---|---|---|
| baseline | nothing | answered | HTTP 200, `finish_reason stop` |
| model-that-does-not-exist | an unknown model name | refused, `http_error`, with Cloudflare's own message | HTTP 400 `7000: No route for that URI` |
| request-it-cannot-accept | `max_tokens` of -5 | refused, `http_error`, with Cloudflare's own message | HTTP 400 `8007: AiError ... max_tokens must be at least 1, got -5` |
| answer-cut-off | `max_tokens` of 1 | refused, `invalid_response` | HTTP 200, `finish_reason length` |
| answer-larger-than-allowed | the caller allows only 40 bytes back | refused, `response_too_large` | HTTP 200 with a real answer, discarded for its size |
| runs-out-of-time | a time limit of 0.05 seconds | refused, `timeout`, after 50 ms | no answer was waited for |

6 of 6 behaved as the case expects. In none did the client pass, answer wrongly or crash. The first run on Cloudflare needed no change to
the client: Cloudflare's `{"errors": [{"code", "message"}]}` shape was already read by the error-text change made earlier the same day.

## Things this run shows that are easy to miss

- **The cut-off check was a real refusal here, and it will not always be.** This model answers in the Chat Completions shape, which says
  why it stopped. Older Workers AI models answer `{"response": text}` and do not, so the client cannot tell a cut-off answer from a
  complete one (documented in `cloudflare_complete`). For such a model the script records `cannot_tell_if_cut_off: true` and does not
  count the case as a pass of the cut-off check. That path is covered offline only; this model did not exercise it.
- **The model that answered is not the one asked for.** The request named `...-fp8-fast`; the answer reported `...-instruct-sd`. The
  record keeps both. Anyone reading a result by model name should read the reported one.
- The error message of the second case is capped at 160 characters, so Cloudflare's text is cut mid-sentence in the record.

## What this run does not show

- **No malformed body.** No real service sends one on request. The malformed-body cases remain offline-only.
- **No wrong-token case.** The proxy substitutes the real token, so a wrong one cannot be sent. The 401 and 403 paths are offline-only.
- **No rate-limit case.** None came up.
- Nothing about Anthropic, OpenAI, Azure OpenAI or the native Gemini route. Nothing about hostile documents.
