# Failures caused on purpose against Groq, 2026-11-17

`induced-failures.json` is what `interop/induced_failures.py --out` wrote, unaltered. SHA-256
`e385cdebf565f7a6ccc06564c63808e6a1a3d1213714ecb6c0e039bd903058e4`. It was scanned for key material, bearer tokens and
authorization headers: no matches. Cost: $0 (a free tier, six calls). The key was held by the session's network proxy, which added it to
each request; the process saw a placeholder.

## What was run, and on what

Six cases through this repository's own Chat Completions client against `https://api.groq.com/openai/v1` with `openai/gpt-oss-120b`,
sending the same `User-Agent` (`STACK-UAI2-Provider/1.0`) that `groq_complete` sends. **This is the route the `groq` provider uses**, the
same address, path, header and reader. (The script calls the shared reader directly, not `groq_complete` itself, so the wrapper's own
argument checks were not exercised.)

| Case | What was done | What the client did | Real answer |
|---|---|---|---|
| baseline | nothing | answered | HTTP 200, `finish_reason stop`, model reported `openai/gpt-oss-120b` |
| model-that-does-not-exist | an unknown model name | refused, `http_error`, with Groq's own message | HTTP 404 `invalid_request_error: The model ... does not exist or you do not have access to it` |
| request-it-cannot-accept | `max_tokens` of -5 | refused, `http_error`, with Groq's own message | HTTP 400 ``invalid_request_error: `max_tokens` has type number -5, but it should be a positive integer`` |
| answer-cut-off | `max_tokens` of 1 | refused, `invalid_response` | HTTP 200, `finish_reason length` |
| answer-larger-than-allowed | the caller allows only 40 bytes back | refused, `response_too_large` | HTTP 200 with a real answer, discarded for its size |
| runs-out-of-time | a time limit of 0.05 seconds | refused, `timeout`, after 50 ms | no answer was waited for |

6 of 6 behaved as the case expects. In none did the client pass, answer wrongly or crash. The first run on Groq needed no change to the
client: Groq answers errors as `{"error": {"message", "type"}}`, a shape the reader already understood.

## What this run does not show

- **No malformed body.** No real service sends one on request. The malformed-body cases remain offline-only.
- **No wrong-key case.** The proxy substitutes the real key, so a wrong one cannot be sent. The 401 and 403 paths are offline-only.
- **No rate-limit case.** None came up.
- Nothing about Cloudflare, Anthropic, OpenAI, Azure OpenAI or the native Gemini route. Nothing about hostile documents.
- The script was changed after the Google run (an optional `--user-agent` flag, off by default). The Google rows were made without it
  and are still what the script does with no flag.
