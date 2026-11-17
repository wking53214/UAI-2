# Failures caused on purpose against a real service: Google's OpenAI-style endpoint, 2026-11-17

`induced-failures.json` is what `interop/induced_failures.py --out` wrote, unaltered. SHA-256
`7c53a824a0903705333f9c17314dab86e8bd9c42cf906b8956319a3c74128823`. It was scanned for key material, bearer tokens and
authorization headers: no matches. Cost: $0 (a free tier, six calls). The key was held by the session's network proxy, which added it to
each request; the process saw a placeholder.

## What was run, and on what

`interop/induced_failures.py` ran six cases through this repository's own Chat Completions client against
`https://generativelanguage.googleapis.com/v1beta/openai` with `gemini-3.1-flash-lite`. **This is Google's OpenAI-compatible endpoint, not
the native Gemini endpoint the `gemini` route uses.** The native endpoint reads an API key only from its own `x-goog-api-key` header, which
the secure credential form could not send (a Bearer key gets HTTP 401 there). So this run says nothing about the `gemini` route itself.

| Case | What was done | What the client did | Real answer |
|---|---|---|---|
| baseline | nothing | answered | HTTP 200, `finish_reason stop`, model reported `gemini-3.1-flash-lite` |
| model-that-does-not-exist | an unknown model name | refused, `http_error`, with Google's own message | HTTP 404 `NOT_FOUND: models/no-such-model-uai-check is not found ...` |
| request-it-cannot-accept | `max_tokens` of -5 | refused, `http_error`, with Google's own message | HTTP 400 `INVALID_ARGUMENT: max_tokens must be positive but was -5` |
| answer-cut-off | `max_tokens` of 1 | refused, `invalid_response` | HTTP 200, `finish_reason length` |
| answer-larger-than-allowed | the caller allows only 40 bytes back | refused, `response_too_large` | HTTP 200 with a real answer, discarded for its size |
| runs-out-of-time | a time limit of 0.05 seconds | refused, `timeout`, after 50 ms | no answer was waited for |

6 of 6 behaved as the case expects. In none did the client pass, answer wrongly or crash.

## What this run found

1. **A defect, fixed in the same change.** Google answers an error as a one-element list, `[{"error": {...}}]`. The client's reader of
   provider error text understood only a bare object, so Google's message was thrown away and the record said only "HTTP 404". The
   reader now unwraps the list (`cns_interop/providers.py`; tests `test_an_error_wrapped_in_a_one_element_list_is_read_the_same_way`,
   which fail without the fix).
2. **Google's model catalog is a moving target.** `gemini-2.5-flash` answers 404 ("no longer available to new users") although it is still
   listed. `gemini-3.8-flash` did not answer within 100 seconds, and `gemma-4-31b-it` answered 503 ("high demand") after 78 seconds. The first
   two attempts of this run used those and recorded those failures; the rows above are from the model that answered in about a second.
   The 60-second limit was met by the client with a clean refusal each time.
3. **My own script was missing a check.** The first version of the script did not call the address check every real client calls, so
   it would have sent a key over plain `http` to another host. An offline test caught it before any key was used that way, and it is fixed.

## What this run does not show

- **No malformed body.** No real service sends one on request. The malformed-body cases remain offline-only.
- **No wrong-key case.** The proxy substitutes the real key, so a wrong one cannot be sent. The 401 and 403 paths are offline-only.
- **No rate-limit case.** None came up.
- Nothing about the native Gemini route, Groq, Cloudflare, Anthropic, OpenAI or Azure OpenAI.
