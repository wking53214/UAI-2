# The first live OpenRouter run, 2026-11-17

`openrouter-live.json` is what `interop/live_providers.py --out` wrote, unaltered. It has seven entries; six are
`executed: false` (no key for those providers in this run) and one is the OpenRouter run. SHA-256
`f21d6f21884c240ee51ce6d90f65c03bed3ec234459d93e9f0f704f5dbec8bb7`. It was scanned for key prefixes, bearer tokens and
authorization headers: no matches. The documents are synthetic. The file holds the SHA-256 of each request and response, not the bytes.

## What was run

Two real calls to `inclusionai/ling-3.2-flash:free` through OpenRouter, one for a paystub that clears the income screen
(512,000 cents) and one that does not (100,000 cents). Cost: $0 (a free model). The key was held by the session's network proxy,
which added it to the request; the process saw only a placeholder.

## What the rows show

| | |
|---|---|
| Calls that answered | 2 of 2, `call: ok`, `finish_reason: stop` |
| Model reported by OpenRouter | `inclusionai/ling-3.2-flash:free` both times (the one asked for) |
| Verdict for the paystub that clears | `pass`, accepted by the strict reader and the decider's policy |
| Verdict for the paystub that does not | `retry`, accepted |
| `live` flag | `true`, set by the runner after a real answer was read |

## What happened before this run, and what it does not show

- **Two earlier calls to `google/gemma-4-31b-it:free` answered HTTP 429.** OpenRouter's own error said the model "is temporarily
  rate-limited upstream" (a pool shared by all free users, served by Google AI Studio). It was not our key and not our code. The
  model was dropped. Of four other free models tried with a one-word request, three answered and one (`gemma-4-26b-a4b-it:free`)
  was rate-limited the same way. Free models come and go; expect to pick another one next time.
- This is two calls, one model, one document type. It shows that this client can read a real OpenRouter answer. It shows nothing
  about OpenAI or Azure OpenAI, whose routes remain untested and refused by default.
- Nothing here shows hostile-document behaviour through OpenRouter; that is what `interop/jury.py` does, and it was not run.
- The model that answers a free id can change between runs. Each record keeps both the model asked for and the one reported.
