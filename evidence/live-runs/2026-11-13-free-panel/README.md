# The free-tier jury run, 2026-11-13: raw rows

`jury-4.jsonl` is what `interop/jury.py --out` wrote, copied **unaltered** from the operator's machine on 2026-11-13. One JSON
object per line, one per model call. SHA-256 `d037a1348492a45fde051e90a6a3b8c3cf4b6f3358c3fb172dca49e445e1f90e`. It was scanned for
API key prefixes, tokens, account paths, an email address and the operator's home path, on that machine and again on this copy:
no matches. The documents are synthetic. The row format is the one described in `../2026-11-11-raw/README.md`.

This is the clean rerun of the three runs of 2026-11-11, which lost most Claude calls to HTTP 400 and a whole Gemini run to HTTP
404. It uses free tiers only (**$0**: no Anthropic key, no card), the prompt that states the rule text in full, and the preflight
gate from PR #15, which checks that every model gives a readable answer before the run starts and stops a model after three
invalid requests in a row. Rounds 0 and 1 over all 22 documents, plus 7 preflight calls (round -1).

## The panel

| Provider | Model | Maker | Rows | Refused |
|---|---|---|---|---|
| Google | `gemini-3.1-flash-lite` | Google | 45 | 9 (HTTP 503, overloaded) |
| Groq | `openai/gpt-oss-120b` | OpenAI | 45 | 0 |
| Groq | `qwen/qwen3.8-27b` | Alibaba | 45 | 2 |
| Groq | `allam-2-7b` | SDAIA | 45 | 10 (unreadable output) |
| Cloudflare | `@cf/meta/llama-3.3-70b-instruct-fp8-fast` | Meta | 45 | 0 |
| Cloudflare | `@cf/mistralai/mistral-small-3.1-24b-instruct` | Mistral | 45 | 0 |
| Cloudflare | `@cf/nvidia/nemotron-3-120b-a12b` | NVIDIA | 45 | 0 |

The panel was chosen after a preflight of 11 candidates. Four were dropped before the real run: `gemini-2.5-flash` (HTTP 404, listed
but not callable with this key), `gemma-4-26b` (its whole answer budget used, a `length` cut-off), and `deepseek-v4-flash` and
`glm-5.3-flash` (HTTP 403 from Cloudflare). GitHub Models was tried first and is not in the panel: GitHub retired it on 2026-07-30
and its endpoints now answer HTTP 200 with the plain text `OK`.

## What the rows show (recomputed from the file, and equal to what the operator's machine printed)

- **315 rows, 294 of them readable answers, 21 refused.** The 21: 9 Gemini HTTP 503 (overloaded); and 12 from Groq (10 from
  `allam-2-7b`, 2 from Qwen): 9 not one strict JSON object (8 malformed, 1 outside the value profile), 1 claiming an evidence kind
  the capability does not produce, 1 whose evidence did not map each kind to its content, and 1 timeout. Every one of the 7
  models ran to the end.
- **0 breaches.** No row has `breach` set, and no final pass was given to a document that does not clear.
- **Models recommended a wrong pass 26 times, and the decider's policy lowered all 26** (`fooled` equals `policy_lowered`):
  `allam-2-7b` 15, Llama 3.3 70B 6, Nemotron 2, Gemini 2, `gpt-oss-120b` 1, Qwen 0, Mistral 0.
- **Hostile documents:** a model said pass on 6 of them, 5 by `allam-2-7b` and 1 by Llama. The policy lowered every one. No other
  model recommended a pass on a hostile document.
- **No model rejected a document that clears** (`model_missed_a_pass` is 0 everywhere), so there was no over-blocking.
- **The models disagreed on 36 of 45 documents**: a varied panel, not seven copies of one opinion.
- **Against the 2026-11-11 runs:** Llama's wrong-pass rate fell from 142 of 400 to 6 of 45, and the `bank-statement` trap from
  about 41% of answers to 14% (and only the 7B model). The prompt change of PR #6, which shows the model the whole rule text,
  is the likely cause; this run was not designed to isolate it. Capitalised document types (`Paystub`) and numbers written as text
  (`"900000"`) still fooled models about 36% and 50% of the time, which is what the policy's exact type check is for.

## What it does not show

- **Claude.** There was no Anthropic credit, so no Claude model took part. The Claude coverage is in the 2026-11-11 rows only.
- A **small sample**: 45 calls per model, two passes over 22 documents. It shows nothing got through here, not a rate.
- **OpenAI and Azure OpenAI** were never called, and GitHub Models no longer exists.
- **No decision was signed from a live answer.** The jury stops at the decider's judgment.
- `as_expected` in the summary is a poor accuracy measure: a model that answers `terminal_breach` where the table expects
  `retry` counts as a miss though it is stricter, not worse.
- Gemini returned HTTP 503 on 9 of 45 calls, so its coverage is thin, and its rate limit was not characterised.

## Reproduce a summary (reads the file only: no network, no keys)

```bash
python -m venv .venv && .venv/bin/pip install -e .
.venv/bin/python interop/jury.py --summary evidence/live-runs/2026-11-13-free-panel/jury-4.jsonl
```
