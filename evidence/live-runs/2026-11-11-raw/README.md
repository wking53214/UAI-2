# Raw rows of the three live jury runs (2026-11-11 evening, local time of the operator's machine)

These are the files that `interop/jury.py --out` wrote during the live runs, copied **unaltered** from the operator's
machine on 2026-11-13. One JSON object per line, one line per model call. Earlier, only printed summaries of two of these
runs were kept (`../2026-11-12-jury-findings.md`); the rows were thought lost. This folder replaces that gap, and it shows
that the earlier summaries were incomplete for run 2 and silent about run 3. Read the sections below before quoting any number.

| File | Rows | SHA-256 |
|---|---|---|
| `jury.jsonl` (run 1) | 633 | `1e1458bfa832d2d99f3363648cb60e3b4fe6ff074618ea5b4b8495cbbb6410b8` |
| `jury-2.jsonl` (run 2) | 2,665 | `03d3d358b97b78d3c916a7bde3e3d8dca93ce10bbeeeb2de12e5df89f78b1b7e` |
| `jury-3.jsonl` (run 3) | 400 | `95f8e7cb443ffae5d0a71bed9babbc84da4f23014a86a20a5dd0743f14c81fb2` |

Each row has 21 fields: `breach`, `cost_usd`, `cum_usd`, `expect`, `finish_reason`, `http_status`, `input_tokens`, `juror`,
`kind`, `latency_s`, `matches_expect`, `model_verdict`, `name`, `output_tokens`, `policy_lowered`, `provider`, `reasons`,
`request_sha256`, `response_sha256`, `round`, `verdict`. There are no timestamps. The documents are synthetic (a paystub or tax
return with an income figure, some edge and hostile variants).

Before they were added, the files were scanned for API key prefixes (`sk-ant-`, `AIza`, `gsk_`, `Bearer `) and for account paths,
an email address and the operator's home path. There were no matches, on the operator's machine and again on this copy.

## What each run was

**Run 1** (`jury.jsonl`): 633 rows, $1.41 of Anthropic spend, rounds 0 to 7, stopped by hand. Haiku, Sonnet and Opus 5.5,
Llama 3.3 70B on Cloudflare, gpt-oss-120b on Groq, and `gemini-3.8-flash`. The provider answered (HTTP 200) on 605 rows. Gemini
returned HTTP 503 on all 6 of its rows, and Groq rate-limited 22 rows (HTTP 429). This matches the summary in
`../2026-11-12-jury-findings.md` exactly.

**Run 2** (`jury-2.jsonl`): 2,665 rows, $1.86 of Anthropic spend, rounds 0 to 29. The same panel with `gemini-3.5-flash`. The
earlier summary was taken early ("157 calls so far, $0.30") and is superseded by this file. The provider answered on 1,074 rows:
- Cloudflare answered all 400 of its rows and Groq 182 of 239 (57 rate-limited). Gemini answered 26 of 46 (20 rate-limited).
- **Anthropic answered 466 of 1,980 rows and returned HTTP 400 on 1,513.** The first HTTP 400 is at file row 919, in round 8, at a
  cumulative spend of $1.8162, immediately after a Sonnet call that answered. From there on nearly every Claude call failed, at
  a cost of $0.00 each, with two isolated successes. So **Claude coverage in this run ends at round 8 of 30.**
- **The cause of the HTTP 400s is not recorded.** The client keeps no error body. A credit balance reaching zero or a spend limit
  would produce a sudden, permanent switch like this one, and the isolated successes were small calls. That is a guess; nothing
  in the rows confirms it. The operator's Anthropic account (billing, limits, usage for that evening) would settle it.
- The still-high wrong-pass counts on the edge documents (an unaccepted document type, a capitalised type) show this run
  predates the PR #6 fix, after which the model is shown the full rule text.

**Run 3** (`jury-3.jsonl`): 400 rows, $0.00, a failed run kept for the record. The only juror was `gemini-3-flash`, which
returned HTTP 404 on 399 rows (the model name did not exist) and a timeout on one. It produced no answers.

## What the rows do show

- **0 breaches in all 3,698 rows**: no row has `breach` set, and `interop/jury.py --summary` reports 0 for each file. A breach
  is a final pass on a document that does not clear.
- **The provider answered on 1,679 rows** (605 + 1,074 + 0). The rest are failures of the call (HTTP 400, 404, 429, 503 or a
  timeout) or answers the strict reader refused. A failed call is not a safe answer; it is no answer.
- Where models were fooled (said pass on a document that should not pass), the decider's policy lowered every one. Across both
  runs, only Llama and gpt-oss recommended a pass on a hostile document; no Claude model did.

## What they do not show

- Anything about Claude after round 8 of run 2, or about Gemini beyond 26 answers in run 2.
- OpenAI, GitHub Models and Azure OpenAI (never called). No decision was signed from a live answer: the jury stops at the
  decider's judgment.
- Why the Anthropic calls began to fail (see above), or how the system behaves with the PR #6 fix, which a new run would measure.

## Reproduce a summary (reads files only, no network, no keys)

```bash
python -m venv .venv && .venv/bin/pip install -e .
.venv/bin/python interop/jury.py --summary evidence/live-runs/2026-11-11-raw/jury-2.jsonl
```
