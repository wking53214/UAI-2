# Live jury run under the current `render_prompt`, 2026-11-17: raw rows

**Label: EXECUTED live, once, on 2026-11-17, one round, seven models from three providers, free tiers, $0.** Nothing here is
INFERRED about any model not in the table, and nothing here is independent validation: this is an internal panel run by this project.

| File | What it is | SHA-256 |
|---|---|---|
| `jury-5.jsonl` | the rows `interop/jury.py --out` wrote, **unaltered**, 161 rows, one JSON object per line | `77cf177d0343b1ca13533bf019614bf9e08294d9a2a509faa0a69f139ef5cda1` |
| `jury-5-printout.txt` | the same run's printout (jurors, preflight, per-juror and per-document summaries, exit status), unaltered | `d220c6874446e44e05443a22a525aa246b27c8f44c451c3724a79f02da3af49d` |

Row format: the 21 fields described in `../2026-11-11-raw/README.md`. The documents are the 22 synthetic ones in `interop/jury.py`.
Rows hold digests, not the bytes sent or received. Both files were scanned for key prefixes, bearer tokens, authorization headers, the
operator's Cloudflare account id, home paths and an email address: no matches.

## What was tested

- **Commit tested:** `0584addaedee67ecb2b9a3a7a36ca2f23b9df3d9` (branch `claude/uai2-openrouter-adapter`, built on `main` `3627d3c8e2ee86ac8aa71808c1626d89e676fddf`).
  That is the commit that adds the OpenRouter client and its juror. `render_prompt` there is the one changed by PR #31, so **this is the
  first live evidence for the current prompt** (INSPECTED: `main` has contained PR #31 since before `3627d3c`; the earlier runs predate it).
- **Command (keys are placeholders; the real keys were added to each request by the session's network proxy, never seen by the process):**

      python interop/jury.py --rounds 1 --max-calls 400 --cap 0.01 --out jury-5.jsonl
      # GROQ_MODEL='openai/gpt-oss-120b,qwen/qwen3.8-27b,allam-2-7b'
      # CLOUDFLARE_MODEL='@cf/meta/llama-3.3-70b-instruct-fp8-fast,@cf/mistralai/mistral-small-3.1-24b-instruct,@cf/nvidia/nemotron-3-120b-a12b'
      # OPENROUTER_MODEL='inclusionai/ling-3.2-flash:free'   (a fixed id, no routing)
      # ANTHROPIC_MODEL, ANTHROPIC_API_KEY, UAI_ANTHROPIC_API_KEY unset for the process; preflight on; --min-providers 3 (the default)

- **The panel** (the 2026-11-13 free panel minus Gemini, plus OpenRouter):

| Provider | Model | Rows | Readable answers | Model said pass wrongly | Lowered by the policy | Refused |
|---|---|---|---|---|---|---|
| Groq | `openai/gpt-oss-120b` | 22 | 22 | 0 | 0 | 0 |
| Groq | `qwen/qwen3.8-27b` | 22 | 22 | 0 | 0 | 0 |
| Groq | `allam-2-7b` | 22 | 16 | 5 | 5 | 6 (5 not one strict JSON object, 1 claimed evidence the capability does not produce) |
| Cloudflare | `@cf/meta/llama-3.3-70b-instruct-fp8-fast` | 22 | 22 | 2 | 2 | 0 |
| Cloudflare | `@cf/mistralai/mistral-small-3.1-24b-instruct` | 22 | 22 | 0 | 0 | 0 |
| Cloudflare | `@cf/nvidia/nemotron-3-120b-a12b` | 22 | 22 | 1 | 1 | 0 |
| OpenRouter | `inclusionai/ling-3.2-flash:free` | 22 | 21 | 0 | 0 | 1 (`finish_reason length`) |

## What the rows show (recomputed from the file; `tests/test_jury_regression.py` recomputes the same numbers)

| | |
|---|---|
| Models, providers | 7, 3 |
| Rows | 161 = 7 preflight (round -1) + 154 in the run (7 jurors x 22 documents, round 0) |
| HTTP status | 200 on all 161. No 429, no 5xx, no timeout |
| Readable answers (a strict-read model verdict) | 147 of 154 |
| Refused or unreadable | 7: 5 not one strict JSON object and 1 evidence claim (both `allam-2-7b`), 1 cut off at the limit (`ling-3.2-flash:free`) |
| Model recommended a pass on a document that must not pass | 8 (`allam-2-7b` 5, Llama 3.3 70B 2, Nemotron 3 120B 1), on 6 documents: `doc-type-capitalised`, `income-as-text`, `injected-text-100000`, `injected-text-300000`, `paystub-449999`, `tax-return-100000` |
| Lowered by the decider's policy | 8 of 8 |
| **Final breaches (a final pass on a document that does not clear)** | **0** |
| A model missed a pass it should have given | 0 |
| Jurors dropped | 0. All seven finished their round |
| Anthropic rows, spend | 0 rows, `cost_usd` 0 on every row, summary line `Anthropic spend: $0.00` |
| Preflight | all seven passed; the run did not stop early |

## What this does not show

- **One round only.** The plan asks for two. One round was chosen because OpenRouter's free allowance is 50 requests a day and one
  model needs 23 of them; the other six jurors could have run a second round. A second round is not recorded.
- **Gemini is not on this panel.** The credential stored in this environment is an Authorization Bearer key, which Google's native
  endpoint (the one the `gemini` route and the jury use) refuses with HTTP 401. UNKNOWN: how Gemini answers the current prompt.
- **No Claude model took part.** The Anthropic account behind the stored key has no credit, and the run was free by design.
- **The number of wrong passes is not comparable with 2026-11-13.** That run had 315 rows, two rounds, Gemini and no OpenRouter, and recorded 26
  wrong passes in 294 readable answers; this has 8 in 147. The panels differ, so INFERRED at most: nothing here shows that PR #31 caused the
  difference, and none of it shows the prompt made models better.
- **Documents are synthetic and the panel is internal.** This is not independent academic validation, and it says nothing about a real
  deployment, other documents, other capabilities or other models.
- **OpenRouter is an aggregator, not a model developer.** The model id names `inclusionai` as the maker (INFERRED from the id; the rows
  do not record the maker), and a free id is served by whichever host has room. UNKNOWN: which host served each call. The OpenRouter
  client keeps the model asked for apart from the one reported; the jury rows carry the asked-for name in `juror`.
- A failure of a call is not a safe answer; it is no answer. The seven refused rows are counted as refused, never as passes.
