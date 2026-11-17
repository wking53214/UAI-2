# Live jury rerun: plan (not executed)

**Status: a plan for the operator. Nothing in this file has been run. No provider was called and no key was used to write it.**

**Update 2026-11-17:** the plan was run once, with these differences: one round (not two), Gemini left out (its native endpoint refuses the
credential stored in that environment), OpenRouter added as the third provider so the preflight's three-provider minimum held, keys supplied through
a network proxy and not shell variables, and `--cap 0.01` added as a guard. Results: `evidence/live-runs/2026-11-17-jury-current-prompt/`. Everything
below is the plan as written and was not edited.

## Why a rerun

Every recorded jury run (`evidence/live-runs/2026-11-11-raw/`, `2026-11-13-free-panel/`) was made **before** PR #31 changed
`render_prompt` to define when each verdict is used. So no live evidence covers the prompt on `main` today. The offline test
`tests/test_jury_regression.py` shows the *policy* still lowers every recorded wrong pass; it says nothing about how a model
answers the new prompt. Only a new run can.

## What a rerun can and cannot show

- It can show: how the current prompt changes model verdicts on the 22 documents, and that the decider's policy still lowers
  every wrong pass (the same two claims as before).
- It cannot show: anything about models or providers not in the panel, or any property of the receiver's grants and keys.
- A free-tier panel is Google, Groq and Cloudflare only. **No Claude model takes part** unless an Anthropic key with credit is
  used, and that costs money. Do not run it without deciding the cap first.

## Before the run

1. Check out the commit to be tested and record `git rev-parse HEAD` and `python -m pytest -q tests/test_jury.py tests/test_jury_regression.py`.
2. Put keys in your shell environment only. Never in a file, a commit, an issue or a chat. `jury.py` reads them from the
   environment and never writes them; rows hold digests, not the bytes sent or received.
3. Choose the panel with `GEMINI_MODEL`, `GROQ_MODEL`, `CLOUDFLARE_MODEL` (comma lists allowed) and `CLOUDFLARE_ACCOUNT_ID`.
   The 2026-11-13 panel is the starting point (see its README for the model list); models change, so expect the preflight to
   drop some.
4. Leave the preflight on. It makes one call per model and the run refuses to start (exit 4) if fewer than `--min-providers`
   (default 3) different providers answer.

## The run

    python interop/jury.py --rounds 2 --max-calls 400 --out jury-5.jsonl
    python interop/jury.py --summary jury-5.jsonl

- Free tiers: leave `ANTHROPIC_MODEL` unset so `--cap` never applies. If you do add Claude, set `--cap` low (the code reserves the
  worst case before each call) and decide the amount first.
- A juror stops after three invalid-request answers (HTTP 400, 402, 404, 422) in a row, by design.

## Stop and do not publish if

- the run exits 4, or any juror was dropped for reasons you do not understand;
- `BREACH` is above 0 in the summary. That is a final pass on a document that does not clear: report it as a defect before
  anything else;
- a key or token appears anywhere in the rows (scan them first, as the earlier runs were).

## After the run

1. Copy the rows file **unaltered** into a new folder `evidence/live-runs/<date>-<name>/`.
2. Write that folder's `README.md` with the file's SHA-256 (`sha256sum jury-5.jsonl`), the commit tested, the panel, the date and
   the numbers recomputed from the file. `tests/test_evidence_consistency.py` fails if a hash in a README matches no file or a
   file's hash is missing.
3. Add the folder to `FILES` in `tests/test_jury_regression.py`, with its row counts.
4. State what it is: **EXECUTED live by the operator on <date>, one run, models as named**. Do not generalise to other models.
