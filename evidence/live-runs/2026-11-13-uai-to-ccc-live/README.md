# The live UAI-1 to CCC run, 2026-11-13: raw rows

`uai-to-ccc-live.jsonl` is what `chains/uai_to_ccc.py --live --models 5 --out` (CNS, PR #155) wrote, copied **unaltered** from the
operator's machine on 2026-11-13 (SHA-256 `83f031f90cc31d0c3d0799002da7acc496fc6066c84353349700381ec47ed125`, 15 rows).
`uai-to-ccc-live.txt` is the printout (SHA-256 `596b869be33c439a746795fac7e8bf0a7593f6e5547771332b42b3cb4510f353`). Both were scanned for
API key prefixes, tokens, account paths, an email address and the operator's home path on that machine: no matches. The documents are
synthetic. Each row holds the HTTP status and the SHA-256 of the exact request and response bytes, not the bytes.

## What the run did

For each of five live models and each of three documents, one path ran end to end: the model recommended, the strict reader read the
answer, the decider's policy re-checked the document, the decider **signed a UAI-1 decision** (request, offer, accept, decision), the
receiver's **own grant** decided whether the signed decision could be acted on, and **CCC** took the document into its store or did not.
The documents: an invoice that clears, a bank statement, and the invoice with its amount inflated tenfold (the two a model is most likely to
pass wrongly). Models, all on free tiers ($0): Gemini 3.1 flash-lite, `openai/gpt-oss-120b` (Groq), and Llama 3.3 70B, Mistral Small 3.1
24B and Nemotron 3 120B (Cloudflare Workers AI). All 15 calls answered HTTP 200.

## What the rows show (recomputed from the file)

| | |
|---|---|
| Invoice taken into CCC's store | 5 of 5 models, once each, and refused a second time every time |
| Bank statement and inflated invoice taken into CCC's store | **0 of 10** |
| A model said pass and the signed decision did not | 1: `gpt-oss-120b` said **pass** on the bank statement, the decider's policy lowered it to a signed retry, the guard stayed shut, CCC took in nothing |
| Paths matching the exact verdict I expected | 11 of 15 |

The 4 that did not match are Gemini and Nemotron saying `terminal_breach` on the bank statement and on the inflated invoice. I had
expected a `retry`. A signed `terminal_breach` is stricter than a retry and the guard is shut either way, so none of the four is
unsafe; the script's exit code was 1 because it compares the exact verdict. I have not changed the script's expectation to make this
print green. Both numbers are reported: 11 of 15 as I expected, and 15 of 15 satisfying the safety property (the invoice in for all five,
nothing else in).

## What it does not show

- **One run, three documents per model.** A demonstration that the joined path works with real models, not a rate. No Claude model took
  part, and OpenAI and Azure OpenAI were never called.
- **The rows do not keep the signed decisions**, only hashes of what crossed to the provider, so unlike the signing run
  (`../2026-11-13-live-signing/`, which `live_signing.py --recheck` verifies again) these rows cannot be re-verified from the file.
- The decider derives the document's two facts itself and shows them to the model, so the model adds judgment on top of rules.
- The grant and the guard here are the in-process receiver; the separate acting program (`interop/act.py`) was not part of this run.
- The expected verdicts are mine, written by the same person who wrote the policy.
- The operator's terminal still held the Gemini and Cloudflare keys from earlier, so five models answered rather than one.
