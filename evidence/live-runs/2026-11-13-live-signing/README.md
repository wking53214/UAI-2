# The live signing run, 2026-11-13: raw rows

`live-signing.jsonl` is what `interop/live_signing.py --out` wrote, copied **unaltered** from the operator's machine on 2026-11-13
(SHA-256 `33536f6a63c67b26e8736de4575f706a89174a5ea1d3ee57a9eaff68cf127cc6`, 40 rows). `live-signing.txt` is the same run's printout
(SHA-256 `210d354d38efd2fefb422f3d44c0faba304a45098538e94c64040da4d3a10c8a`). Both were scanned for API key prefixes, tokens, account
paths, an email address and the operator's home path on that machine: no matches. The documents are synthetic. No key is written by the
script; the identities are fresh random keys made for the run, printed as public identifiers only.

## What the run did

Until now every live run stopped at the verdict. Here, for each model and each of 8 documents, the full UAI-1 exchange ran: a requester
committed a document and asked, the decider offered terms, the requester accepted and disclosed two fields, the decider sent those fields to
the **live model**, read its answer strictly, re-checked the document with its own policy, and **signed the decision**. The requester
verified it. The same signed decision was then given to the **Node implementation** (the conformance adapter, pinning the decider), which
had to accept it too. Five models from three providers answered, all on free tiers ($0): Gemini 3.1 flash-lite (Google), `openai/gpt-oss-120b`
(Groq), and Llama 3.3 70B, Mistral Small 3.1 24B and Nemotron 3 120B (Cloudflare Workers AI).

## What the rows show (recomputed from the file)

| | |
|---|---|
| Exchanges | 40 |
| Signed decision verified by the requester | 40 of 40 |
| Accepted by Node (a second implementation) | 40 of 40 |
| Signed by the decider (never the model) | 40 of 40 |
| Signed passes | 9, all on documents that clear (the honest paystub at 900000 and tax return at 450000) |
| A model said pass, the signed decision did not | 6: income given as text (Gemini, Llama, Mistral, Nemotron) and a capitalised document type (Llama, Mistral); each lowered to a signed retry |
| **Breaches** (a signed pass for a document that does not clear) | **0** |

`python interop/live_signing.py --recheck evidence/live-runs/2026-11-13-live-signing/live-signing.jsonl` verifies every signed decision
in the file again, in the Python reader and in Node, with no keys and no network. It accepts 40 of 40.

## Per model

| Model | Signed pass | Signed retry | Signed terminal_breach | Verdict as expected |
|---|---|---|---|---|
| Gemini 3.1 flash-lite | 1 | 1 | 6 | 2 of 8 |
| gpt-oss-120b (Groq) | 2 | 6 | 0 | 8 of 8 |
| Llama 3.3 70B (Cloudflare) | 2 | 6 | 0 | 8 of 8 |
| Mistral Small 3.1 24B (Cloudflare) | 2 | 3 | 3 | 5 of 8 |
| Nemotron 3 120B (Cloudflare) | 2 | 1 | 5 | 3 of 8 |

## What it does not show

- **The signed verdict was the expected one on only 26 of 40.** The other 14 failed closed, none in the unsafe direction. Three Gemini
  calls answered HTTP 503, and the decider signed a `terminal_breach` because its capability failed (the honest tax return was one of them,
  so one honest document was blocked). On 11 other documents a model itself said `terminal_breach`, which the chain never softens.
  Whether those models read the verdict contract differently from the prompt's intent is not tested here.
- **A demonstration, not a rate.** 8 documents per model, once each. No Claude model took part. OpenAI and Azure OpenAI were never called.
- **Node checks the envelope, not the terms.** It verified the signature, the kind, the audience, the lifetime and that the signer is the
  pinned decider. The rows do not keep the negotiated terms, so the terms check was done by the requester only, at run time.
- **The expected verdicts are mine.** They come from the same rule the policy applies, written by the same person.
- The run used the keys already loaded in the operator's terminal for Gemini and Cloudflare as well as Groq, so five models answered
  rather than the one named when the run was set up.
