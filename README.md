# UAI: the Universal AI Interface

A reference design, in two parts, for using AI models in decisions without giving them authority:

1. **UAI-1**, a protocol by which two separate systems request, sign and independently verify a decision.
2. **A provider-neutral model interface** that reaches several AI providers through one request and response shape,
   and feeds a model's answer into a UAI-1 decision as an untrusted recommendation.

**Status in one paragraph.** Version 0.1.0, untagged. Everything here was built and tested by one project. No one
outside it has implemented the protocol, reproduced the results or reviewed the code. "Universal" is the name and
the aim; it is not something this repository has shown. This page says what exists, what the evidence is, what is
unproven, and how to check or break it. It asks for independent evaluation, not endorsement.

| If you want | Read |
|---|---|
| a ten-minute working example | [docs/QUICKSTART.md](docs/QUICKSTART.md) |
| the engineering detail | [README_ENGINEERING.md](README_ENGINEERING.md) |
| the protocol specification | [docs/interop/UAI-1.md](docs/interop/UAI-1.md) |
| what depends on CNS and what does not | [UAI_CNS_INTEGRATION_BOUNDARY.md](UAI_CNS_INTEGRATION_BOUNDARY.md) |
| each claim and its evidence | [CLAIM_EVIDENCE_CROSSWALK.md](CLAIM_EVIDENCE_CROSSWALK.md) |
| to implement it yourself | [docs/interop/implementers/README.md](docs/interop/implementers/README.md) |

## Role within ≡TACK

- **What it is.** A thin way in for model calls plus UAI-1, a signed decision format: a model recommends, the decider's policy decides, and the decision leaves signed so a receiver can verify it.
- **Authority matrix.** Authentication: Ed25519 signatures on envelopes, checked against identities the receiver pins or endorses. Authorization on the receiver's side: the receiver's own grants, a person's signed approval where a grant requires one, and single-use permits (`cns_interop/grants.py`, `cns_interop/decision.py`). Evidence generation and verification: signed envelopes, replay protection and a hash-chained audit record. Transport to model providers (`cns_interop/providers.py`). Enforcement is partial: the receiver programs `interop/act.py` and `interop/node/act.mjs` answer permitted or refused and spend the permit. They are a permit gate, not an executor, so a caller that ignores the answer is not stopped. The content of policy is the decider's. It does not hold a model's signing key: no model is handed a key, ledger, grant or approval.
- **Does not own.** What a policy or a grant says (the decider and the receiver write those), a person's decision to approve, or the gate contract (CNS defines it). The code that checks grants and approvals is here.
- **Depends on.** CNS v4.1.0 (released tag). The provider clients use only the Python standard library.
- **Depended on by.** UNKNOWN (not inspected here).
- **Fail behavior.** The trust decision is the receiver's. Fail-closed by default: `interop/act.py` refuses to start with no receiver policy options (EXECUTED 2026-11-16 and again 2026-11-19), a provider failure becomes a refusal and never a pass, and a stale revocation list refuses (both tested). Three things to know. First, `--decision-only` lets a verified signature open the action with no receiver grant and no audit record; it says so on stderr, and the production profile refuses it (EXECUTED 2026-11-20; see `interop/act.py` and `docs/interop/SECURITY_PROFILES.md`). Second, the two receiver programs take no revocation store. They trust the identities named on `--trust`, and a signed revocation of one of them is not consulted: a `TrustPolicy` built the way `act.py` builds it reported a revoked key as not revoked (EXECUTED 2026-11-16). Revocation works in the library when the caller passes a store. Third, without `--max-clock-skew-ms`, which only the default profile (`UAI_PROFILE` unset) allows, message lifetimes are judged by this host's clock (INSPECTED). `interop/act.py`, `interop/node/act.mjs` and the trust, grant and decision modules are unchanged between the 2026-11-16 checks and commit `51216c2` (VERIFIED 2026-11-19 with `git diff`). Grants, approvals and the PostgreSQL ledgers are covered by the test suite on one host; ledgers across separate machines are not shown (`docs/EVIDENCE.md`). This is a reference design, not a production system.
- **Trust boundary.** A model is an untrusted advisor. API keys come from environment variables; the retired `uai2_gemini`, `uai2_groq` and `uai2_cloudflare` modules are refused because their clients followed redirects that could send a key to another host.

EXECUTED 2026-11-19 at `51216c2` (Python 3.13, Node 22, PostgreSQL 16, one container): 1660 passed, 0 failed, 0 skipped (9 min 36 s); both conformance commands reported 72 of 72; `python interop/demo.py` exited with status 0. At the review of 2026-11-15 (`4e30427`) the suite had 1589 tests, all passing. Not run: live provider calls (no keys here; `interop/live_providers.py` printed `NOT EXECUTED` for each provider) and CI.

## The problem

Two problems, usually mixed together.

**Provider APIs differ.** Each AI provider has its own request format, response format, way of saying an answer was
cut off, and way of failing. Code written against one does not run against another, and a difference in how
truncation or refusal is reported can turn into a silent error.

**A model's answer carries no authority and no checkable origin.** When a system acts on what a model said, a second
system has no way to tell who decided, on what terms, about which document, or whether the message was altered or
replayed. And a model can be talked into the wrong answer by the document it is reading.

A common interface addresses the first problem. It does nothing for the second. This repository treats them as
separate layers.

## The approach

One rule runs through the design: **a model recommends, the decider's policy decides, the decider signs, and the
receiver's own grant permits.** A model is never given a signing key, a ledger, a grant or an approval.

```
  requester                        decider                               provider
  ---------                        -------                               --------
  commit the document
  request  ----------------------> offer terms
  accept (agreed fields only) ---> build the prompt  ------------------> model
                                   strict reader  <--- text (untrusted) ---
                                     exactly four keys, repairs nothing
                                   decider's policy (your code)
                                     may lower a verdict, never has to accept one
  verify  <----------------------- sign the decision (UAI-1)
    signature, terms, document,
    reply binding, not seen before
      |
      v
  the receiver's own grant decides whether anything may be done
```

Every step in this diagram is implemented and tested in this repository. What the tests do and do not show is in
"What has been demonstrated" below.

## UAI-1 and UAI-2

Both live in this one repository.

| | UAI-1 | UAI-2 |
|---|---|---|
| What it is | the signed decision protocol; wire version `uai/1` | the name of this repository, and of the provider-neutral model interface in it (package `uai`, first written as modules named `uai2_*`) |
| What it establishes | an envelope format, identity by public key, trust chosen by the receiver, a request and decision exchange with selective disclosure, replay refusal, stable refusal codes | one typed request and response for several providers; uniform failure categories; a record of each provider call; the path from a model's answer to a signed UAI-1 decision |
| Specification | [docs/interop/UAI-1.md](docs/interop/UAI-1.md) | none written; described in [README_ENGINEERING.md](README_ENGINEERING.md) |
| Implementations | two, Python (`cns_interop/`) and Node (`interop/node/`), separately written by the same project | one, Python (`uai/`, `cns_interop/providers.py`) |
| Conformance suite | 72 cases, covering how a receiver reads and checks a message | none |
| History | developed in the CNS repository, moved here unchanged on 2026-11-11 ([IMPORTED_FROM_CNS.md](IMPORTED_FROM_CNS.md)) | begun here on 2026-11-06 |

UAI-2 is not a second version of the protocol. It builds on UAI-1 and does not replace it. The two have very
different amounts of evidence behind them, and the stronger should not lend credibility to the weaker.

## How it works

The example is [interop/examples/uai_quickstart.py](interop/examples/uai_quickstart.py), about sixty lines.
It screens one document against one rule: monthly income of at least 450000 cents.

1. `uai.connect("groq", "llama-3.3-70b-versatile")` builds a provider client and reads the key from the
   environment. Nothing is sent. (`uai.connect` offers six provider routes.)
2. A requester commits a document with three fields and asks a decider to screen it. They agree terms: the decider
   will see two fields. The name on the document is never disclosed.
3. The decider sends those two fields to the model and asks for a verdict in a fixed format.
4. The answer is read strictly: exactly the keys `verdict`, `reasons`, `evidence`, `escalate`. Prose around the
   answer, an extra key, or a claim of approval is refused, and the decider signs a failure instead.
5. The decider's own `policy` function re-checks the income. A model's "pass" stands only if the policy keeps it.
6. The decider signs the decision. A pass carries the decider's record of the provider call: which model, and the
   SHA-256 of the request sent and the answer read.
7. The requester verifies the signature, the terms, the document and that it has not seen this decision before.
   Presenting the same decision a second time is refused.

With a key set, the program prints something like this (the sample is from the quickstart guide; no live run of this
example is recorded under `evidence/`):

    provider: groq  model: llama-3.3-70b-versatile
    provider call: ok; recommendation accepted (verdict pass)
    decision: pass  allowed: True  signed by: ...
      signed record of the call: request 06fb22e5a13d0ce2...  answer d8365df6e1f910ed...
    presented a second time: refused (terms)

Without a key it prints `NOT EXECUTED` and exits with status 3, so "no key" cannot be mistaken for "it worked".
With `--income 100000` the decision is `retry` even if the model says "pass".

Conceptually, a provider integration is one function, `complete(prompt) -> text`, that holds the key and refuses
anything but one normally finished text answer. Everything else is the same for every provider.

## CNS

CNS (<https://github.com/wking53214/CNS>) is a separate library by the same author. UAI depends on a narrow part of
it, pinned at the tag `v4.1.0`:

- a function that fingerprints content, used under every signature and digest;
- the three verdict words `pass`, `retry`, `terminal_breach`;
- optionally, a way to export a decision made by a group of CNS gates as a signed UAI-1 decision.

CNS does not sign, verify, identify, authorize, prevent replay or call model providers for UAI. That is all code in
this repository. The Node implementation here uses no CNS code and passes the same conformance suite. Whether the
dependency gives UAI a measurable benefit has not been tested. The exact imports, the cost of the dependency and a
comparison a researcher could run are in [UAI_CNS_INTEGRATION_BOUNDARY.md](UAI_CNS_INTEGRATION_BOUNDARY.md).

CNS is also the shared vocabulary of a larger set of repositories by the same author. That larger system is not what
this repository asks anyone to evaluate.

## What has been demonstrated

"Stand-in" means a local server written by this project that speaks a provider's wire format. It checks this code,
not the provider. "Live" means the real service answered. Full records: [docs/EVIDENCE.md](docs/EVIDENCE.md).

| Test or experiment | Environment | Provider and model | Live or stand-in | Expected | Observed | Evidence |
|---|---|---|---|---|---|---|
| Full test suite | one Linux container, Python 3.13, Node 22, PostgreSQL 16, commit `c6c1033`, 2026-11-18 | six front-door routes | stand-in | all pass, none skipped | 1660 passed, 0 failed, 0 skipped | `python -m pytest -q`; CI run #187 concluded success for Python 3.10 to 3.13 (its logs were not read) |
| Conformance suite, both implementations | same | none | not applicable | every case passes | Python 72 of 72, Node 72 of 72 | `contracts/uai1/run_conformance.py` |
| Two-language exchange | same | none (rule-based deciders) | not applicable | each side verifies the other's decision; replay and tampering refused | as expected | `python interop/demo.py` |
| Hostile and edge documents, model panel | operator's machine, 2026-11-11 | Claude Haiku, Sonnet and Opus 5.5; Gemini; `gpt-oss-120b` on Groq; Llama 3.3 70B on Cloudflare | live | no final pass on a document that should not pass | 0 in 3,698 rows. The provider answered on 1,679; most other rows are failed calls, and Claude coverage stops early in the second run | [evidence/live-runs/2026-11-11-raw/](evidence/live-runs/2026-11-11-raw/README.md) |
| Same, free-tier panel | operator's machine, 2026-11-13 | 7 models on Google, Groq and Cloudflare; no Claude model | live | same | 0 in 315 rows; models recommended a wrong pass 26 times and the policy lowered all 26 | [evidence/live-runs/2026-11-13-free-panel/](evidence/live-runs/2026-11-13-free-panel/README.md) |
| Live answer taken to a signed decision | operator's machine, 2026-11-13 | 5 models on Google, Groq and Cloudflare | live | every decision signed by the decider and verified by both implementations; no signed pass on a failing document | 40 of 40 verified, 0 wrong passes. The verdict was the expected one on 26 of 40; the other 14 failed closed. Signatures re-verified from the stored rows on 2026-11-18: 40 of 40 | [evidence/live-runs/2026-11-13-live-signing/](evidence/live-runs/2026-11-13-live-signing/README.md) |
| Model panel under the current prompt | a cloud workspace, commit `0584add`, 2026-11-17 | 7 models on Groq, Cloudflare and OpenRouter | live | no final pass that should not happen | 0 in 161 rows, one round; 8 wrong passes recommended and lowered | [evidence/live-runs/2026-11-17-jury-current-prompt/](evidence/live-runs/2026-11-17-jury-current-prompt/README.md) |
| Single use of a decision under process and database failure | one cloud machine, 2026-11-17 | none | not applicable | one effect per message; no loss of a commit anyone was told about | three 25-minute runs, zero findings | [evidence/live-runs/2026-11-17-soak-mid-commit-3x25min/](evidence/live-runs/2026-11-17-soak-mid-commit-3x25min/README.md) |

How to read this table. The live runs are small, were run by the project on synthetic documents, and are snapshots,
not rates. The expected outcomes were written by the same person who wrote the policy. Only the first three rows and
the signature re-check were executed for this revision; the rest are the project's committed records.

Provider routes, by whether the client for each has been run against the real service:

| Route | Run against the real service |
|---|---|
| Anthropic, Google Gemini, Groq, Cloudflare Workers AI | yes |
| OpenAI, Azure OpenAI (also reachable under the older name `copilot`) | **no**; tested against stand-ins only |

## Relation to existing work

The building blocks are standard: Ed25519 signatures, a canonical encoding hashed before signing, a replay ledger,
salted hash commitments for selective disclosure, default-deny grants. Nothing here is a new cryptographic or
protocol primitive.

What this repository has **not** done is compare the design with existing standards and protocols that cover
similar ground, such as JOSE and COSE for signed messages, W3C Verifiable Credentials, capability tokens, and agent
protocols such as MCP and A2A. A reader who knows those will reasonably ask what this adds. That comparison is an
open item, and an honest answer may be "a particular combination, and a rule about where a model's output may go".

## Known limitations

- **No independent implementation, reproduction or review.** This is the largest gap.
- **One author, one AI model family.** See "Project status" below. Two implementations that agree are weaker
  evidence when both come from the same source.
- **The conformance suite is narrow.** It covers how a receiver reads and checks one message. It does not cover the
  exchange, disclosure, grants, or ledger behaviour under failure.
- **The provider interface is narrow and unspecified.** One user message, no system instruction, a fixed output
  limit, text only. No streaming, tools or conversation. There is no written specification and no second
  implementation of it.
- **Two of six routes have never been run live, and the front door never has.** The live runs called the provider
  clients directly. The single entry point, the typed interface and the signed record of a provider call have been
  exercised only against stand-ins.
- **One machine.** Every test and long run, including the database failure tests, ran on a single host.
- **The record of a provider call is the decider's own statement.** No provider signs its answers.
- **A policy checks only what it is shown.** A forged document with plausible values clears.
- **Signed, not encrypted.** Confidentiality has to come from the channel.
- **Key custody is a draft.** The procedure for a stolen key has not been exercised by people.
- **Not a production system.** No release has been tagged.

Each of these is expanded, with the reason it matters, in [README_ENGINEERING.md](README_ENGINEERING.md) section J
and [docs/EVIDENCE.md](docs/EVIDENCE.md) section 6.

## Independent technical evaluation

The project cannot test its own independence. That is the reason for this section.

**The main question.** Can a team that has not read this code implement UAI-1 from the published documents, run
the conformance suite, and reproduce the result?

To hand a team the documents and nothing else:

    python contracts/uai1/build_kit.py --out uai1-kit.zip

The kit holds the specification, schema, error registry, vectors, the suite and its runner, and no implementation
source. Then:

    python contracts/uai1/run_conformance.py --cmd "<your adapter command>"

**Questions worth answering.**

1. Can an independent team implement the published protocol, and where does the text force a guess?
2. Can it reproduce the conformance results in this page?
3. Do independently written implementations agree with each other on inputs the suite does not contain?
4. Where does it fail? Which assumptions and edge cases are unaddressed?
5. Does the rule "a model recommends, a policy decides" hold against adversarial model output designed by someone
   else?
6. Is the provider interface a useful common denominator, or too narrow to matter?
7. Does the CNS dependency add measurable value over a version without it, and what does it cost?

**What would count as a meaningful result.** Any of these, positive or negative: a third implementation and its
list of disagreements; a case both shipped implementations get wrong; a sentence in the specification that two
careful readers implement differently; an input on which the two shipped implementations disagree about accepting;
a model answer that produces a signed pass the policy should have stopped.

**What would count against the central claim.** If a competent team cannot build a conforming receiver from the kit
without reading the source, the specification is not independently implementable as written. If two conforming
receivers disagree on accept or refuse for ordinary inputs, the suite does not establish interoperability.

**The strongest objections, stated by the project itself.** It may add nothing that existing signed-message and
agent protocols do not already provide. All of its evidence is self-produced, by one author and one AI model family.
Its conformance suite tests a small part of the protocol. Its provider interface may be too narrow to be useful. A
reviewer who confirms any of these has produced a useful result.

**Easiest to reproduce:** the test suite, the conformance runs, the two-language demo. **Hardest:** the live model
runs (providers and models change), and anything across several machines (never done).

**Reporting.** Open an issue on this repository. For conformance disagreements there is a template:
[docs/interop/implementers/DISAGREEMENT_REPORT.md](docs/interop/implementers/DISAGREEMENT_REPORT.md). A
disagreement is a bug in the new implementation, a bug in the reference, or a sentence that needs fixing. All three
are useful.

## Reproduce it

Prerequisites: Python 3.10 or later, Node 22, PostgreSQL server binaries (the ledger tests start their own
throwaway clusters), git and network access to GitHub (CNS is installed from there).

    git clone https://github.com/wking53214/UAI-2.git
    cd UAI-2
    python -m pip install -e ".[dev]"
    python -m pytest -q
    python contracts/uai1/run_conformance.py --cmd "python interop/conformance/reference_adapter.py"
    python contracts/uai1/run_conformance.py --cmd "node interop/node/conformance_adapter.mjs"
    python interop/demo.py

Expected: every test passes and none is skipped (a skipped test fails the run by design); each conformance run
reports 72 of 72; the demo exits with status 0. None of this needs a provider key. There is no tagged release, so
record the commit you ran.

Two error messages in the code (`cns_interop/ledger_postgres.py` and `cns_interop/crypto_backend.py`) print an install
command for the optional PostgreSQL and cryptography extras. The command installs this repository from its GitHub address, not
from a bare package name, because an unrelated public package called `cns` (another author) is on the public package index.
From a clone, `pip install -e ".[postgres]"` or `pip install -e ".[crypto]"` does the same; the `.[dev]` install above
already includes both.

Live provider runs need your own keys and may cost money: `python interop/live_providers.py`. It prints
`NOT EXECUTED` for each provider without a key.

Where things are:

| What | Where |
|---|---|
| Provider-neutral interface | `uai/` |
| Provider clients (the only module that contacts a provider) | `cns_interop/providers.py` |
| UAI-1, Python | `cns_interop/` |
| UAI-1, Node | `interop/node/` |
| Specification | `docs/interop/UAI-1.md` |
| Schema, error registry, conformance suite, runner, kit builder | `contracts/uai1/` |
| Tests | `cns_interop/tests/`, `tests/` |
| Recorded runs | `evidence/` |
| Runners and instruments (demo, jury, soak, fuzzers) | `interop/` |

The Python package is named `cns_interop` for historical reasons. It is UAI-1's implementation and is not part of
CNS.

## Older names

`uai2_bridge` and `uai2_factory` still import and forward to `uai`. `uai2_gemini`, `uai2_groq` and `uai2_cloudflare`
are retired and say so when imported: their clients followed redirects, which could send an API key to another host.
GitHub retired GitHub Models on 2026-07-30, so the old name `copilot` now reaches the Azure OpenAI route.

## Project status

- **Licence:** Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)).
- **Version:** 0.1.0, not tagged. The wire format has its own version, `uai/1`. Changes: [CHANGELOG.md](CHANGELOG.md).
  What a first release still needs: [docs/RELEASE_READINESS.md](docs/RELEASE_READINESS.md).
- **Maturity:** a reference design. Not a production system, not audited, not certified, not formally verified.
- **Affiliation:** none. No institution has reviewed or endorsed this work.
- **How it was built.** All code in this repository was written by Claude models (Anthropic) under the direction of
  one author, who acted as architect, has no programming background, and did not verify the code by reading it.
  The commit history records this: at `c6c1033`, 83 of 138 commits carry an AI co-author line. Verification rests on
  the automated tests and the recorded evidence. The author reports also reviewing the work with a second AI model
  from a different company (ChatGPT); no record of that review is in this repository.
- **Earlier internal reviews.** Some older documents here mention an "external assessment", an "independent
  review", and Go and Rust implementations written from the documents alone. These were AI sessions run by the
  author. Their source and transcripts are not in this repository, so they cannot be reproduced from it. The scored
  assessments under `docs/interop/` are internal working notes with self-assigned scores.
- **Why this matters for a reviewer.** Tests, a second implementation and reviews that share one origin can share
  one blind spot. An implementation by people working only from the specification is the check this project cannot
  make for itself.
