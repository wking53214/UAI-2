# Use it in 10 minutes

This gets one AI model to make a recommendation, has your own rule decide, and produces a signed decision that
anyone you trust can check. It works the same on every supported provider.

## What you need

- Python 3.10 or later.
- An API key for one provider: Anthropic, Google Gemini, OpenAI, Azure OpenAI, Groq or Cloudflare Workers AI. (GitHub Models
  was retired by GitHub on 2026-07-30; the old name `copilot` now means Azure OpenAI.)

## 1. Install

    git clone https://github.com/wking53214/UAI-2.git
    cd UAI-2
    python -m pip install -e .

This installs CNS v3.0.0 (the gate contract) with it. Nothing else is needed: the provider clients use only the
Python standard library.

## 2. Set one environment variable: your key

| Provider | Name to pass | Variable to set |
|---|---|---|
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` (or `UAI_ANTHROPIC_API_KEY`) |
| Google Gemini | `gemini` | `GEMINI_API_KEY` |
| OpenAI | `openai` | `OPENAI_API_KEY` |
| Groq | `groq` | `GROQ_API_KEY` |
| Cloudflare Workers AI | `cloudflare` | `CLOUDFLARE_API_TOKEN`, and your `CLOUDFLARE_ACCOUNT_ID` |
| Azure OpenAI | `copilot-azure` (and `copilot`, its old name: GitHub retired GitHub Models on 2026-07-30) | `AZURE_OPENAI_API_KEY`, and your `AZURE_OPENAI_ENDPOINT` |

For example:

    export GROQ_API_KEY=...

Two providers need a second, non-secret value because their address includes your own account or resource.

## 3. Run the example

    python interop/examples/uai_quickstart.py groq llama-3.3-70b-versatile

Use your provider's name and one of its model names. You should see something like:

    provider: groq  model: llama-3.3-70b-versatile
    provider call: ok; recommendation accepted (verdict pass)
    decision: pass  allowed: True  signed by: ...
      signed record of the call: request 06fb22e5a13d0ce2...  answer d8365df6e1f910ed...
    presented a second time: refused (terms)

Without a key it prints `NOT EXECUTED` and exits with status 3, so a script cannot mistake "no key" for "it worked".

Try `--income 100000`. The example's rule requires 450000, so even if the model says "pass" the decision is `retry`.
That is the point of the design.

## What just happened

1. **The model recommended.** It was shown two fields of a document and asked for a verdict in a strict format.
   Anything outside that format is refused: extra fields, prose around the answer, a claim of approval or authority.
2. **Your rule decided.** The `policy` function in the example re-checked the facts. A model's "pass" stands only if
   your rule keeps it.
3. **The decider signed.** The decision names the document, the agreed terms and the verdict, and is signed with the
   decider's key. A pass also carries a record of the provider call.
4. **The requester verified.** It checked the signature, the terms and the document, and refused the same decision
   when it was presented again.

## Use it in your own code

    import uai

    model = uai.connect("groq", "llama-3.3-70b-versatile")   # reads GROQ_API_KEY; sends nothing yet
    judge = model.judge(policy)                               # hand this to a cns_interop.session.Decider

`interop/examples/uai_quickstart.py` is about sixty lines and shows the rest: the capability, the policy, the decider,
the requester. Copy it and change the capability and the policy to yours.

If you only want text from a model, with no decision:

    typed = model.model_provider()
    answer = typed.generate(uai.ModelRequest(model=model.model, system_instruction="",
                                             user_messages=("Say hello.",), max_output_tokens=512))
    print(answer.content, answer.completion_status)

To choose the provider from the environment instead of in code, set `UAI_PROVIDER` and `UAI_MODEL` and call
`uai.from_env()`.

## Things that are deliberate

- **You always name the provider.** It is never guessed from whichever key happens to be set, because that would let
  a forgotten key decide where your documents are sent.
- **Redirects are refused and plain http is refused** (except to your own machine), so your key cannot be sent
  somewhere you did not name.
- **The key is never written down.** It is not in any record, log line, error message or signed message.
- **The model never holds authority.** It is never given a signing key, a grant or an approval.
- **The signed record of the provider call is the decider's own statement.** No provider signs its answers, so the
  record shows what the decider says it sent and received. It is not proof against a decider that lies.
- **Cloudflare Workers AI does not report why an answer ended.** A cut-off answer from it cannot be detected, and the
  typed interface reports its completion status as unknown.

## Checking a decision in another language

The Node implementation in `interop/node/` shares no code with the Python one and verifies the same decisions. The
specification is `docs/interop/UAI-1.md`, and `contracts/uai1/` holds a conformance suite you can run against your
own implementation in any language:

    python contracts/uai1/run_conformance.py --cmd "your-adapter-command"
