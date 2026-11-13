# From a model's answer to a final verdict: the reading and re-check contract

This page says, in words, what the reference code does between "a model returned some text" and "the decider has a verdict".
It exists so that a second implementation can be written from it **without reading the Python**, and so the two can be compared
on millions of random cases (`interop/policy_differential.py`). Where the two disagree, either one is wrong or this page is
unclear, and the page gets fixed.

Scope: one capability, `income-screen` v1 ("a document whose `doc_type` is exactly `paystub` or `tax-return`, showing a
`monthly_income_cents` that is a whole number at or above 450000"), whose only evidence kind is `threshold-check`. It does not
cover signing, grants, approvals or ledgers.

## Inputs

1. **The document**: a JSON object (the fields the requester disclosed). **Precondition, already guaranteed upstream by UAI-1's
   value profile** (`UAI-1.md` section 1): only text, booleans, null, integers within plus or minus (2^53 - 1), lists, and
   objects with text keys, nested at most 32 levels; valid Unicode text. No floats, no NaN, no exponent. A document outside the
   profile is never given to this chain, so what it would do is unspecified.
2. **The model's answer**: bytes, meant to be UTF-8 text. Treated as untrusted. It may be anything.

## Output

Either **refused** (nothing else is produced), or a **judgment**: a `verdict` (`pass`, `retry` or `terminal_breach`) and an
`evidence` object. A refusal says nothing about the document.

## Step A: read the answer (strict; nothing is repaired)

The answer is refused unless every one of these holds.

1. The bytes are valid UTF-8 and at most 1 MiB (1,048,576 bytes).
2. The text is **one JSON object and nothing else**, read by the strict rules of UAI-1 (`UAI-1.md` section 2, "Wire"): JSON
   whitespace may surround it; any other text before or after it (a code fence, a sentence, a second object, a byte order mark)
   refuses it. No duplicate key in any object, **compared after unescaping** (so `"a"` and `"a"` are the same key). No
   number with a fraction or an exponent, no `NaN`, `Infinity` or `-Infinity`. No integer outside plus or minus (2^53 - 1). No
   leading zeros, no lone surrogate escape. Anything that is not valid JSON refuses it.
3. The object nests at most **32 levels**, counting the answer object itself as level 1 (the same counting as a message body in
   `UAI-1.md` section 1). Every object and every array is a level, **empty ones included**: an empty object that would be the
   33rd level is refused. Numbers, text, `true`, `false` and `null` are not levels. Deeper is refused.
4. The object has **exactly** the keys `verdict`, `reasons`, `evidence`, `escalate`: no other key, none missing.
5. `verdict` is the text `pass`, `retry` or `terminal_breach`, exactly (no other case, no spaces, no other type).
6. `reasons` is an array of **at most 16** texts, each **at most 500 characters** (Unicode code points, not bytes or UTF-16 units).
   Every element is a text.
7. `escalate` is the JSON value `true` or `false` (not text, not a number, not null).
8. `evidence` is an object **every value of which is an object**, and **every key of which is `threshold-check`** (the empty object
   is fine). Any other key, or a value that is not an object (a number, text, a list, null, true or false), refuses the answer.

## Step B: the decider's re-check of the document

The document **clears** if and only if both hold: `doc_type` is present, is text, and equals exactly `paystub` or `tax-return`
(no case folding, no trimming, no look-alike characters); and `monthly_income_cents` is present, is a JSON **integer** (not a
boolean, not text, not null, not a list, not an object), and is at least 450000.

If the model's verdict is `pass` and the document does **not** clear, the verdict becomes `retry` and the evidence becomes the empty
object. In every other case the recommendation is unchanged. The policy can lower a recommendation. It never raises one.

## Step C: escalation

If `escalate` is `true` and the verdict (after Step B) is **not** `terminal_breach`, the verdict becomes `retry` and the evidence
becomes the empty object. A `terminal_breach` is never softened by `escalate`.

## Step D: the result

The result is the verdict after Steps B and C. Its `evidence` is the model's evidence object **only if the final verdict is
`pass`**; otherwise it is the empty object. (The reasons are carried along, with text added by Steps B and C; they are not
compared by the differential test.)

## Properties that must always hold

- **I1:** a final `pass` implies the document clears.
- **I2:** the final verdict is never better than the verdict Step A accepted (better means `pass` over `retry` over `terminal_breach`).
- **I3:** evidence is present only on a final `pass`, and only with the key `threshold-check`.
- **I4:** whatever the answer, the chain returns a refusal or a judgment. It never crashes.

## The harness protocol (`interop/policy_reference.py` and any other implementation)

One JSON request per line on stdin, one JSON answer per line on stdout, in order:

    {"doc": <the document, any JSON object>, "answer_b64": "<base64 of the answer's bytes>"}
    -> {"refused": true}
    -> {"verdict": "pass" | "retry" | "terminal_breach", "evidence": ["threshold-check"] | []}

`evidence` lists the evidence kinds present, sorted. Base64 is used so any bytes can be carried, including ones that are not valid
UTF-8 (which Step A refuses).
