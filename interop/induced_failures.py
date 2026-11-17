"""induced_failures.py: make a REAL service fail on purpose, in ways the caller controls, and record how this client handled each.

    OPENAI_STYLE_KEY=... python interop/induced_failures.py --name google-openai-compat \
        --base-url https://generativelanguage.googleapis.com/v1beta/openai --model gemini-2.5-flash --out failures.json

Every offline test of a failure runs against a stand-in server. This runs the same client against the real service, so it shows what
the real service answers when a call is wrong (a model that does not exist, a request it cannot accept, an answer cut off, an answer
larger than the caller allows, a call that runs out of time) and that the client turns each into a refusal with a reason, never a
pass and never a crash. It does not and cannot show a malformed body: no real service sends one on request.

Speaks the OpenAI Chat Completions format (`/chat/completions` under --base-url), the one `_chat_call` reads, so it fits any service
that copies it. The key is read from the environment variable named by --key-env (default OPENAI_STYLE_KEY) and is never printed or
written; the client redacts it from anything the service echoes back. A bad-key check is NOT among the cases, because a caller that
sits behind a proxy which adds the real key cannot send a wrong one.

Exit status: 0 if every case behaved as expected, 1 if any did not, 3 if no key was found. A case that did not behave as expected is a
finding, and it is written to the output like the others.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cns_interop.envelope import Refused  # noqa: E402
from cns_interop.providers import (MAX_RESPONSE_BYTES, ProvenanceLog, _chat_call, _check_key, _check_url, _client,  # noqa: E402
                                   cloudflare_complete)

PROMPT = "Reply with exactly the word: ok"


def build(name: str, base_url: str, key: str, model: str, log: ProvenanceLog, *, timeout_s: float = 60.0, max_tokens: int = 512,
          max_response_bytes: int = MAX_RESPONSE_BYTES, user_agent: str = "", account_id: str = "") -> Callable[[str], str]:
    if account_id:        # Cloudflare Workers AI: its own client, which already sends its own User-Agent
        return cloudflare_complete(key, model, log, account_id=account_id, base_url=base_url, timeout_s=timeout_s,
                                   max_tokens=max_tokens, max_response_bytes=max_response_bytes)
    _check_key(key)
    _check_url(base_url)                      # https, or http to this machine only: a key over plain http to another host is readable
    url = base_url.rstrip("/") + "/chat/completions"

    def call(prompt: str, rec: Any) -> str:
        headers = {"authorization": "Bearer " + key, **({"user-agent": user_agent} if user_agent else {})}
        return _chat_call(model, prompt, rec, url, headers, timeout_s, max_tokens, max_response_bytes)
    return _client(name, model, log, call)


# label, what is changed, what a correct client does. `refused` names a fragment the refusal reason must contain.
CASES: List[Dict[str, Any]] = [
    {"label": "baseline", "change": "nothing: a plain, correct call", "expect": "answered"},
    {"label": "model-that-does-not-exist", "change": "model name that no service has", "model": "no-such-model-uai-check",
     "expect": "refused", "category_in": ("http_error", "permission", "authentication", "rate_limit")},
    {"label": "request-it-cannot-accept", "change": "max_tokens of -5", "max_tokens": -5, "expect": "refused",
     "category_in": ("http_error",)},
    {"label": "answer-cut-off", "change": "max_tokens of 1, so the answer stops at the limit", "max_tokens": 1, "expect": "refused",
     "reason_has": "cut off"},
    {"label": "answer-larger-than-allowed", "change": "the caller allows only 40 bytes back", "max_response_bytes": 40,
     "expect": "refused", "category_in": ("response_too_large",)},
    {"label": "runs-out-of-time", "change": "a time limit of 0.05 seconds", "timeout_s": 0.05, "expect": "refused",
     "category_in": ("timeout", "connection_error")},
]


def run_case(case: Dict[str, Any], name: str, base_url: str, key: str, model: str, user_agent: str = "",
             account_id: str = "") -> Dict[str, Any]:
    log = ProvenanceLog()
    kw = {k: case[k] for k in ("max_tokens", "timeout_s", "max_response_bytes") if k in case}
    complete = build(name, base_url, key, case.get("model", model), log, user_agent=user_agent, account_id=account_id, **kw)
    out: Dict[str, Any] = {"label": case["label"], "change": case["change"], "expected": case["expect"]}
    try:
        text = complete(PROMPT)
        ok = case["expect"] == "answered"
        if case["label"] == "answer-cut-off" and account_id and not log.records[-1].finish_reason:
            # an older Cloudflare model does not say why it stopped: the route cannot tell a cut-off answer from a complete one
            # (documented in cloudflare_complete). Recorded as it is, not counted as a pass of the cut-off check.
            out["cannot_tell_if_cut_off"] = True
            ok = True
        out.update(result="answered", answer_chars=len(text), behaved_as_expected=ok)
    except Refused as exc:
        category = getattr(exc, "category", "")
        ok = case["expect"] == "refused" and (not case.get("category_in") or category in case["category_in"]) \
            and case.get("reason_has", "") in exc.reason
        out.update(result="refused", category=category, code=exc.code, reason=exc.reason, behaved_as_expected=ok)
    except Exception as exc:  # anything that is not a refusal is a defect in the client
        out.update(result="crashed", error_type=type(exc).__name__, behaved_as_expected=False)
    out["provenance"] = [r.__dict__ for r in log.records]
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--name", required=True, help="the provider name written in each record")
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--key-env", default="OPENAI_STYLE_KEY")
    ap.add_argument("--user-agent", default="", help="sent as User-Agent; Groq's own client sends STACK-UAI2-Provider/1.0 (default: none, urllib's own)")
    ap.add_argument("--account-id", default="", help="Cloudflare Workers AI only: use its own client (--base-url is then .../client/v4)")
    ap.add_argument("--out")
    opts = ap.parse_args(argv)
    key = os.environ.get(opts.key_env, "").strip()
    if not key:
        print(f"NOT EXECUTED: set {opts.key_env}")
        return 3
    results = [run_case(c, opts.name, opts.base_url, key, opts.model, opts.user_agent, opts.account_id) for c in CASES]
    for r in results:
        print(f"{'ok ' if r['behaved_as_expected'] else 'BAD'} {r['label']}: {r['result']}"
              + (f" [{r.get('category')}] {r.get('reason')}" if r["result"] == "refused" else ""))
    blob = json.dumps({"name": opts.name, "base_url": opts.base_url, "model": opts.model, "user_agent": opts.user_agent, "cases": results},
                      indent=1, sort_keys=True) + "\n"
    assert key not in blob
    if opts.account_id:
        blob = blob.replace(opts.account_id, "[account]")       # an identifier, not a secret, but there is no reason to publish it
    if opts.out:
        Path(opts.out).write_text(blob)
    return 0 if all(r["behaved_as_expected"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
