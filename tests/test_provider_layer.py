"""The one provider layer (cns_interop.providers), for what this repository added to it. EVERY SERVER HERE IS A STUB.

cns_interop/tests/test_providers.py holds the layer's original tests for Anthropic, Gemini, OpenAI and Copilot and is
unchanged. This file holds Groq and Cloudflare Workers AI to the same behaviour, and covers what changed for all of
them: the request digest is over the bytes sent, plain http leaves this machine for nowhere, failures carry a category,
token counts and the provider's id are recorded, and a cut-off answer is returned only to a caller that asked for text.
Nothing here shows that a real provider behaves this way; that needs a key (interop/live_providers.py).
"""

from __future__ import annotations

import hashlib
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cns_interop" / "tests"))
from test_adapter import honest_model  # type: ignore[import-not-found]  # noqa: E402
from test_providers import anthropic_ok, exchange, gemini_ok, openai_ok  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.envelope import Refused  # noqa: E402
from cns_interop.providers import (ProvenanceLog, anthropic_complete, cloudflare_complete, copilot_complete,  # noqa: E402
                                   gemini_complete, groq_complete, openai_complete)

KEY = "sk-test-SECRET-0123456789abcdef"
ALL = ["anthropic", "gemini", "openai", "copilot", "copilot-azure", "groq", "cloudflare"]
NEW = ["groq", "cloudflare"]
LABEL = {"anthropic": "anthropic", "gemini": "google", "openai": "openai", "copilot": "copilot-github-models",
         "copilot-azure": "copilot-azure-openai", "groq": "groq", "cloudflare": "cloudflare-workers-ai"}
KEY_HEADER = {"anthropic": "x-api-key", "gemini": "x-goog-api-key", "copilot-azure": "api-key"}


class Raw:
    """A tiny HTTP server that keeps the exact bytes of every request. `respond(path, headers, raw) -> (status, headers, bytes)`."""

    def __init__(self, respond):
        outer = self
        self.requests = []

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("content-length", 0)))
                outer.requests.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "raw": raw})
                status, headers, data = respond(self.path, dict(self.headers), raw)
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                try:
                    self.wfile.write(data)
                except OSError:
                    pass

            do_GET = do_POST

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def cloudflare_ok(text):
    return {"success": True, "errors": [], "result": {"response": text, "usage": {"prompt_tokens": 7, "completion_tokens": 3}}}


def envelope(provider, text):
    if provider == "anthropic":
        return anthropic_ok(text)
    if provider == "gemini":
        return {**gemini_ok(text), "responseId": "resp-1", "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 3}}
    if provider == "cloudflare":
        return cloudflare_ok(text)
    return {**openai_ok(text), "usage": {"prompt_tokens": 7, "completion_tokens": 3}}


def prompt_of(provider, body):
    if provider == "gemini":
        return body["contents"][0]["parts"][0]["text"]
    if provider == "cloudflare":
        return body["prompt"]
    return body["messages"][0]["content"]


def make(provider, url, log, **kw):
    if provider == "copilot":
        return copilot_complete(KEY, "model-x", log, base_url=url, **kw)
    if provider == "copilot-azure":
        return copilot_complete(KEY, "model-x", log, route="azure-openai", base_url=url, **kw)
    if provider == "cloudflare":
        return cloudflare_complete(KEY, "@cf/meta/model-x", log, account_id="acct123", base_url=url, **kw)
    fn = {"anthropic": anthropic_complete, "gemini": gemini_complete, "openai": openai_complete, "groq": groq_complete}[provider]
    return fn(KEY, "model-x", log, base_url=url, **kw)


J = {"content-type": "application/json"}


def serving(provider, reply, extra_headers=None):
    def respond(path, headers, raw):
        text = reply(prompt_of(provider, json.loads(raw)))
        return 200, {**J, **(extra_headers or {})}, json.dumps(envelope(provider, text)).encode()
    return Raw(respond)


def plain(prompt):
    return "ok"


def answering(status, data, headers=None):
    return Raw(lambda p, h, raw: (status, headers or J, data))


# ------------------------------------------------------------------------------------- Groq and Cloudflare, end to end
@pytest.mark.parametrize("provider", NEW)
def test_an_honest_answer_becomes_a_verified_decision_and_the_call_is_recorded(provider):
    stub, log = serving(provider, honest_model, {"cf-ray": "ray-123"}), ProvenanceLog()
    try:
        got = exchange(make(provider, stub.url, log), log)
        assert got.allowed and got.verdict == "pass"
        (rec,) = log.records
        assert rec.provider == LABEL[provider] and rec.call == "ok" and rec.outcome == "accepted"
        assert rec.model_requested.endswith("model-x") and rec.http_status == 200
        assert len(rec.request_sha256) == 64 and len(rec.response_sha256) == 64
        assert (rec.input_tokens, rec.output_tokens) == (7, 3)
        assert rec.finish_reason == ("stop" if provider == "groq" else "")     # Workers AI never says why it stopped
        assert rec.request_id == ("c1" if provider == "groq" else "ray-123")
        low = exchange(make(provider, stub.url, log), log, income=100_000)
        assert low.verdict == "retry" and not low.allowed                      # the policy re-checked; the model's pass did not stand
    finally:
        stub.close()


def test_groq_and_cloudflare_send_what_each_api_expects_and_nothing_else():
    for provider in NEW:
        stub = serving(provider, plain)
        try:
            make(provider, stub.url, ProvenanceLog(), max_tokens=512)("the prompt")
            sent = stub.requests[0]
            body = json.loads(sent["raw"])
            assert sent["headers"]["authorization"] == "Bearer " + KEY and sent["headers"]["user-agent"] == "STACK-UAI2-Provider/1.0"
            if provider == "groq":
                assert sent["path"] == "/chat/completions"
                assert body == {"model": "model-x", "messages": [{"role": "user", "content": "the prompt"}], "max_tokens": 512}
            else:
                assert sent["path"] == "/accounts/acct123/ai/run/@cf/meta/model-x"
                assert body == {"prompt": "the prompt", "max_tokens": 512}
        finally:
            stub.close()


FAILURES = {
    "http-500": (500, b'{"error":"boom"}', "http_error"),
    "unauthorized": (401, b'{"error":"bad key"}', "authentication"),
    "forbidden": (403, b'{"error":"no"}', "permission"),
    "rate-limited": (429, b'{"error":"slow down"}', "rate_limit"),
    "not-json": (200, b"<html>gateway</html>", "invalid_response"),
    "json-list": (200, b"[1,2,3]", "invalid_response"),
    "huge": (200, b'{"x":"' + b"a" * 400_000 + b'"}', "response_too_large"),
}


@pytest.mark.parametrize("provider", ALL)
@pytest.mark.parametrize("mode", sorted(FAILURES))
def test_every_failure_is_a_refusal_with_a_category_a_status_and_no_key(provider, mode):
    status, data, category = FAILURES[mode]
    stub, log = answering(status, data), ProvenanceLog()
    try:
        with pytest.raises(Refused) as e:
            make(provider, stub.url, log)("hi")
        assert e.value.code == "provider" and e.value.category == category
        (rec,) = log.records
        assert rec.http_status == status and rec.outcome == "rejected" and rec.call != "ok"
        assert KEY not in str(e.value) and KEY not in json.dumps(rec.__dict__)
    finally:
        stub.close()


SHAPES = {
    "groq": {"no choices": {"choices": []}, "two choices": {"choices": [{}, {}]},
             "a tool call": {"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "x",
                                                                                  "tool_calls": [{"id": "t"}]}}]},
             "filtered": {"choices": [{"finish_reason": "content_filter", "message": {"role": "assistant", "content": "x"}}]},
             "cut off": {"choices": [{"finish_reason": "length", "message": {"role": "assistant", "content": '{"verdict":"pass"'}}]}},
    "cloudflare": {"unsuccessful": {"success": False, "errors": [{"message": "no"}], "result": None},
                   "success is not true": {"success": "true", "result": {"response": "x"}},
                   "no result": {"success": True}, "no text": {"success": True, "result": {"response": ""}},
                   "text is not text": {"success": True, "result": {"response": ["x"]}}},
}


@pytest.mark.parametrize("provider,name", [(p, n) for p in NEW for n in sorted(SHAPES[p])])
def test_an_answer_in_any_shape_but_the_expected_one_is_refused_never_read(provider, name):
    stub, log = answering(200, json.dumps(SHAPES[provider][name]).encode()), ProvenanceLog()
    try:
        with pytest.raises(Refused) as e:
            make(provider, stub.url, log)("hi")
        assert e.value.code == "provider" and e.value.category in ("invalid_response", "provider_error")
        assert log.records[0].outcome == "rejected"
        got = exchange(make(provider, stub.url, log), log)
        assert got.verdict == "terminal_breach" and not got.allowed          # and through a decider it is a signed failure
    finally:
        stub.close()


HOSTILE = {
    "a stated human approval": lambda p: json.dumps({**json.loads(honest_model(p)), "approved_by_human": True}),
    "a request to sign": lambda p: json.dumps({**json.loads(honest_model(p)), "sign": True}),
    "an action request": lambda p: json.dumps({**json.loads(honest_model(p)), "action_request": {"action": "release-funds"}}),
    "prose around the object": lambda p: "Sure thing. " + honest_model(p),
    "a code fence": lambda p: "```json\n" + honest_model(p) + "\n```",
    "an evidence kind it cannot produce": lambda p: json.dumps({**json.loads(honest_model(p)), "evidence": {"root": {"x": 1}}}),
    "a verdict that does not exist": lambda p: json.dumps({**json.loads(honest_model(p)), "verdict": "approved"}),
}


@pytest.mark.parametrize("provider", NEW)
@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_whatever_a_model_adds_beyond_the_contract_ends_as_a_signed_failure(provider, name):
    stub, log = serving(provider, HOSTILE[name]), ProvenanceLog()
    try:
        got = exchange(make(provider, stub.url, log), log)
        assert got.verdict == "terminal_breach" and not got.allowed
        assert log.records[-1].outcome == "rejected" and "adapter_output" in log.records[-1].reason
    finally:
        stub.close()


# ------------------------------------------------------------------------------------------------- for every provider
@pytest.mark.parametrize("provider", ALL)
def test_the_request_digest_is_the_digest_of_the_bytes_that_were_sent(provider):
    stub, log = serving(provider, plain), ProvenanceLog()
    try:
        make(provider, stub.url, log)("what was sent is what is recorded")
        assert log.records[0].request_sha256 == hashlib.sha256(stub.requests[0]["raw"]).hexdigest()
    finally:
        stub.close()


@pytest.mark.parametrize("provider", ALL)
def test_the_response_digest_is_the_digest_of_the_bytes_that_came_back(provider):
    data = json.dumps(envelope(provider, "ok")).encode()
    stub, log = answering(200, data), ProvenanceLog()
    try:
        make(provider, stub.url, log)("hi")
        assert log.records[0].response_sha256 == hashlib.sha256(data).hexdigest()
    finally:
        stub.close()


@pytest.mark.parametrize("provider", ALL)
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_no_redirect_is_followed_so_the_key_reaches_no_second_host(provider, status):
    other = Raw(lambda p, h, raw: (200, J, json.dumps(envelope(provider, "ok")).encode()))
    stub = answering(status, b"", {"location": other.url + "/steal"})
    try:
        with pytest.raises(Refused) as e:
            make(provider, stub.url, ProvenanceLog())("hi")
        assert str(status) in e.value.reason and other.requests == []
    finally:
        stub.close()
        other.close()


@pytest.mark.parametrize("provider", ALL)
def test_the_key_is_in_one_header_and_in_no_url_body_record_or_error(provider):
    stub, log = serving(provider, plain), ProvenanceLog()
    try:
        make(provider, stub.url, log)("hi")
        sent = stub.requests[0]
        header = KEY_HEADER.get(provider, "authorization")
        assert sent["headers"][header] in (KEY, "Bearer " + KEY)
        assert [k for k, v in sent["headers"].items() if KEY in v] == [header]
        assert KEY not in sent["path"] and KEY.encode() not in sent["raw"]
        assert KEY not in json.dumps([r.__dict__ for r in log.records]) and KEY not in repr(log.records)
    finally:
        stub.close()


@pytest.mark.parametrize("provider", ALL)
@pytest.mark.parametrize("url", ["http://example.com", "http://10.0.0.5:8080", "ftp://example.com", "example.com", ""])
def test_a_key_is_never_sent_over_plain_http_to_another_machine(provider, url):
    if provider == "copilot" and url == "":
        return  # the GitHub Models route has its own https default when no base_url is given
    with pytest.raises(ValueError) as e:
        make(provider, url, ProvenanceLog())
    assert KEY not in str(e.value)


@pytest.mark.parametrize("provider", ALL)
def test_https_and_this_machine_are_accepted(provider):
    for url in ("https://example.com", "http://127.0.0.1:9", "http://localhost:9", "http://[::1]:9"):
        assert callable(make(provider, url, ProvenanceLog()))


@pytest.mark.parametrize("provider", ALL)
def test_a_host_that_cannot_be_reached_and_one_that_is_too_slow_are_refusals_with_their_own_categories(provider):
    log = ProvenanceLog()
    with pytest.raises(Refused) as e:
        make(provider, "http://127.0.0.1:9", log, timeout_s=2.0)("hi")
    assert e.value.category == "connection_error" and log.records[0].http_status is None

    def slow(p, h, raw):
        time.sleep(1.5)
        return 200, J, json.dumps(envelope(provider, "{}")).encode()
    stub = Raw(slow)
    try:
        with pytest.raises(Refused) as e:
            make(provider, stub.url, ProvenanceLog(), timeout_s=0.3)("hi")
        assert e.value.category == "timeout"
    finally:
        stub.close()


def cut_off(provider):
    out = envelope(provider, '{"verdict":"pass"')
    if provider == "anthropic":
        out["stop_reason"] = "max_tokens"
    elif provider == "gemini":
        out["candidates"][0]["finishReason"] = "MAX_TOKENS"
    else:
        out["choices"][0]["finish_reason"] = "length"
    return json.dumps(out).encode()


REPORTS_FINISH = [p for p in ALL if p != "cloudflare"]


@pytest.mark.parametrize("provider", REPORTS_FINISH)
def test_a_cut_off_answer_is_refused_unless_the_caller_asked_for_text_and_then_the_record_says_it_was_cut_off(provider):
    stub = answering(200, cut_off(provider))
    try:
        with pytest.raises(Refused):
            make(provider, stub.url, ProvenanceLog())("hi")                      # the default, and the only mode a decision uses
        log = ProvenanceLog()
        assert make(provider, stub.url, log, truncated_ok=True)("hi") == '{"verdict":"pass"'
        assert log.records[0].finish_reason in ("max_tokens", "MAX_TOKENS", "length")
        got = exchange(make(provider, stub.url, log, truncated_ok=True), log)
        assert got.verdict == "terminal_breach"                                  # even so, half an answer is no recommendation
    finally:
        stub.close()


@pytest.mark.parametrize("provider", REPORTS_FINISH)
def test_asking_for_text_does_not_let_a_filtered_or_declined_answer_through(provider):
    out = envelope(provider, "x")
    if provider == "anthropic":
        out["stop_reason"] = "refusal"
    elif provider == "gemini":
        out["candidates"][0]["finishReason"] = "SAFETY"
    else:
        out["choices"][0]["finish_reason"] = "content_filter"
    stub = answering(200, json.dumps(out).encode())
    try:
        with pytest.raises(Refused):
            make(provider, stub.url, ProvenanceLog(), truncated_ok=True)("hi")
    finally:
        stub.close()


def test_gemini_sends_an_output_limit_only_when_given_one():
    stub = serving("gemini", plain)
    try:
        make("gemini", stub.url, ProvenanceLog())("hi")
        make("gemini", stub.url, ProvenanceLog(), max_tokens=512)("hi")
        first, second = (json.loads(r["raw"]) for r in stub.requests)
        assert "generationConfig" not in first and second["generationConfig"] == {"maxOutputTokens": 512}
    finally:
        stub.close()


@pytest.mark.parametrize("usage", [None, "many", {"prompt_tokens": -1, "completion_tokens": 3}, {"prompt_tokens": True, "completion_tokens": 3},
                                   {"prompt_tokens": 1.5, "completion_tokens": 3}, {"prompt_tokens": 1}])
def test_token_counts_that_are_not_two_plain_counts_are_left_unrecorded(usage):
    stub, log = answering(200, json.dumps({**openai_ok("x"), "usage": usage}).encode()), ProvenanceLog()
    try:
        make("groq", stub.url, log)("hi")
        assert (log.records[0].input_tokens, log.records[0].output_tokens) == (None, None)
    finally:
        stub.close()


@pytest.mark.parametrize("bad", [{"account_id": ""}, {"account_id": "a/b"}, {"account_id": "../x"}, {"account_id": "a?b"}])
def test_a_cloudflare_account_id_that_could_change_the_path_is_a_caller_error(bad):
    with pytest.raises(ValueError):
        cloudflare_complete(KEY, "@cf/meta/m", ProvenanceLog(), **bad)


@pytest.mark.parametrize("model", ["", "m?x=1", "m#frag", "../../user/tokens"])
def test_a_cloudflare_model_name_that_could_change_the_path_is_a_caller_error(model):
    with pytest.raises(ValueError):
        cloudflare_complete(KEY, model, ProvenanceLog(), account_id="acct123")


@pytest.mark.parametrize("ch", ["\n", " ", "\t", "​", "﻿"])
def test_groq_and_cloudflare_refuse_a_key_with_whitespace_or_a_hidden_character_and_never_show_it(ch):
    for build in (lambda k: groq_complete(k, "m", ProvenanceLog()),
                  lambda k: cloudflare_complete(k, "m", ProvenanceLog(), account_id="acct123")):
        with pytest.raises(ValueError) as e:
            build("sk-SECRET" + ch + "tail")
        assert "SECRET" not in str(e.value)
