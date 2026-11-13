"""interop/jury.py against a LOCAL stub server that speaks the chat-completions wire format. Nothing here calls a real provider.

What this shows: a comma list of models makes one juror each; the preflight keeps a juror whose provider gives a readable answer
and drops one whose request is refused AND one whose provider answers HTTP 200 with something that is not a model answer (a
retired service replying a plain "OK", the case the first preflight missed); the run refuses to start when too few providers
pass; a juror stops after three invalid-request answers in a row (the failure that wasted the 2026-11-11 runs); and a key is
sent only in the header. What it does NOT show: that any real provider behaves this way, or how a model answers.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "interop"))

import jury  # type: ignore[import-not-found]  # noqa: E402

GOOD = {"verdict": "pass", "reasons": ["clears the threshold"], "evidence": {"threshold-check": {"observed": 900000}},
        "escalate": False}


class Stub:
    """A chat-completions server. A model in `refuse` gets HTTP `status`; one in `plain` gets HTTP 200 and the text OK; any
    other gets a valid answer."""

    def __init__(self, refuse=(), status=404, plain=()):
        self.requests, self.refuse, self.status, self.plain = [], set(refuse), status, set(plain)
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
                outer.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                kind = "application/json"
                if body.get("model") in outer.refuse:
                    code, data = outer.status, b'{"error": "no such model"}'
                elif body.get("model") in outer.plain:
                    code, data, kind = 200, b"OK", "text/plain"
                else:
                    code, data = 200, json.dumps({"id": "x", "model": body.get("model", ""), "usage": {"prompt_tokens": 5, "completion_tokens": 5},
                                                  "choices": [{"finish_reason": "stop", "message": {
                                                      "role": "assistant", "content": json.dumps(GOOD)}}]}).encode()
                self.send_response(code)
                self.send_header("content-type", kind)
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


KEY = "groq-test-KEY-0123456789"
ENV = {"GROQ_API_KEY": KEY, "GROQ_MODEL": "good-model, dead-model, bad-name"}


def shared():
    return {"lock": threading.Lock(), "spent": 0.0, "reserved": 0.0, "stop": False}


def test_a_comma_list_of_models_makes_one_juror_each_and_the_key_stays_in_the_header(capsys):
    stub = Stub()
    try:
        jurors = jury.jurors_from_env(ENV, [], stub.url)
        assert [(j["provider"], j["model"]) for j in jurors] == [("groq", "good-model"), ("groq", "dead-model"), ("groq", "bad-name")]
        rows = []
        jury.preflight(jurors[:1], shared(), rows.append)
        sent = stub.requests[0]
        assert sent["path"] == "/chat/completions" and sent["body"]["model"] == "good-model"
        assert {k.lower(): v for k, v in sent["headers"].items()}["authorization"] == "Bearer " + KEY
        assert KEY not in json.dumps(rows) and KEY not in json.dumps(sent["body"])
    finally:
        stub.close()
    assert "NOT EXECUTED: google" in capsys.readouterr().out


def test_a_provider_with_no_key_or_no_model_is_said_and_adds_no_juror(capsys):
    assert jury.jurors_from_env({"GROQ_API_KEY": KEY, "GROQ_MODEL": " , "}, [], None) == []
    assert "NOT EXECUTED: groq" in capsys.readouterr().out


def test_preflight_keeps_a_readable_answer_and_drops_a_refused_request_and_a_plain_ok_from_a_retired_service(capsys):
    stub = Stub(refuse=["bad-name"], status=404, plain=["dead-model"])
    try:
        jurors = jury.jurors_from_env(ENV, [], stub.url)
        rows = []
        kept = jury.preflight(jurors, shared(), rows.append)
        assert [j["model"] for j in kept] == ["good-model"]
        assert [r["http_status"] for r in rows] == [200, 200, 404] and {r["round"] for r in rows} == {-1}
        out = capsys.readouterr().out
        assert "preflight FAILED  groq:dead-model" in out and "preflight FAILED  groq:bad-name" in out
        assert jurors[1]["ended"].startswith("failed the preflight") and jurors[2]["ended"].startswith("failed the preflight")
    finally:
        stub.close()


def test_three_invalid_requests_in_a_row_end_a_juror_instead_of_burning_the_whole_run():
    stub = Stub(refuse=["good-model"], status=404)
    try:
        juror = jury.jurors_from_env(ENV, [], stub.url)[0]
        rows = []
        opts = argparse.Namespace(rounds=5, max_calls=100, spacing=0.0, cap=1.0)
        jury.run_juror(juror, opts, list(jury.documents()), shared(), rows.append)
        assert len(rows) == 3 and {r["http_status"] for r in rows} == {404}
        assert "refused as invalid" in juror["ended"]
    finally:
        stub.close()


def test_a_juror_that_is_answered_is_not_stopped_by_the_invalid_request_rule():
    stub = Stub()
    try:
        juror = jury.jurors_from_env(ENV, [], stub.url)[0]
        rows = []
        opts = argparse.Namespace(rounds=1, max_calls=7, spacing=0.0, cap=1.0)
        jury.run_juror(juror, opts, list(jury.documents()), shared(), rows.append)
        assert len(rows) == 7 and {r["http_status"] for r in rows} == {200}
    finally:
        stub.close()


def test_the_run_refuses_to_start_when_too_few_providers_pass_the_preflight(tmp_path, monkeypatch, capsys):
    stub = Stub(plain=["good-model", "dead-model", "bad-name"])           # every model answers a plain OK
    try:
        for k, v in ENV.items():
            monkeypatch.setenv(k, v)
        out = tmp_path / "rows.jsonl"
        code = jury.main(["--stub", stub.url, "--out", str(out), "--min-providers", "1", "--rounds", "1"])
        assert code == 4 and "NOT EXECUTED: 0 provider(s) passed the preflight" in capsys.readouterr().out
        rows = [json.loads(line) for line in out.read_text().splitlines()]
        assert len(rows) == 3 and {r["round"] for r in rows} == {-1}      # only the preflight calls were made
        assert len(stub.requests) == 3
    finally:
        stub.close()


def test_the_run_goes_ahead_when_enough_providers_pass_and_the_failed_models_are_left_out(tmp_path, monkeypatch, capsys):
    stub = Stub(refuse=["bad-name"], status=404, plain=["dead-model"])
    try:
        for k, v in ENV.items():
            monkeypatch.setenv(k, v)
        out = tmp_path / "rows.jsonl"
        code = jury.main(["--stub", stub.url, "--out", str(out), "--min-providers", "1", "--rounds", "1", "--max-calls", "2",
                          "--spacing", "0"])
        rows = [json.loads(line) for line in out.read_text().splitlines()]
        assert code == 0, capsys.readouterr().out
        assert {r["juror"] for r in rows if r["round"] == 0} == {"groq:good-model"}
        assert sum(1 for r in rows if r["round"] == -1) == 3            # the preflight, kept in the record
    finally:
        stub.close()
