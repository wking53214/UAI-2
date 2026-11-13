"""interop/jury.py against a LOCAL stub server that speaks the chat-completions wire format. Nothing here calls a real provider.

What this shows: the preflight keeps a juror whose provider answers and drops one whose request is refused; the run refuses to
start when too few providers pass; a juror stops after three invalid-request answers in a row (the failure that wasted the
2026-11-11 runs); GitHub Models jurors come from the environment, one per listed model; and a key is sent only in the header.
What it does NOT show: that any real provider behaves this way, or how a model answers.
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
    """A chat-completions server. A request naming a model in `refuse` gets HTTP `status`; any other gets a valid answer."""

    def __init__(self, refuse=(), status=404):
        self.requests, self.refuse, self.status = [], set(refuse), status
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
                outer.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                if body.get("model") in outer.refuse:
                    code, data = outer.status, b'{"error": "no such model"}'
                else:
                    code, data = 200, json.dumps({"id": "x", "model": body.get("model", ""), "usage": {"prompt_tokens": 5, "completion_tokens": 5},
                                                  "choices": [{"finish_reason": "stop", "message": {
                                                      "role": "assistant", "content": json.dumps(GOOD)}}]}).encode()
                self.send_response(code)
                self.send_header("content-type", "application/json")
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


ENV = {"GROQ_API_KEY": "groq-test-KEY-0123456789", "GROQ_MODEL": "groq-model",
       "GITHUB_MODELS_TOKEN": "ghp-test-TOKEN-0123456789", "GITHUB_MODELS_LIST": "openai/good, meta/bad-name"}


def shared():
    return {"lock": threading.Lock(), "spent": 0.0, "reserved": 0.0, "stop": False}


def test_github_models_jurors_come_from_the_environment_one_per_listed_model_and_the_token_stays_in_the_header():
    stub = Stub()
    try:
        jurors = jury.jurors_from_env(ENV, [], stub.url)
        assert [(j["provider"], j["model"]) for j in jurors] == [
            ("groq", "groq-model"), ("github-models", "openai/good"), ("github-models", "meta/bad-name")]
        rows = []
        jury.preflight(jurors[1:2], shared(), rows.append)
        sent = stub.requests[0]
        assert sent["path"] == "/chat/completions" and sent["body"]["model"] == "openai/good"
        assert {k.lower(): v for k, v in sent["headers"].items()}["authorization"] == "Bearer " + ENV["GITHUB_MODELS_TOKEN"]
        assert ENV["GITHUB_MODELS_TOKEN"] not in json.dumps(rows) and ENV["GITHUB_MODELS_TOKEN"] not in json.dumps(sent["body"])
    finally:
        stub.close()


def test_a_missing_github_token_or_list_is_said_and_adds_no_juror(capsys):
    jurors = jury.jurors_from_env({"GROQ_API_KEY": "groq-test-KEY-0123456789", "GROQ_MODEL": "m", "GITHUB_MODELS_TOKEN": "t"}, [], None)
    assert [j["provider"] for j in jurors] == ["groq"]
    assert "NOT EXECUTED: github-models" in capsys.readouterr().out


def test_preflight_keeps_a_juror_whose_provider_answers_and_drops_one_whose_request_is_refused(capsys):
    stub = Stub(refuse=["meta/bad-name"], status=404)
    try:
        jurors = jury.jurors_from_env(ENV, [], stub.url)
        rows = []
        kept = jury.preflight(jurors, shared(), rows.append)
        assert [j["model"] for j in kept] == ["groq-model", "openai/good"]
        assert [r["http_status"] for r in rows] == [200, 200, 404] and {r["round"] for r in rows} == {-1}
        assert "preflight FAILED  github-models:meta/bad-name" in capsys.readouterr().out
        assert jurors[2]["ended"].startswith("failed the preflight")
    finally:
        stub.close()


def test_three_invalid_requests_in_a_row_end_a_juror_instead_of_burning_the_whole_run():
    stub = Stub(refuse=["groq-model"], status=404)
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
    stub = Stub(refuse=["groq-model", "openai/good", "meta/bad-name"], status=404)
    try:
        for k, v in ENV.items():
            monkeypatch.setenv(k, v)
        out = tmp_path / "rows.jsonl"
        code = jury.main(["--stub", stub.url, "--out", str(out), "--min-providers", "2", "--rounds", "1"])
        assert code == 4 and "NOT EXECUTED: 0 provider(s) passed the preflight" in capsys.readouterr().out
        rows = [json.loads(line) for line in out.read_text().splitlines()]
        assert len(rows) == 3 and {r["round"] for r in rows} == {-1}      # only the preflight calls were made
        assert len(stub.requests) == 3
    finally:
        stub.close()


def test_the_run_goes_ahead_when_enough_providers_pass_and_the_failed_one_is_left_out(tmp_path, monkeypatch, capsys):
    stub = Stub(refuse=["meta/bad-name"], status=404)
    try:
        for k, v in ENV.items():
            monkeypatch.setenv(k, v)
        out = tmp_path / "rows.jsonl"
        code = jury.main(["--stub", stub.url, "--out", str(out), "--min-providers", "2", "--rounds", "1", "--max-calls", "2",
                          "--spacing", "0"])
        rows = [json.loads(line) for line in out.read_text().splitlines()]
        assert code == 0, capsys.readouterr().out
        assert {r["juror"] for r in rows if r["round"] == 0} == {"groq:groq-model", "github-models:openai/good"}
        assert sum(1 for r in rows if r["round"] == -1) == 3            # the preflight, kept in the record
    finally:
        stub.close()
