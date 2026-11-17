"""interop/induced_failures.py, against a stand-in server. EVERY SERVER HERE IS A STUB.

What this shows: the script runs its six cases, counts a case as expected only when the client refused (or answered, for the
baseline) in the way the case names, never prints or writes the key, and exits 3 without a key and 1 when a case misbehaves.
What it does not show: how any real service answers. That is what running the script against one is for, and
evidence/live-runs/ holds the rows of the runs made so far.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_provider_layer import KEY, Raw  # type: ignore[import-not-found]  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("induced_failures", ROOT / "interop" / "induced_failures.py")
induced = importlib.util.module_from_spec(spec)
spec.loader.exec_module(induced)

J = {"content-type": "application/json"}


def ok_body(finish="stop"):
    return {"id": "c1", "model": "m", "choices": [{"index": 0, "finish_reason": finish, "message": {"role": "assistant", "content": "ok"}}]}


def service(*, wrong_on=None):
    """Behaves like a service: 404 for an unknown model, 400 for a negative limit, a cut-off answer for a limit of 1, else ok."""
    def respond(path, headers, raw):
        body = json.loads(raw)
        time.sleep(0.15)                                            # slow enough that a 0.05 second limit is missed
        if wrong_on == "all-ok":
            return 200, J, json.dumps(ok_body()).encode()
        if body["model"].startswith("no-such"):
            return 404, J, json.dumps([{"error": {"code": 404, "message": "model not found", "status": "NOT_FOUND"}}]).encode()
        if body["max_tokens"] < 1:
            return 400, J, json.dumps({"error": {"message": "max_tokens must be positive", "type": "invalid_request_error"}}).encode()
        return 200, J, json.dumps(ok_body("length" if body["max_tokens"] == 1 else "stop")).encode()
    return Raw(respond)


def run(monkeypatch, capsys, stub, tmp_path):
    monkeypatch.setenv("OPENAI_STYLE_KEY", KEY + "\n")
    out = tmp_path / "out.json"
    code = induced.main(["--name", "stand-in", "--base-url", stub.url, "--model", "m", "--out", str(out)])
    return code, capsys.readouterr().out, json.loads(out.read_text()), out.read_text()


def test_every_case_behaves_as_expected_against_a_service_that_behaves(monkeypatch, capsys, tmp_path):
    stub = service()
    try:
        code, printed, data, text = run(monkeypatch, capsys, stub, tmp_path)
    finally:
        stub.close()
    assert code == 0 and printed.count("ok ") == 6 and "BAD" not in printed
    assert [c["label"] for c in data["cases"]] == [c["label"] for c in induced.CASES]
    by = {c["label"]: c for c in data["cases"]}
    assert by["baseline"]["result"] == "answered"
    assert "NOT_FOUND: model not found" in by["model-that-does-not-exist"]["reason"]           # a list-wrapped error is read
    assert "invalid_request_error: max_tokens must be positive" in by["request-it-cannot-accept"]["reason"]
    assert by["runs-out-of-time"]["category"] == "timeout" and by["answer-larger-than-allowed"]["category"] == "response_too_large"
    assert KEY not in text and KEY not in printed


def test_a_service_that_answers_a_call_it_should_refuse_is_reported_as_a_finding_and_exits_1(monkeypatch, capsys, tmp_path):
    stub = service(wrong_on="all-ok")
    try:
        code, printed, data, _ = run(monkeypatch, capsys, stub, tmp_path)
    finally:
        stub.close()
    bad = {c["label"] for c in data["cases"] if not c["behaved_as_expected"]}
    assert code == 1 and "model-that-does-not-exist" in bad and "request-it-cannot-accept" in bad and "baseline" not in bad


def test_no_key_means_not_executed_and_exit_3(monkeypatch, capsys):
    monkeypatch.delenv("OPENAI_STYLE_KEY", raising=False)
    assert induced.main(["--name", "n", "--base-url", "https://example.invalid", "--model", "m"]) == 3
    assert "NOT EXECUTED" in capsys.readouterr().out


@pytest.mark.parametrize("bad", ["http://example.com/v1", "ftp://x"])
def test_a_plain_http_address_to_another_machine_is_refused_before_a_key_is_sent(monkeypatch, capsys, tmp_path, bad):
    monkeypatch.setenv("OPENAI_STYLE_KEY", KEY)
    with pytest.raises(ValueError):
        induced.run_case(induced.CASES[0], "n", bad, KEY, "m")


def test_a_user_agent_is_sent_only_when_asked_for(monkeypatch, capsys, tmp_path):
    stub = service()
    try:
        monkeypatch.setenv("OPENAI_STYLE_KEY", KEY)
        induced.main(["--name", "n", "--base-url", stub.url, "--model", "m"])
        without = {r["headers"].get("user-agent", "") for r in stub.requests}
        induced.main(["--name", "n", "--base-url", stub.url, "--model", "m", "--user-agent", "STACK-UAI2-Provider/1.0"])
        with_flag = {r["headers"].get("user-agent", "") for r in stub.requests[len(stub.requests) // 2:]}
    finally:
        stub.close()
    assert "STACK-UAI2-Provider/1.0" not in without and with_flag == {"STACK-UAI2-Provider/1.0"}


def cloudflare_service():
    """Workers AI as the older models answer it: `{"success", "result": {"response"}}`, with no word on why the answer ended."""
    def respond(path, headers, raw):
        body = json.loads(raw)
        time.sleep(0.15)
        if path.endswith("no-such-model-uai-check"):
            return 404, J, json.dumps({"success": False, "errors": [{"code": 7000, "message": "No route for that URI"}], "result": None}).encode()
        if body["max_tokens"] < 1:
            return 400, J, json.dumps({"success": False, "errors": [{"code": 5006, "message": "max_tokens invalid"}], "result": None}).encode()
        return 200, J, json.dumps({"success": True, "errors": [], "result": {"response": "ok"}}).encode()
    return Raw(respond)


def test_the_cloudflare_style_uses_its_own_client_records_that_a_cut_off_cannot_be_told_and_never_prints_the_account(monkeypatch, capsys, tmp_path):
    stub = cloudflare_service()
    account = "95d61c4bd9fd85311a2e86717ecc7a60"
    try:
        monkeypatch.setenv("OPENAI_STYLE_KEY", KEY)
        out = tmp_path / "o.json"
        code = induced.main(["--name", "cf", "--base-url", stub.url, "--model", "@cf/meta/model-x", "--account-id", account, "--out", str(out)])
        paths = {r["path"] for r in stub.requests}
    finally:
        stub.close()
    printed = capsys.readouterr().out
    data = json.loads(out.read_text())
    by = {c["label"]: c for c in data["cases"]}
    assert code == 0 and paths >= {f"/accounts/{account}/ai/run/@cf/meta/model-x"}
    assert by["answer-cut-off"]["result"] == "answered" and by["answer-cut-off"]["cannot_tell_if_cut_off"] is True
    assert "7000: No route for that URI" in by["model-that-does-not-exist"]["reason"] and "5006: max_tokens invalid" in by["request-it-cannot-accept"]["reason"]
    assert account not in out.read_text() and KEY not in out.read_text() and KEY not in printed
