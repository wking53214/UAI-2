import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cns_composition.providers.protocol import (
    CompletionStatus, ModelRequest, ModelResponse,
)
from uai2_bridge import PortableTextProvider, ProviderExecutionError
from uai2_groq import GroqAdapter

MODEL = "groq-test-model"


class GroqStubHandler(BaseHTTPRequestHandler):
    status = 200
    payload = {}
    raw_body = None
    captured = {}

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        type(self).captured = {
            "path": self.path,
            "headers": dict(self.headers),
            "body": json.loads(raw),
            "raw": raw,
        }
        body = (
            type(self).raw_body
            if type(self).raw_body is not None
            else json.dumps(type(self).payload).encode()
        )
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class GroqAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), GroqStubHandler
        )
        cls.thread = threading.Thread(
            target=cls.server.serve_forever, daemon=True
        )
        cls.thread.start()
        cls.base_url = (
            "http://127.0.0.1:%s" % cls.server.server_port
        )

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        GroqStubHandler.status = 200
        GroqStubHandler.raw_body = None
        GroqStubHandler.captured = {}
        GroqStubHandler.payload = {
            "id": "groq-response-1",
            "model": "groq-reported-model",
            "choices": [{
                "message": {"content": "stub Groq answer"},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": 8,
                "completion_tokens": 4,
            },
        }

    def adapter(self):
        return GroqAdapter(
            "stub-groq-secret", MODEL, base_url=self.base_url
        )

    def request(self):
        return ModelRequest(
            model=MODEL,
            system_instruction="",
            user_messages=("hello provider",),
            max_output_tokens=512,
            generation_settings={},
        )

    def test_wire_contract_and_normalization(self):
        adapter = self.adapter()
        provider = PortableTextProvider(adapter, "groq", MODEL)
        result = provider.generate(self.request())

        self.assertIsInstance(result, ModelResponse)
        self.assertEqual(result.content, "stub Groq answer")
        self.assertEqual(result.provider, "groq")
        self.assertEqual(result.model, MODEL)
        self.assertEqual(result.completion_status, CompletionStatus.COMPLETE)
        self.assertEqual(result.usage.input_tokens, 8)
        self.assertEqual(result.usage.output_tokens, 4)
        self.assertEqual(result.request_id, "groq-response-1")
        self.assertEqual(
            result.native_response["model_reported"],
            "groq-reported-model",
        )

        captured = GroqStubHandler.captured
        self.assertEqual(captured["path"], "/chat/completions")
        headers = {k.lower(): v for k, v in captured["headers"].items()}
        self.assertEqual(
            headers["authorization"], "Bearer stub-groq-secret"
        )
        self.assertEqual(captured["body"]["model"], MODEL)
        self.assertEqual(captured["body"]["max_tokens"], 512)
        self.assertEqual(
            captured["body"]["messages"][0]["content"],
            "hello provider",
        )
        self.assertNotIn("stub-groq-secret", captured["raw"].decode())

        evidence = adapter.last_evidence
        self.assertEqual(evidence.outcome, "success")
        self.assertEqual(len(evidence.request_sha256), 64)
        self.assertEqual(len(evidence.response_sha256), 64)
        self.assertIsNotNone(evidence.model_reported)
        self.assertGreaterEqual(evidence.latency_ms, 0)
        self.assertNotIn("stub-groq-secret", repr(evidence))

    def test_length_finish_reason_maps_to_max_tokens(self):
        GroqStubHandler.payload["choices"][0]["finish_reason"] = "length"
        result = PortableTextProvider(
            self.adapter(), "groq", MODEL
        ).generate(self.request())
        self.assertEqual(
            result.completion_status, CompletionStatus.MAX_TOKENS
        )

    def test_content_filter_maps_to_stopped(self):
        GroqStubHandler.payload["choices"][0]["finish_reason"] = "content_filter"
        result = PortableTextProvider(
            self.adapter(), "groq", MODEL
        ).generate(self.request())
        self.assertEqual(
            result.completion_status, CompletionStatus.STOPPED
        )

    def test_http_401_is_sanitized(self):
        GroqStubHandler.status = 401
        GroqStubHandler.payload = {
            "error": {"message": "private authentication detail"}
        }
        adapter = self.adapter()
        with self.assertRaises(ProviderExecutionError) as caught:
            adapter("hello", 512)
        self.assertEqual(caught.exception.category, "authentication")
        self.assertNotIn("private authentication detail", str(caught.exception))
        self.assertEqual(adapter.last_evidence.http_status, 401)
        self.assertEqual(adapter.last_evidence.outcome, "failure")

    def test_http_429_is_sanitized(self):
        GroqStubHandler.status = 429
        GroqStubHandler.payload = {
            "error": {"message": "private rate limit detail"}
        }
        adapter = self.adapter()
        with self.assertRaises(ProviderExecutionError) as caught:
            adapter("hello", 512)
        self.assertEqual(caught.exception.category, "rate_limit")
        self.assertNotIn("private rate limit detail", str(caught.exception))
        self.assertEqual(adapter.last_evidence.http_status, 429)

    def test_malformed_json_is_rejected_and_hashed(self):
        GroqStubHandler.raw_body = b"{not-json"
        adapter = self.adapter()
        with self.assertRaises(ProviderExecutionError) as caught:
            adapter("hello", 512)
        self.assertEqual(caught.exception.category, "invalid_response")
        self.assertEqual(adapter.last_evidence.outcome, "failure")
        self.assertEqual(len(adapter.last_evidence.response_sha256), 64)

    def test_oversized_response_is_rejected(self):
        GroqStubHandler.raw_body = b"x" * 2_000_001
        adapter = self.adapter()
        with self.assertRaises(ProviderExecutionError) as caught:
            adapter("hello", 512)
        self.assertEqual(caught.exception.category, "response_too_large")
        self.assertEqual(adapter.last_evidence.outcome, "failure")


if __name__ == "__main__":
    unittest.main()
