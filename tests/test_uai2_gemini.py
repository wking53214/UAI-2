import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cns_composition.providers.protocol import CompletionStatus, ModelRequest, ModelResponse
from uai2_bridge import PORTABLE_MAX_OUTPUT_TOKENS, PortableTextProvider, ProviderExecutionError
from uai2_gemini import GeminiAdapter


MODEL = "gemini-test-model"


class StubHandler(BaseHTTPRequestHandler):
    status = 200
    payload = {}
    captured = {}
    raw_body = None

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        type(self).captured = {
            "path": self.path,
            "headers": dict(self.headers),
            "body": json.loads(raw),
            "raw": raw,
        }
        body = type(self).raw_body if type(self).raw_body is not None else json.dumps(type(self).payload).encode()
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class GeminiAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), StubHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = "http://127.0.0.1:%s" % cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        StubHandler.status = 200
        StubHandler.payload = {
            "candidates": [{
                "content": {"parts": [{"text": "stub answer"}]},
                "finishReason": "STOP",
            }],
            "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 3},
            "modelVersion": "gemini-test-reported",
            "responseId": "stub-response-1",
        }
        StubHandler.captured = {}
        StubHandler.raw_body = None

    def adapter(self):
        return GeminiAdapter("stub-secret-key", MODEL, base_url=self.base_url)

    def test_wire_contract_and_response_normalization(self):
        adapter = self.adapter()
        provider = PortableTextProvider(adapter, "google-gemini", MODEL)
        request = ModelRequest(
            model=MODEL,
            system_instruction="",
            user_messages=("hello provider",),
            max_output_tokens=PORTABLE_MAX_OUTPUT_TOKENS,
            generation_settings={},
        )
        result = provider.generate(request)

        self.assertIsInstance(result, ModelResponse)
        self.assertEqual(result.content, "stub answer")
        self.assertEqual(result.completion_status, CompletionStatus.COMPLETE)
        self.assertEqual(result.usage.input_tokens, 7)
        self.assertEqual(result.usage.output_tokens, 3)
        self.assertEqual(result.request_id, "stub-response-1")
        self.assertEqual(result.native_response["model_version"], "gemini-test-reported")

        captured = StubHandler.captured
        self.assertTrue(captured["path"].endswith(":generateContent"))
        self.assertEqual(captured["body"]["generationConfig"]["maxOutputTokens"], 512)
        self.assertEqual(captured["body"]["contents"][0]["parts"][0]["text"], "hello provider")
        self.assertEqual({k.lower(): v for k, v in captured["headers"].items()}["x-goog-api-key"], "stub-secret-key")
        self.assertNotIn("stub-secret-key", captured["raw"].decode())

        evidence = adapter.last_evidence
        self.assertEqual(evidence.outcome, "success")
        self.assertEqual(len(evidence.request_sha256), 64)
        self.assertEqual(len(evidence.response_sha256), 64)
        self.assertEqual(evidence.model_reported, "gemini-test-reported")

    def test_max_tokens_finish_reason_survives_bridge(self):
        StubHandler.payload["candidates"][0]["finishReason"] = "MAX_TOKENS"
        result = PortableTextProvider(
            self.adapter(), "google-gemini", MODEL
        ).generate(ModelRequest(
            model=MODEL, system_instruction="", user_messages=("hello",),
            max_output_tokens=512, generation_settings={},
        ))
        self.assertEqual(result.completion_status, CompletionStatus.MAX_TOKENS)

    def test_http_429_is_sanitized_and_evidenced(self):
        StubHandler.status = 429
        StubHandler.payload = {"error": {"message": "private provider detail"}}
        adapter = self.adapter()
        provider = PortableTextProvider(adapter, "google-gemini", MODEL)
        request = ModelRequest(
            model=MODEL, system_instruction="", user_messages=("hello",),
            max_output_tokens=512, generation_settings={},
        )
        with self.assertRaises(ProviderExecutionError) as caught:
            provider.generate(request)

        self.assertEqual(caught.exception.category, "rate_limit")
        self.assertNotIn("private provider detail", str(caught.exception))
        evidence = adapter.last_evidence
        self.assertEqual(evidence.outcome, "failure")
        self.assertEqual(evidence.error_category, "rate_limit")
        self.assertEqual(evidence.http_status, 429)
        self.assertIsNone(evidence.response_sha256)
        self.assertNotIn("stub-secret-key", repr(evidence))


    def test_malformed_json_is_rejected_and_hashed(self):
        StubHandler.raw_body = b"{not-json"
        adapter = self.adapter()
        with self.assertRaises(ProviderExecutionError) as caught:
            adapter("hello", 512)
        self.assertEqual(caught.exception.category, "invalid_response")
        self.assertEqual(adapter.last_evidence.outcome, "failure")
        self.assertEqual(adapter.last_evidence.error_category, "invalid_response")
        self.assertEqual(len(adapter.last_evidence.response_sha256), 64)

    def test_safety_finish_reason_is_preserved(self):
        StubHandler.payload["candidates"][0]["finishReason"] = "SAFETY"
        result = PortableTextProvider(
            self.adapter(), "google-gemini", MODEL
        ).generate(ModelRequest(
            model=MODEL, system_instruction="", user_messages=("hello",),
            max_output_tokens=512, generation_settings={},
        ))
        self.assertEqual(result.completion_status, CompletionStatus.STOPPED)

    def test_http_401_is_sanitized_and_evidenced(self):
        StubHandler.status = 401
        StubHandler.payload = {"error": {"message": "private auth detail"}}
        adapter = self.adapter()
        with self.assertRaises(ProviderExecutionError) as caught:
            adapter("hello", 512)
        self.assertEqual(caught.exception.category, "authentication")
        self.assertNotIn("private auth detail", str(caught.exception))
        self.assertEqual(adapter.last_evidence.http_status, 401)
        self.assertEqual(adapter.last_evidence.error_category, "authentication")

    def test_oversized_response_is_rejected(self):
        StubHandler.raw_body = b"x" * 2_000_001
        adapter = self.adapter()
        with self.assertRaises(ProviderExecutionError) as caught:
            adapter("hello", 512)
        self.assertEqual(caught.exception.category, "response_too_large")
        self.assertEqual(adapter.last_evidence.outcome, "failure")
        self.assertEqual(adapter.last_evidence.error_category, "response_too_large")


if __name__ == "__main__":
    unittest.main()
