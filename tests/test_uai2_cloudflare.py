import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cns_composition.providers.protocol import (
    CompletionStatus, ModelRequest, ModelResponse,
)
from uai2_bridge import PortableTextProvider, ProviderExecutionError
from uai2_cloudflare import CloudflareAdapter

MODEL = "@cf/meta/llama-3.1-8b-instruct"
ACCOUNT = "test-account"


class CloudflareStubHandler(BaseHTTPRequestHandler):
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
        self.send_header("cf-ray", "stub-ray-id")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class CloudflareAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), CloudflareStubHandler
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
        CloudflareStubHandler.status = 200
        CloudflareStubHandler.raw_body = None
        CloudflareStubHandler.captured = {}
        CloudflareStubHandler.payload = {
            "success": True,
            "result": {
                "response": "stub Cloudflare answer",
            },
            "errors": [],
            "messages": [],
        }

    def adapter(self):
        return CloudflareAdapter(
            ACCOUNT,
            "stub-cloudflare-secret",
            MODEL,
            base_url=self.base_url,
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
        provider = PortableTextProvider(
            adapter, "cloudflare-workers-ai", MODEL
        )
        result = provider.generate(self.request())

        self.assertIsInstance(result, ModelResponse)
        self.assertEqual(result.content, "stub Cloudflare answer")
        self.assertEqual(result.provider, "cloudflare-workers-ai")
        self.assertEqual(result.model, MODEL)
        self.assertEqual(
            result.completion_status, CompletionStatus.COMPLETE
        )
        self.assertIsNone(result.usage)
        self.assertEqual(result.request_id, "stub-ray-id")
        self.assertEqual(
            result.native_response["finish_reason"], "UNKNOWN"
        )

        captured = CloudflareStubHandler.captured
        self.assertEqual(
            captured["path"],
            f"/accounts/{ACCOUNT}/ai/run/{MODEL}",
        )
        headers = {
            k.lower(): v
            for k, v in captured["headers"].items()
        }
        self.assertEqual(
            headers["authorization"],
            "Bearer stub-cloudflare-secret",
        )
        self.assertEqual(
            captured["body"]["prompt"], "hello provider"
        )
        self.assertEqual(captured["body"]["max_tokens"], 512)
        self.assertNotIn(
            "stub-cloudflare-secret", captured["raw"].decode()
        )

        evidence = adapter.last_evidence
        self.assertEqual(evidence.outcome, "success")
        self.assertEqual(evidence.provider, "cloudflare-workers-ai")
        self.assertEqual(len(evidence.request_sha256), 64)
        self.assertEqual(len(evidence.response_sha256), 64)
        self.assertGreaterEqual(evidence.latency_ms, 0)
        self.assertEqual(evidence.request_id, "stub-ray-id")
        self.assertNotIn("stub-cloudflare-secret", repr(evidence))

    def test_http_401_is_sanitized(self):
        CloudflareStubHandler.status = 401
        adapter = self.adapter()
        with self.assertRaises(ProviderExecutionError) as caught:
            adapter("hello", 512)
        self.assertEqual(caught.exception.category, "authentication")
        self.assertEqual(adapter.last_evidence.http_status, 401)
        self.assertEqual(adapter.last_evidence.outcome, "failure")
        self.assertNotIn("stub-cloudflare-secret", str(caught.exception))

    def test_http_403_is_sanitized(self):
        CloudflareStubHandler.status = 403
        adapter = self.adapter()
        with self.assertRaises(ProviderExecutionError) as caught:
            adapter("hello", 512)
        self.assertEqual(caught.exception.category, "permission")
        self.assertEqual(adapter.last_evidence.http_status, 403)

    def test_http_429_is_sanitized(self):
        CloudflareStubHandler.status = 429
        adapter = self.adapter()
        with self.assertRaises(ProviderExecutionError) as caught:
            adapter("hello", 512)
        self.assertEqual(caught.exception.category, "rate_limit")
        self.assertEqual(adapter.last_evidence.http_status, 429)

    def test_malformed_json_is_rejected_and_hashed(self):
        CloudflareStubHandler.raw_body = b"{not-json"
        adapter = self.adapter()
        with self.assertRaises(ProviderExecutionError) as caught:
            adapter("hello", 512)
        self.assertEqual(caught.exception.category, "invalid_response")
        self.assertEqual(adapter.last_evidence.outcome, "failure")
        self.assertEqual(
            len(adapter.last_evidence.response_sha256), 64
        )

    def test_missing_response_text_is_rejected(self):
        CloudflareStubHandler.payload = {
            "success": True,
            "result": {},
            "errors": [],
        }
        adapter = self.adapter()
        with self.assertRaises(ProviderExecutionError) as caught:
            adapter("hello", 512)
        self.assertEqual(caught.exception.category, "invalid_response")

    def test_unsuccessful_api_envelope_is_rejected(self):
        CloudflareStubHandler.payload = {
            "success": False,
            "result": None,
            "errors": [{"message": "private provider detail"}],
        }
        adapter = self.adapter()
        with self.assertRaises(ProviderExecutionError) as caught:
            adapter("hello", 512)
        self.assertEqual(caught.exception.category, "provider_error")
        self.assertNotIn(
            "private provider detail", str(caught.exception)
        )

    def test_oversized_response_is_rejected(self):
        CloudflareStubHandler.raw_body = b"x" * 2_000_001
        adapter = self.adapter()
        with self.assertRaises(ProviderExecutionError) as caught:
            adapter("hello", 512)
        self.assertEqual(
            caught.exception.category, "response_too_large"
        )
        self.assertEqual(adapter.last_evidence.outcome, "failure")

    def test_invalid_prompt_is_rejected(self):
        adapter = self.adapter()
        with self.assertRaises(ProviderExecutionError) as caught:
            adapter("", 512)
        self.assertEqual(caught.exception.category, "invalid_request")


if __name__ == "__main__":
    unittest.main()
