import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from uai2_factory import create_provider
from uai2_bridge import ProviderExecutionError
from uai2_gemini import GeminiAdapter
from uai2_groq import GroqAdapter
from uai2_cloudflare import CloudflareAdapter
from cns_composition.providers.protocol import ModelRequest


class FailureHandler(BaseHTTPRequestHandler):
    status = 200
    raw_body = None

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)

        body = self.raw_body
        if body is None:
            body = json.dumps({
                "error": {"message": "private test detail"}
            }).encode()

        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class FactoryFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), FailureHandler
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

    def make_request(self, model):
        return ModelRequest(
            model=model,
            system_instruction="",
            user_messages=("failure conformance test",),
            max_output_tokens=512,
            generation_settings={},
        )

    def test_factory_failure_categories_match_across_providers(self):
        cases = [
            (401, None, "authentication"),
            (429, None, "rate_limit"),
            (200, b"{not-json", "invalid_response"),
        ]

        for provider_name in ("gemini", "groq", "cloudflare"):
            for status, raw_body, expected in cases:
                with self.subTest(
                    provider=provider_name,
                    status=status,
                    expected=expected,
                ):
                    FailureHandler.status = status
                    FailureHandler.raw_body = raw_body

                    model = (
                        "gemini-test-model"
                        if provider_name == "gemini"
                        else "groq-test-model"
                    )

                    if provider_name == "gemini":
                        model = "gemini-test-model"
                        adapter_patch = patch(
                            "uai2_factory.GeminiAdapter",
                            side_effect=lambda key, selected_model:
                                GeminiAdapter(
                                    key, selected_model,
                                    base_url=self.base_url,
                                ),
                        )
                        config = {
                            "UAI2_PROVIDER": "gemini",
                            "UAI2_MODEL": model,
                            "GEMINI_API_KEY": "stub-key",
                        }
                    elif provider_name == "groq":
                        model = "groq-test-model"
                        adapter_patch = patch(
                            "uai2_factory.GroqAdapter",
                            side_effect=lambda key, selected_model:
                                GroqAdapter(
                                    key, selected_model,
                                    base_url=self.base_url,
                                ),
                        )
                        config = {
                            "UAI2_PROVIDER": "groq",
                            "UAI2_MODEL": model,
                            "GROQ_API_KEY": "stub-key",
                        }
                    else:
                        model = "@cf/meta/llama-3.1-8b-instruct"
                        adapter_patch = patch(
                            "uai2_factory.CloudflareAdapter",
                            side_effect=lambda account, token, selected_model:
                                CloudflareAdapter(
                                    account, token, selected_model,
                                    base_url=self.base_url,
                                ),
                        )
                        config = {
                            "UAI2_PROVIDER": "cloudflare",
                            "UAI2_MODEL": model,
                            "CLOUDFLARE_ACCOUNT_ID": "stub-account",
                            "CLOUDFLARE_API_TOKEN": "stub-key",
                        }

                    with adapter_patch:
                        provider = create_provider(config)

                    adapter = provider._complete

                    with self.assertRaises(
                        ProviderExecutionError
                    ) as caught:
                        provider.generate(self.make_request(model))

                    self.assertEqual(caught.exception.category, expected)
                    self.assertEqual(
                        adapter.last_evidence.error_category,
                        expected,
                    )
                    self.assertEqual(
                        adapter.last_evidence.outcome,
                        "failure",
                    )

                    if status in (401, 429):
                        self.assertEqual(
                            adapter.last_evidence.http_status,
                            status,
                        )

                    self.assertNotIn(
                        "private test detail",
                        str(caught.exception),
                    )
                    self.assertNotIn(
                        "stub-key",
                        repr(adapter.last_evidence),
                    )


if __name__ == "__main__":
    unittest.main()
