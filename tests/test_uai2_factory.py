import unittest
from unittest.mock import patch

from uai.protocol import (
    CompletionStatus,
    ModelRequest,
    ModelResponse,
)
from uai2_bridge import ProviderResult
from uai2_factory import create_provider
import uai2_factory


def make_request(model):
    return ModelRequest(
        model=model,
        system_instruction="",
        user_messages=("factory portability test",),
        max_output_tokens=512,
        generation_settings={},
    )


class FactoryTests(unittest.TestCase):

    def test_gemini_selection_uses_common_interface(self):
        model = "gemini-test-model"

        def complete(prompt, limit):
            return ProviderResult(
                content="common response",
                provider="google-gemini",
                model=model,
                completion_status=CompletionStatus.COMPLETE,
            )

        with patch("uai2_factory.GeminiAdapter", return_value=complete) as adapter:
            provider = create_provider({
                "UAI2_PROVIDER": "gemini",
                "UAI2_MODEL": model,
                "GEMINI_API_KEY": "test-secret",
            })

        adapter.assert_called_once_with("test-secret", model)
        response = provider.generate(make_request(model))
        self.assertIsInstance(response, ModelResponse)
        self.assertEqual(response.provider, "google-gemini")
        self.assertEqual(response.content, "common response")

    def test_groq_selection_uses_common_interface(self):
        model = "groq-test-model"

        def complete(prompt, limit):
            return ProviderResult(
                content="common response",
                provider="groq",
                model=model,
                completion_status=CompletionStatus.COMPLETE,
            )

        with patch("uai2_factory.GroqAdapter", return_value=complete) as adapter:
            provider = create_provider({
                "UAI2_PROVIDER": "groq",
                "UAI2_MODEL": model,
                "GROQ_API_KEY": "test-secret",
            })

        adapter.assert_called_once_with("test-secret", model)
        response = provider.generate(make_request(model))
        self.assertIsInstance(response, ModelResponse)
        self.assertEqual(response.provider, "groq")
        self.assertEqual(response.content, "common response")

    def test_cloudflare_selection_uses_common_interface(self):
        model = "@cf/meta/llama-3.1-8b-instruct"

        def complete(prompt, limit):
            return ProviderResult(
                content="common response",
                provider="cloudflare-workers-ai",
                model=model,
                completion_status=CompletionStatus.COMPLETE,
            )

        with patch(
            "uai2_factory.CloudflareAdapter",
            return_value=complete,
        ) as adapter:
            provider = create_provider({
                "UAI2_PROVIDER": "cloudflare",
                "UAI2_MODEL": model,
                "CLOUDFLARE_ACCOUNT_ID": "test-account",
                "CLOUDFLARE_API_TOKEN": "test-secret",
            })

        adapter.assert_called_once_with(
            "test-account", "test-secret", model
        )
        response = provider.generate(make_request(model))
        self.assertIsInstance(response, ModelResponse)
        self.assertEqual(response.provider, "cloudflare-workers-ai")
        self.assertEqual(response.content, "common response")

    def test_cloudflare_missing_account_id_rejected(self):
        with self.assertRaisesRegex(ValueError, "CLOUDFLARE_ACCOUNT_ID"):
            create_provider({
                "UAI2_PROVIDER": "cloudflare",
                "UAI2_MODEL": "test-model",
                "CLOUDFLARE_API_TOKEN": "test-secret",
            })

    def test_cloudflare_missing_api_token_rejected(self):
        with self.assertRaisesRegex(ValueError, "CLOUDFLARE_API_TOKEN"):
            create_provider({
                "UAI2_PROVIDER": "cloudflare",
                "UAI2_MODEL": "test-model",
                "CLOUDFLARE_ACCOUNT_ID": "test-account",
            })

    def test_missing_provider_rejected(self):
        with self.assertRaisesRegex(ValueError, "UAI2_PROVIDER"):
            create_provider({})

    def test_unsupported_provider_rejected(self):
        with self.assertRaisesRegex(ValueError, "UAI2_PROVIDER"):
            create_provider({"UAI2_PROVIDER": "unknown"})

    def test_missing_model_rejected(self):
        with self.assertRaisesRegex(ValueError, "UAI2_MODEL"):
            create_provider({
                "UAI2_PROVIDER": "gemini",
                "GEMINI_API_KEY": "test-secret",
            })

    def test_missing_selected_key_rejected(self):
        with self.assertRaisesRegex(ValueError, "GROQ_API_KEY"):
            create_provider({
                "UAI2_PROVIDER": "groq",
                "UAI2_MODEL": "test-model",
            })


if __name__ == "__main__":
    unittest.main()
