import unittest

from cns_composition.providers.protocol import (
    CompletionStatus,
    ModelProvider,
    ModelRequest,
    ModelResponse,
)
from uai2_bridge import (
    PORTABLE_MAX_OUTPUT_TOKENS,
    PortableTextProvider,
    ProviderExecutionError,
)


MODEL = "test-model"


def request(**changes):
    values = {
        "model": MODEL,
        "system_instruction": "",
        "user_messages": ("hello provider",),
        "max_output_tokens": PORTABLE_MAX_OUTPUT_TOKENS,
        "generation_settings": {},
    }
    values.update(changes)
    return ModelRequest(**values)


class BridgeTests(unittest.TestCase):
    def make_provider(self, complete=None, **kwargs):
        return PortableTextProvider(
            complete or (lambda prompt, limit: "common response"),
            "test-provider",
            MODEL,
            **kwargs,
        )

    def test_structural_model_provider_conformance(self):
        self.assertIsInstance(self.make_provider(), ModelProvider)

    def test_common_response_shape(self):
        response = self.make_provider().generate(request())
        self.assertIsInstance(response, ModelResponse)
        self.assertEqual(response.content, "common response")
        self.assertEqual(response.provider, "test-provider")
        self.assertEqual(response.model, MODEL)
        self.assertEqual(response.completion_status, CompletionStatus.COMPLETE)

    def test_only_one_user_message_is_passed(self):
        received = []
        provider = self.make_provider(lambda prompt, limit: received.append((prompt, limit)) or "ok")
        provider.generate(request())
        self.assertEqual(received, [("hello provider", 512)])

    def test_system_instruction_rejected(self):
        with self.assertRaisesRegex(ValueError, "system instructions"):
            self.make_provider().generate(request(system_instruction="Be concise"))

    def test_multiple_messages_rejected(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.make_provider().generate(
                request(user_messages=("first", "second"))
            )

    def test_wrong_token_limit_rejected(self):
        with self.assertRaisesRegex(ValueError, "512"):
            self.make_provider().generate(request(max_output_tokens=256))

    def test_generation_settings_rejected(self):
        with self.assertRaisesRegex(ValueError, "generation settings"):
            self.make_provider().generate(
                request(generation_settings={"temperature": 0.2})
            )

    def test_wrong_model_rejected(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.make_provider().generate(request(model="other-model"))

    def test_provider_failure_normalized(self):
        class Refused(Exception):
            code = "rate_limit"
            reason = "provider rate limit"

        def fail(prompt, limit):
            raise Refused()

        with self.assertRaises(ProviderExecutionError) as caught:
            self.make_provider(fail).generate(request())

        self.assertEqual(caught.exception.category, "rate_limit")
        self.assertEqual(caught.exception.reason, "provider rate limit")

    def test_non_text_response_rejected(self):
        with self.assertRaises(ProviderExecutionError) as caught:
            self.make_provider(lambda prompt, limit: {"text": "not plain text"}).generate(
                request()
            )
        self.assertEqual(caught.exception.category, "invalid_response")

    def test_token_limit_is_forwarded_to_provider(self):
        received = []
        provider = self.make_provider(
            lambda prompt, limit: received.append(limit) or "ok"
        )
        provider.generate(request())
        self.assertEqual(received, [512])



    def test_structured_result_preserves_completion_metadata(self):
        from uai2_bridge import ProviderResult
        from cns_composition.providers.protocol import TokenUsage

        usage = TokenUsage(3, 7)
        native = {"finish_reason": "length"}
        result = ProviderResult(
            "partial answer", "test-provider", MODEL,
            CompletionStatus.MAX_TOKENS, usage, "request-123", native
        )
        provider = PortableTextProvider(
            lambda prompt, limit: result, "test-provider", MODEL
        )
        response = provider.generate(request())

        self.assertEqual(response.content, "partial answer")
        self.assertEqual(response.completion_status, CompletionStatus.MAX_TOKENS)
        self.assertEqual(response.usage, usage)
        self.assertEqual(response.request_id, "request-123")
        self.assertEqual(response.native_response, native)

    def test_structured_result_rejects_identity_mismatch(self):
        from uai2_bridge import ProviderResult

        result = ProviderResult(
            "answer", "different-provider", MODEL, CompletionStatus.COMPLETE
        )
        provider = PortableTextProvider(
            lambda prompt, limit: result, "test-provider", MODEL
        )

        with self.assertRaises(ProviderExecutionError) as caught:
            provider.generate(request())

        self.assertEqual(caught.exception.category, "identity_mismatch")


if __name__ == "__main__":
    unittest.main(verbosity=2)
