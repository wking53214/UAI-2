"""Contract and boundary checks for the provider-neutral model interface."""

import subprocess
import sys
from dataclasses import FrozenInstanceError

import pytest

from uai.protocol import (
    CompletionStatus, ModelProvider, ModelRequest, ModelResponse, TokenUsage,
)


def request(**changes):
    values = {"model": "consumer-model-id", "system_instruction": "Be concise",
              "user_messages": ("Hello",), "max_output_tokens": 64,
              "generation_settings": {"temperature": 0.2}}
    values.update(changes)
    return ModelRequest(**values)


def response(**changes):
    values = {"content": "Hello back", "provider": "example",
              "model": "consumer-model-id",
              "completion_status": CompletionStatus.COMPLETE,
              "usage": TokenUsage(3, 2), "request_id": "req-1",
              "native_response": {"vendor_field": "retained"}}
    values.update(changes)
    return ModelResponse(**values)


def test_request_construction_and_settings_are_immutable():
    source = {"temperature": 0.2}
    item = request(generation_settings=source)
    source["temperature"] = 0.9
    assert item.model == "consumer-model-id"
    assert item.user_messages == ("Hello",)
    assert item.generation_settings["temperature"] == 0.2
    with pytest.raises(TypeError):
        item.generation_settings["temperature"] = 0.5
    with pytest.raises(FrozenInstanceError):
        item.model = "changed"


def test_response_construction_and_frozen_fields():
    native = {"vendor_field": "retained"}
    item = response(native_response=native)
    assert item.content == "Hello back" and item.provider == "example"
    assert item.usage == TokenUsage(3, 2) and item.request_id == "req-1"
    assert item.native_response is native
    with pytest.raises(FrozenInstanceError):
        item.content = "changed"
    with pytest.raises(FrozenInstanceError):
        item.usage.output_tokens = 8


@pytest.mark.parametrize("changes, error", [
    ({"model": " "}, ValueError), ({"user_messages": ()}, ValueError),
    ({"user_messages": ("ok", 2)}, ValueError), ({"max_output_tokens": 0}, ValueError),
    ({"max_output_tokens": True}, TypeError), ({"generation_settings": {" ": 1}}, ValueError),
    ({"generation_settings": {"x": []}}, TypeError),
])
def test_invalid_requests_are_rejected(changes, error):
    with pytest.raises(error):
        request(**changes)


def test_invalid_responses_and_usage_are_rejected():
    with pytest.raises(ValueError):
        response(provider="")
    with pytest.raises(TypeError):
        response(completion_status="complete")
    with pytest.raises(ValueError):
        TokenUsage(-1, 0)
    with pytest.raises(TypeError):
        TokenUsage(True, 0)


def test_fake_provider_satisfies_the_synchronous_protocol():
    class FakeProvider:
        def generate(self, request):
            assert isinstance(request, ModelRequest)
            return response()

    provider = FakeProvider()
    assert isinstance(provider, ModelProvider)
    assert provider.generate(request()).content == "Hello back"


def test_neutral_import_does_not_load_anthropic():
    result = subprocess.run(
        [sys.executable, "-c", "import sys; import uai.protocol; "
         "assert not any(n == 'anthropic' or n.startswith('anthropic.') for n in sys.modules)"],
        check=False, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
