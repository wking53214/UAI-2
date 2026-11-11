"""Provider-neutral synchronous model request and response contracts.

This module defines data exchanged by consumers and provider adapters. It performs
no I/O and makes no authorization, routing, or model-selection decisions. Native
provider data is retained separately from normalized response content.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Mapping, Protocol, Tuple, Union, runtime_checkable

__all__ = ["CompletionStatus", "ModelRequest", "TokenUsage", "ModelResponse", "ModelProvider"]

GenerationValue = Union[str, int, float, bool, None]


class CompletionStatus(str, Enum):
    """Provider-neutral description of how generation ended."""

    COMPLETE = "complete"
    MAX_TOKENS = "max_tokens"
    STOPPED = "stopped"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ModelRequest:
    """Consumer-supplied input for one synchronous generation call."""

    model: str
    system_instruction: str
    user_messages: Tuple[str, ...]
    max_output_tokens: int
    generation_settings: Mapping[str, GenerationValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.model, str) or not self.model.strip():
            raise ValueError("model must be a non-empty string")
        if not isinstance(self.system_instruction, str):
            raise TypeError("system_instruction must be a string")
        if not isinstance(self.user_messages, tuple) or not self.user_messages:
            raise ValueError("user_messages must be a non-empty tuple of strings")
        if any(not isinstance(message, str) or not message.strip() for message in self.user_messages):
            raise ValueError("each user message must be a non-empty string")
        if isinstance(self.max_output_tokens, bool) or not isinstance(self.max_output_tokens, int):
            raise TypeError("max_output_tokens must be an integer")
        if self.max_output_tokens <= 0:
            raise ValueError("max_output_tokens must be positive")
        if not isinstance(self.generation_settings, Mapping):
            raise TypeError("generation_settings must be a mapping")
        settings = dict(self.generation_settings)
        for key, value in settings.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("generation setting names must be non-empty strings")
            if value is not None and not isinstance(value, (str, int, float, bool)):
                raise TypeError("generation setting values must be scalar values or None")
            if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
                raise ValueError("generation setting floats must be finite")
        object.__setattr__(self, "generation_settings", MappingProxyType(settings))


@dataclass(frozen=True)
class TokenUsage:
    """Input and output token counts when reported by a provider."""

    input_tokens: int
    output_tokens: int

    def __post_init__(self) -> None:
        for name, value in (("input_tokens", self.input_tokens), ("output_tokens", self.output_tokens)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
            if value < 0:
                raise ValueError(f"{name} must be non-negative")


@dataclass(frozen=True)
class ModelResponse:
    """Normalized response fields plus an explicitly separate native response."""

    content: str
    provider: str
    model: str
    completion_status: CompletionStatus
    usage: TokenUsage | None = None
    request_id: str | None = None
    native_response: object | None = None

    def __post_init__(self) -> None:
        for name, value in (("provider", self.provider), ("model", self.model)):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(self.content, str):
            raise TypeError("content must be a string")
        if not isinstance(self.completion_status, CompletionStatus):
            raise TypeError("completion_status must be a CompletionStatus")
        if self.usage is not None and not isinstance(self.usage, TokenUsage):
            raise TypeError("usage must be TokenUsage or None")
        if self.request_id is not None and (not isinstance(self.request_id, str) or not self.request_id.strip()):
            raise ValueError("request_id must be a non-empty string or None")


@runtime_checkable
class ModelProvider(Protocol):
    """Synchronous generation interface implemented by model-provider adapters."""

    def generate(self, request: ModelRequest) -> ModelResponse: ...
