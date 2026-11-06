"""Provider-neutral bridge into the CNS typed model contract."""

from dataclasses import dataclass

from cns_composition.providers.protocol import (
    CompletionStatus,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    TokenUsage,
)

PORTABLE_MAX_OUTPUT_TOKENS = 512


class ProviderExecutionError(RuntimeError):
    """Sanitized, provider-neutral execution failure."""

    def __init__(self, category: str, reason: str):
        super().__init__(reason)
        self.category = category
        self.reason = reason


@dataclass(frozen=True)
class ProviderResult:
    """Normalized result produced by a provider-specific adapter."""

    content: str
    provider: str
    model: str
    completion_status: CompletionStatus
    usage: TokenUsage | None = None
    request_id: str | None = None
    native_response: object | None = None


class PortableTextProvider:
    """Bridge a bounded provider callable into the CNS typed contract."""

    def __init__(self, complete, provider: str, model: str):
        if not callable(complete):
            raise TypeError("complete must be callable")
        if not isinstance(provider, str) or not provider.strip():
            raise ValueError("provider must be a non-empty string")
        if not isinstance(model, str) or not model.strip():
            raise ValueError("model must be a non-empty string")

        self._complete = complete
        self._provider = provider
        self._model = model

    def generate(self, request: ModelRequest) -> ModelResponse:
        if not isinstance(request, ModelRequest):
            raise TypeError("request must be a ModelRequest")
        if request.model != self._model:
            raise ValueError("request model does not match configured provider model")
        if request.system_instruction:
            raise ValueError("portable profile does not support system instructions")
        if len(request.user_messages) != 1:
            raise ValueError("portable profile requires exactly one user message")
        if request.max_output_tokens != PORTABLE_MAX_OUTPUT_TOKENS:
            raise ValueError("portable profile requires exactly 512 output tokens")
        if request.generation_settings:
            raise ValueError("portable profile does not support generation settings")

        try:
            result = self._complete(
                request.user_messages[0],
                request.max_output_tokens,
            )
        except Exception as exc:
            category = getattr(exc, "category", getattr(exc, "code", "provider_error"))
            reason = getattr(exc, "reason", "provider completion failed")
            if not isinstance(category, str) or not category:
                category = "provider_error"
            if not isinstance(reason, str) or not reason:
                reason = "provider completion failed"
            raise ProviderExecutionError(category[:80], reason[:200]) from None

        # Temporary compatibility path for existing text-only callables.
        # New provider adapters must return ProviderResult.
        if isinstance(result, str):
            result = ProviderResult(
                content=result,
                provider=self._provider,
                model=self._model,
                completion_status=CompletionStatus.COMPLETE,
            )

        if not isinstance(result, ProviderResult):
            raise ProviderExecutionError(
                "invalid_response",
                "provider returned neither text nor ProviderResult",
            )

        if result.provider != self._provider or result.model != self._model:
            raise ProviderExecutionError(
                "identity_mismatch",
                "provider response identity did not match configuration",
            )

        try:
            return ModelResponse(
                content=result.content,
                provider=result.provider,
                model=result.model,
                completion_status=result.completion_status,
                usage=result.usage,
                request_id=result.request_id,
                native_response=result.native_response,
            )
        except (TypeError, ValueError):
            raise ProviderExecutionError(
                "invalid_response",
                "provider returned invalid normalized response fields",
            ) from None
