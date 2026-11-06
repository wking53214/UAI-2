"""UAI-2 Gemini HTTP adapter; stdlib only."""

import hashlib
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from cns_composition.providers.protocol import CompletionStatus, TokenUsage
from uai2_bridge import ProviderExecutionError, ProviderResult


@dataclass(frozen=True)
class GeminiExecutionEvidence:
    provider: str
    model_requested: str
    model_reported: str | None
    request_sha256: str
    response_sha256: str | None
    latency_ms: int
    finish_reason: str
    request_id: str | None
    outcome: str = "success"
    error_category: str | None = None
    http_status: int | None = None


class GeminiAdapter:
    def __init__(self, api_key, model, *, base_url="https://generativelanguage.googleapis.com", timeout_s=30):
        if not isinstance(api_key, str) or not api_key.strip():
            raise ValueError("Gemini API key is required")
        if not isinstance(model, str) or not model.strip():
            raise ValueError("Gemini model is required")
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s
        self.last_evidence = None

    def __call__(self, prompt, max_output_tokens):
        body = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": max_output_tokens},
        }
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        request_hash = hashlib.sha256(encoded).hexdigest()
        started = time.perf_counter()
        self.last_evidence = None
        self._response_hash = None
        try:
            return self._execute(prompt, max_output_tokens)
        except ProviderExecutionError as exc:
            self.last_evidence = GeminiExecutionEvidence(
                "google-gemini", self._model, None, request_hash, self._response_hash,
                int((time.perf_counter() - started) * 1000), "ERROR", None,
                "failure", exc.category, getattr(exc, "http_status", None),
            )
            raise

    def _execute(self, prompt, max_output_tokens):
        body = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": max_output_tokens},
        }
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        request_hash = hashlib.sha256(encoded).hexdigest()
        url = f"{self._base_url}/v1beta/models/{self._model}:generateContent"
        req = urllib.request.Request(
            url,
            data=encoded,
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": self._api_key,
            },
            method="POST",
        )
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self._timeout_s) as response:
                raw = response.read(2_000_001)
                if len(raw) > 2_000_000:
                    raise ProviderExecutionError("response_too_large", "Gemini response exceeded size limit")
                status = response.status
                response_headers = response.headers
        except urllib.error.HTTPError as exc:
            category = {401: "authentication", 403: "permission", 429: "rate_limit"}.get(exc.code, "http_error")
            error = ProviderExecutionError(category, f"Gemini HTTP status {exc.code}")
            error.http_status = exc.code
            raise error from None
        except urllib.error.URLError:
            raise ProviderExecutionError("connection_error", "Gemini connection failed") from None
        except TimeoutError:
            raise ProviderExecutionError("timeout", "Gemini request timed out") from None

        latency = int((time.perf_counter() - started) * 1000)
        if not 200 <= status < 300:
            raise ProviderExecutionError("http_error", f"Gemini HTTP status {status}")

        response_hash = hashlib.sha256(raw).hexdigest()
        self._response_hash = response_hash
        try:
            data = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProviderExecutionError("invalid_response", "Gemini returned invalid JSON") from None
        if not isinstance(data, dict):
            raise ProviderExecutionError("invalid_response", "Gemini response was not an object")

        candidates = data.get("candidates")
        if not isinstance(candidates, list) or not candidates or not isinstance(candidates[0], dict):
            raise ProviderExecutionError("invalid_response", "Gemini returned no candidate")
        candidate = candidates[0]
        content_obj = candidate.get("content")
        parts = content_obj.get("parts") if isinstance(content_obj, dict) else None
        if not isinstance(parts, list):
            raise ProviderExecutionError("invalid_response", "Gemini candidate had no parts")
        texts = [part.get("text") for part in parts if isinstance(part, dict) and isinstance(part.get("text"), str)]
        if not texts:
            raise ProviderExecutionError("invalid_response", "Gemini candidate contained no text")

        finish = candidate.get("finishReason")
        if not isinstance(finish, str) or not finish:
            finish = "UNKNOWN"
        status_map = {
            "STOP": CompletionStatus.COMPLETE,
            "MAX_TOKENS": CompletionStatus.MAX_TOKENS,
            "SAFETY": CompletionStatus.STOPPED,
            "RECITATION": CompletionStatus.STOPPED,
            "BLOCKLIST": CompletionStatus.STOPPED,
            "PROHIBITED_CONTENT": CompletionStatus.STOPPED,
            "SPII": CompletionStatus.STOPPED,
        }
        completion_status = status_map.get(finish, CompletionStatus.UNKNOWN)

        usage = None
        metadata = data.get("usageMetadata")
        if isinstance(metadata, dict):
            incoming = metadata.get("promptTokenCount")
            outgoing = metadata.get("candidatesTokenCount")
            if isinstance(incoming, int) and not isinstance(incoming, bool) and incoming >= 0 and isinstance(outgoing, int) and not isinstance(outgoing, bool) and outgoing >= 0:
                usage = TokenUsage(incoming, outgoing)

        reported_model = data.get("modelVersion")
        request_id = data.get("responseId")
        self.last_evidence = GeminiExecutionEvidence(
            "google-gemini", self._model,
            reported_model if isinstance(reported_model, str) else None,
            request_hash, response_hash, latency, finish,
            request_id if isinstance(request_id, str) else None,
        )
        return ProviderResult(
            content="".join(texts),
            provider="google-gemini",
            model=self._model,
            completion_status=completion_status,
            usage=usage,
            request_id=request_id if isinstance(request_id, str) and request_id else None,
            native_response={
                "finish_reason": finish,
                "model_version": reported_model if isinstance(reported_model, str) else None,
            },
        )
