"""UAI-2 native Cloudflare Workers AI adapter; stdlib only."""

import hashlib
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from cns_composition.providers.protocol import CompletionStatus
from uai2_bridge import ProviderExecutionError, ProviderResult


@dataclass(frozen=True)
class CloudflareExecutionEvidence:
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


class CloudflareAdapter:
    MAX_RESPONSE_BYTES = 2_000_000

    def __init__(
        self,
        account_id,
        api_token,
        model,
        *,
        base_url="https://api.cloudflare.com/client/v4",
        timeout_s=45,
    ):
        for value, label in (
            (account_id, "Cloudflare account ID"),
            (api_token, "Cloudflare API token"),
            (model, "Cloudflare model"),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(label + " is required")

        self._account_id = account_id.strip()
        self._api_token = api_token
        self._model = model.strip()
        self._base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s
        self.last_evidence = None
        self._response_hash = None

    def __call__(self, prompt, max_output_tokens):
        if not isinstance(prompt, str) or not prompt:
            raise ProviderExecutionError(
                "invalid_request", "Cloudflare prompt must be non-empty text"
            )
        if (
            not isinstance(max_output_tokens, int)
            or isinstance(max_output_tokens, bool)
            or max_output_tokens < 1
        ):
            raise ProviderExecutionError(
                "invalid_request", "Cloudflare output token limit is invalid"
            )

        body = {
            "prompt": prompt,
            "max_tokens": max_output_tokens,
        }
        encoded = json.dumps(
            body, sort_keys=True, separators=(",", ":")
        ).encode()
        request_hash = hashlib.sha256(encoded).hexdigest()
        started = time.perf_counter()
        self.last_evidence = None
        self._response_hash = None

        try:
            return self._execute(encoded, request_hash)
        except ProviderExecutionError as exc:
            self.last_evidence = CloudflareExecutionEvidence(
                "cloudflare-workers-ai",
                self._model,
                None,
                request_hash,
                self._response_hash,
                int((time.perf_counter() - started) * 1000),
                "ERROR",
                None,
                "failure",
                exc.category,
                getattr(exc, "http_status", None),
            )
            raise

    def _execute(self, encoded, request_hash):
        url = (
            f"{self._base_url}/accounts/{self._account_id}"
            f"/ai/run/{self._model}"
        )
        req = urllib.request.Request(
            url,
            data=encoded,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_token}",
                "User-Agent": "STACK-UAI2-Provider/1.0",
            },
            method="POST",
        )

        started = time.perf_counter()
        try:
            with urllib.request.urlopen(
                req, timeout=self._timeout_s
            ) as response:
                raw = response.read(self.MAX_RESPONSE_BYTES + 1)
                if len(raw) > self.MAX_RESPONSE_BYTES:
                    raise ProviderExecutionError(
                        "response_too_large",
                        "Cloudflare response exceeded size limit",
                    )
                status = response.status
                request_id = response.headers.get("cf-ray")
        except urllib.error.HTTPError as exc:
            category = {
                401: "authentication",
                403: "permission",
                429: "rate_limit",
            }.get(exc.code, "http_error")
            error = ProviderExecutionError(
                category, f"Cloudflare HTTP status {exc.code}"
            )
            error.http_status = exc.code
            raise error from None
        except urllib.error.URLError:
            raise ProviderExecutionError(
                "connection_error", "Cloudflare connection failed"
            ) from None
        except TimeoutError:
            raise ProviderExecutionError(
                "timeout", "Cloudflare request timed out"
            ) from None

        if not 200 <= status < 300:
            raise ProviderExecutionError(
                "http_error", f"Cloudflare HTTP status {status}"
            )

        self._response_hash = hashlib.sha256(raw).hexdigest()
        try:
            data = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProviderExecutionError(
                "invalid_response", "Cloudflare returned invalid JSON"
            ) from None

        if not isinstance(data, dict):
            raise ProviderExecutionError(
                "invalid_response", "Cloudflare response was not an object"
            )

        if data.get("success") is not True:
            raise ProviderExecutionError(
                "provider_error", "Cloudflare reported an unsuccessful inference"
            )

        result = data.get("result")
        content = result.get("response") if isinstance(result, dict) else None
        if not isinstance(content, str) or not content.strip():
            raise ProviderExecutionError(
                "invalid_response", "Cloudflare returned no text response"
            )

        latency = int((time.perf_counter() - started) * 1000)
        self.last_evidence = CloudflareExecutionEvidence(
            "cloudflare-workers-ai",
            self._model,
            None,
            request_hash,
            self._response_hash,
            latency,
            "UNKNOWN",
            request_id if isinstance(request_id, str) else None,
        )

        return ProviderResult(
            content=content,
            provider="cloudflare-workers-ai",
            model=self._model,
            completion_status=CompletionStatus.COMPLETE,
            request_id=request_id if isinstance(request_id, str) else None,
            native_response={
                "model_reported": None,
                "finish_reason": "UNKNOWN",
            },
        )
