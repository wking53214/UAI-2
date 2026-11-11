"""Configuration-driven provider selection for UAI-2."""

import os

from uai2_bridge import PortableTextProvider
from uai2_gemini import GeminiAdapter
from uai2_groq import GroqAdapter
from uai2_cloudflare import CloudflareAdapter


def create_provider(environ=None):
    """Build the configured provider behind the common CNS interface."""
    env = os.environ if environ is None else environ

    selected = env.get("UAI2_PROVIDER", "").strip().lower()
    model = env.get("UAI2_MODEL", "").strip()

    if selected not in ("gemini", "groq", "cloudflare"):
        raise ValueError("UAI2_PROVIDER must be gemini, groq, or cloudflare")

    if not model:
        raise ValueError("UAI2_MODEL is required")

    if selected == "cloudflare":
        account_id = env.get("CLOUDFLARE_ACCOUNT_ID", "")
        api_token = env.get("CLOUDFLARE_API_TOKEN", "")

        if not isinstance(account_id, str) or not account_id.strip():
            raise ValueError("CLOUDFLARE_ACCOUNT_ID is required")
        if not isinstance(api_token, str) or not api_token.strip():
            raise ValueError("CLOUDFLARE_API_TOKEN is required")

        adapter = CloudflareAdapter(account_id, api_token, model)
        return PortableTextProvider(
            adapter, "cloudflare-workers-ai", model
        )

    if selected == "gemini":
        key_name = "GEMINI_API_KEY"
        identity = "google-gemini"
        adapter_class = GeminiAdapter
    else:
        key_name = "GROQ_API_KEY"
        identity = "groq"
        adapter_class = GroqAdapter

    api_key = env.get(key_name, "")
    if not isinstance(api_key, str) or not api_key.strip():
        raise ValueError(key_name + " is required for selected provider")

    adapter = adapter_class(api_key, model)
    return PortableTextProvider(adapter, identity, model)
