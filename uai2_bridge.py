"""Moved. The bridge is `uai.bridge`; this module keeps the old import path working and holds no code of its own."""

from uai.bridge import PORTABLE_MAX_OUTPUT_TOKENS, PortableTextProvider, ProviderExecutionError, ProviderResult

__all__ = ["PORTABLE_MAX_OUTPUT_TOKENS", "PortableTextProvider", "ProviderExecutionError", "ProviderResult"]
