"""Retired. The gemini client is `cns_interop.providers.gemini_complete`, reached through `uai.connect("gemini", model)`.

This module's adapter class called the provider with the standard library's default opener, which follows a redirect
and sends the API key to wherever it points. The replacement refuses redirects. Nothing is re-exported from here, so
that no caller keeps using the old class by accident.
"""

raise ImportError("uai2_gemini is retired: use uai.connect(\"gemini\", model), which is backed by "
                  "cns_interop.providers.gemini_complete (see docs/QUICKSTART.md)")
