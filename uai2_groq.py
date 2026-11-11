"""Retired. The groq client is `cns_interop.providers.groq_complete`, reached through `uai.connect("groq", model)`.

This module's adapter class called the provider with the standard library's default opener, which follows a redirect
and sends the API key to wherever it points. The replacement refuses redirects. Nothing is re-exported from here, so
that no caller keeps using the old class by accident.
"""

raise ImportError("uai2_groq is retired: use uai.connect(\"groq\", model), which is backed by "
                  "cns_interop.providers.groq_complete (see docs/QUICKSTART.md)")
