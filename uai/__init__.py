"""uai: the Universal AI Interface.

    import uai
    model = uai.connect("gemini", "gemini-2.5-flash")   # the key is read from GEMINI_API_KEY

One provider layer (`cns_interop.providers`), one way in (`uai.connect`, or `uai.from_env`), two things to do with a
model: have it recommend toward a signed UAI-1 decision (`Connection.judge`), or use it for plain text behind the typed
contract (`Connection.model_provider`). A model is an untrusted advisor throughout: it recommends, the decider's policy
decides, a grant permits, a person approves. docs/QUICKSTART.md is the ten-minute guide.
"""

from .bridge import PORTABLE_MAX_OUTPUT_TOKENS, PortableTextProvider, ProviderExecutionError, ProviderResult
from .connect import PROVIDERS, Connection, connect, from_env
from .judge import PROVIDER_CALL, ProviderJudge
from .protocol import CompletionStatus, ModelProvider, ModelRequest, ModelResponse, TokenUsage

__all__ = ["connect", "from_env", "Connection", "PROVIDERS", "ProviderJudge", "PROVIDER_CALL", "PortableTextProvider",
           "ProviderResult", "ProviderExecutionError", "PORTABLE_MAX_OUTPUT_TOKENS", "CompletionStatus", "ModelProvider",
           "ModelRequest", "ModelResponse", "TokenUsage"]
