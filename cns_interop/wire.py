"""wire: envelopes as JSON text, read strictly.

JSON is only how an envelope travels; the signature is over the CNS canonical digest, so formatting never matters
to it. Reading is strict where a lenient parser would let two implementations see different messages in the same
bytes: a duplicated key, a float, NaN or Infinity, or more than MAX_BYTES of text is refused before anything else
looks at it. One envelope per line (JSON Lines) is the framing the reference transports use.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

from .envelope import MAX_INT, Envelope, Refused

__all__ = ["MAX_BYTES", "dumps", "loads"]

MAX_BYTES = 1 << 20


def _no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise Refused("malformed", f"the key {k!r} appears twice, and receivers would disagree on which counts")
        out[k] = v
    return out


def _no_float(text: str) -> Any:
    raise Refused("profile", f"the number {text} is a float; UAI-1 carries integers only")


def _bounded_int(text: str) -> int:
    """An integer outside +/-(2**53 - 1) is refused while reading, as the Node reader does, not only later when the
    envelope's profile is checked: a reader of any other kind of job (act.py's) must not see a number another
    implementation would have refused."""
    value = int(text)
    if not -MAX_INT <= value <= MAX_INT:
        raise Refused("profile", "an integer outside +/-(2**53 - 1), which not every runtime can represent exactly")
    return value


def _no_constant(text: str) -> Any:
    raise Refused("malformed", f"{text} is not a JSON value")


def dumps(envelope: Envelope) -> str:
    """One line of JSON. Keys sorted, no insignificant spaces, non-ASCII kept as UTF-8."""
    return json.dumps(envelope.to_wire(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def loads(text: "str | bytes | bytearray", *, max_bytes: int = MAX_BYTES) -> Dict[str, Any]:
    """Parse one envelope's JSON. The result still has to pass `open_envelope` before anything trusts it."""
    if isinstance(text, (bytes, bytearray)):
        if len(text) > min(max_bytes, MAX_BYTES):
            raise Refused("malformed", f"the message is larger than {min(max_bytes, MAX_BYTES)} bytes")
        try:
            text = bytes(text).decode("utf-8")
        except UnicodeDecodeError:
            raise Refused("malformed", "the message is not UTF-8") from None
    if not isinstance(text, str):
        raise Refused("malformed", "the message is not text")
    if len(text.encode("utf-8", "surrogatepass")) > min(max_bytes, MAX_BYTES):
        raise Refused("malformed", f"the message is larger than {min(max_bytes, MAX_BYTES)} bytes")
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_float=_no_float, parse_int=_bounded_int,
                           parse_constant=_no_constant)
    except json.JSONDecodeError as exc:
        raise Refused("malformed", f"the message is not JSON ({exc.msg})") from None
    except RecursionError:
        raise Refused("malformed", "the message nests too deeply to read") from None
    except ValueError as exc:  # e.g. an integer too long for the interpreter to convert
        raise Refused("profile", f"the message holds a value that cannot be read ({exc})") from None
    if not isinstance(value, dict):
        raise Refused("malformed", "the message is not a JSON object")
    return value
