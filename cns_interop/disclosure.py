"""disclosure: prove which document you mean while showing the other side only the fields it agreed to see.

WHY THIS EXISTS

A requester often holds more than the decider needs, or should hold. A screening agent may need an income figure and
a document type, and has no business receiving a name or an account number. But the decision it signs has to be tied
to one exact document, or it can be replayed against a different one with the same income.

Each field is committed separately: commitment = subject_digest({"field": name, "salt": salt, "value": value}),
with a fresh 128-bit salt per field so a short value (a yes/no, a small number) cannot be guessed back from its
commitment. The document's digest is subject_digest({"commitments": {name: commitment, ...}}) over every field.
The requester sends all the commitments and opens (salt and value) only the agreed fields. The decider recomputes
the digest from the commitments, checks each opening against its commitment, and signs a decision bound to that
digest. The undisclosed fields stay hidden, and the decision still names the whole document.

The digest is a CNS `Judged.digest`, so the same document can be judged by an in-process SuperGate and by a remote
agent and the two verdicts compared.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional

from cns.gate import subject_digest

from .envelope import Refused, check_profile

__all__ = ["Committed", "commit", "commitment", "root_of", "open_disclosure"]

_SALT = re.compile(r"\A[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


def commitment(name: str, salt: str, value: Any) -> str:
    return subject_digest({"field": name, "salt": salt, "value": value})


def root_of(commitments: Mapping[str, str]) -> str:
    return subject_digest({"commitments": dict(commitments)})


@dataclass(frozen=True)
class Committed:
    """A document committed field by field. Keep it private; send what `reveal` returns."""

    identity: str
    values: Mapping[str, Any]
    salts: Mapping[str, str]

    @property
    def commitments(self) -> Dict[str, str]:
        return {n: commitment(n, self.salts[n], v) for n, v in self.values.items()}

    @property
    def digest(self) -> str:
        return root_of(self.commitments)

    def reveal(self, names: Iterable[str]) -> Dict[str, Any]:
        """Every commitment, and the opening of exactly `names`."""
        names = sorted(set(names))
        missing = [n for n in names if n not in self.values]
        if missing:
            raise ValueError("the document has no field " + ", ".join(missing))
        return {"commitments": self.commitments,
                "disclosed": {n: {"salt": self.salts[n], "value": self.values[n]} for n in names}}


def commit(identity: str, values: Mapping[str, Any], salts: Optional[Mapping[str, str]] = None) -> Committed:
    """Commit a document's fields. `salts` is for reproducible test vectors only; leave it out otherwise."""
    if not isinstance(identity, str) or not identity:
        raise ValueError("a document needs an identity")
    if not values:
        raise ValueError("a document needs at least one field")
    check_profile(dict(values))
    chosen = dict(salts) if salts is not None else {n: secrets.token_hex(16) for n in values}
    if set(chosen) != set(values) or not all(isinstance(s, str) and _SALT.match(s) for s in chosen.values()):
        raise ValueError("every field needs its own 32-hex-digit salt")
    return Committed(identity=identity, values=dict(values), salts=chosen)


def open_disclosure(digest: str, presented: Mapping[str, Any], agreed: Iterable[str]) -> Dict[str, Any]:
    """Check a disclosure against the document digest and the agreed fields; return the disclosed values.

    Refused('disclosure') if the commitments do not produce `digest`, an opening does not match its commitment, an
    agreed field is not opened, or any field is opened that was NOT agreed. Over-disclosure is refused, not ignored:
    a decider that agreed not to receive a field must not end up holding it because a requester sent it anyway."""
    if not isinstance(presented, Mapping) or set(presented) != {"commitments", "disclosed"}:
        raise Refused("disclosure", "a disclosure is exactly commitments and disclosed")
    commitments, disclosed = presented["commitments"], presented["disclosed"]
    if not isinstance(commitments, Mapping) or not commitments or not all(
            isinstance(c, str) and _HEX64.match(c) for c in commitments.values()):
        raise Refused("disclosure", "commitments must map each field to a 64-hex-digit digest")
    if root_of(commitments) != digest:
        raise Refused("disclosure", "the commitments do not produce the document digest the terms name")
    if not isinstance(disclosed, Mapping):
        raise Refused("disclosure", "disclosed must be a mapping")
    agreed = set(agreed)
    extra, missing = set(disclosed) - agreed, agreed - set(disclosed)
    if extra:
        raise Refused("disclosure", "fields were disclosed that the terms do not allow: " + ", ".join(sorted(extra)))
    if missing:
        raise Refused("disclosure", "agreed fields were not disclosed: " + ", ".join(sorted(missing)))
    out: Dict[str, Any] = {}
    for name in sorted(agreed):
        opening = disclosed[name]
        if not isinstance(opening, Mapping) or set(opening) != {"salt", "value"} or not (
                isinstance(opening["salt"], str) and _SALT.match(opening["salt"])):
            raise Refused("disclosure", f"the opening of {name} is not exactly a 32-hex-digit salt and a value")
        if name not in commitments or commitment(name, opening["salt"], opening["value"]) != commitments[name]:
            raise Refused("disclosure", f"the opening of {name} does not match its commitment")
        out[name] = opening["value"]
    return out
