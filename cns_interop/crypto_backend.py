"""crypto_backend: which implementation of Ed25519 signs and verifies, chosen explicitly and never swapped silently.

TWO BACKENDS, ONE SET OF ACCEPTED SIGNATURES

  pure          cns_interop.ed25519, the RFC written out in Python. No dependency. Not constant time (see ed25519.py).
  cryptography  the `cryptography` package, which delegates to OpenSSL. An optional extra: `pip install cns[crypto]`.

Verification on EITHER backend first runs the strict checks every UAI-1 implementation shares (`ed25519.acceptable`:
canonical points, canonical s, no small-order key), because OpenSSL on its own accepts some encodings the protocol
refuses. After that the library's equation decides. A differential test (test_crypto_backend.py) runs both backends
over the RFC 8032 vectors, the shared UAI vectors and a corpus of mutated and malformed signatures and requires the
same answer, byte for byte, from each. Signatures are deterministic in both, so a signature made by one verifies
under the other and the wire format does not change.

CHOOSING

  UAI_CRYPTO_BACKEND=pure           the default, which is what every release before this one did
  UAI_CRYPTO_BACKEND=cryptography   required: if the package is missing the import FAILS. There is no fallback.
  UAI_PROFILE=production            a local signing seed is refused on the pure backend. A production deployment
                                    signs with the cryptography backend, or hands `Signer.external` a keystore or HSM
                                    function. It never gets a quiet downgrade.

FROZEN FOR THE LIFE OF THE PROCESS (revision 4)

  * The profile is read from UAI_PROFILE ONCE, at first use, and never again; changing the variable later does nothing.
  * Under the production profile the backend must be NAMED (UAI_CRYPTO_BACKEND set to `cryptography`; there is no default and
    `pure` is refused), the first use freezes it, and `use()` raises: a running process cannot be talked into another backend.
  * Outside production `use()` still works until `freeze()` is called, which the benchmark and tests rely on.
  * `diagnostics()` reports the profile, the backend actually in force and whether it is frozen, so an operator can verify
    the approved configuration instead of trusting it.

WHAT THIS DOES NOT CLAIM

That the cryptography backend is side-channel resistant. It delegates to a widely used, maintained library whose
Ed25519 is built for constant-time operation; no timing or fault-injection measurement was made here, and the
protocol's own safety does not depend on one. Key material still exists in this process's memory while it signs.
Where that is unacceptable, keep the key in an HSM or keystore and use `Signer.external`.
"""

from __future__ import annotations

import os
from typing import Optional, Protocol

from . import ed25519

__all__ = ["ALGORITHM", "ALGORITHMS", "Backend", "PureBackend", "CryptographyBackend", "use", "current", "production",
           "freeze", "diagnostics", "public_key", "sign", "verify"]

ALGORITHM = "ed25519"
#: The only algorithm UAI-1 defines. An identity names its algorithm (`uai:ed25519:...`); anything else is refused,
#: never mapped onto this one, so a message cannot be steered onto a weaker primitive.
ALGORITHMS = frozenset({ALGORITHM})


class Backend(Protocol):
    name: str

    def public_key(self, seed: bytes) -> bytes: ...

    def sign(self, seed: bytes, message: bytes) -> bytes: ...

    def verify(self, public: bytes, message: bytes, signature: bytes) -> bool: ...


class PureBackend:
    name = "pure"

    def public_key(self, seed: bytes) -> bytes:
        return ed25519.public_key(seed)

    def sign(self, seed: bytes, message: bytes) -> bytes:
        return ed25519.sign(seed, message)

    def verify(self, public: bytes, message: bytes, signature: bytes) -> bool:
        return ed25519.verify(public, message, signature)


class CryptographyBackend:
    name = "cryptography"

    def __init__(self) -> None:
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        except ImportError:
            raise RuntimeError("the cryptography backend was requested and the `cryptography` package is not "
                               "installed (pip install 'cns[crypto]'); there is no fallback") from None
        self._invalid, self._ser = InvalidSignature, serialization
        self._priv, self._pub = Ed25519PrivateKey, Ed25519PublicKey

    def public_key(self, seed: bytes) -> bytes:
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != ed25519.SEED_BYTES:
            raise ValueError("an Ed25519 private key is a 32-byte seed")
        key = self._priv.from_private_bytes(bytes(seed)).public_key()
        return key.public_bytes(self._ser.Encoding.Raw, self._ser.PublicFormat.Raw)

    def sign(self, seed: bytes, message: bytes) -> bytes:
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != ed25519.SEED_BYTES:
            raise ValueError("an Ed25519 private key is a 32-byte seed")
        return self._priv.from_private_bytes(bytes(seed)).sign(message)

    def verify(self, public: bytes, message: bytes, signature: bytes) -> bool:
        if not ed25519.acceptable(public, signature):  # the shared strict checks come first, as on every backend
            return False
        try:
            self._pub.from_public_bytes(bytes(public)).verify(bytes(signature), message)
        except (self._invalid, ValueError):
            return False
        return True


_current: Optional[Backend] = None
_profile: Optional[str] = None
_frozen = False


def _select(name: str) -> Backend:
    if name == "pure":
        return PureBackend()
    if name == "cryptography":
        return CryptographyBackend()
    raise ValueError(f"unknown crypto backend {name!r}: expected 'pure' or 'cryptography'")


def production() -> bool:
    """True under the production profile. UAI_PROFILE is read once; a later change to it is ignored."""
    global _profile
    if _profile is None:
        _profile = os.environ.get("UAI_PROFILE", "")
    return _profile == "production"


def freeze() -> Backend:
    """Pin the backend now. After this, `use()` raises for the rest of the process."""
    global _frozen
    backend = current()
    _frozen = True
    return backend


def use(name: str) -> Backend:
    """Choose the backend for this process. An unknown name, or a missing package, raises: nothing is substituted.

    Refused once the process is frozen, and always under the production profile (configure it with UAI_CRYPTO_BACKEND at start)."""
    global _current
    if production():
        raise RuntimeError("the production profile fixes the cryptographic backend at start-up (UAI_CRYPTO_BACKEND); "
                           "it cannot be changed in a running process")
    if _frozen and (_current is None or _current.name != name):
        raise RuntimeError("the cryptographic backend is frozen for this process and cannot be changed")
    _current = _select(name)
    return _current


def current() -> Backend:
    global _current, _frozen
    if _current is None:
        if production():
            name = os.environ.get("UAI_CRYPTO_BACKEND", "")
            if name != "cryptography":
                raise RuntimeError("the production profile needs UAI_CRYPTO_BACKEND=cryptography, named explicitly "
                                   f"(got {name or 'nothing'!r}); there is no default and no fallback")
            _current = _select(name)
            _frozen = True
        else:
            _current = _select(os.environ.get("UAI_CRYPTO_BACKEND", "pure"))
    return _current


def diagnostics() -> dict:
    """What is actually in force, for an operator to compare with what was approved. Reads nothing secret."""
    backend = current()
    return {"algorithm": ALGORITHM, "backend": backend.name, "profile": "production" if production() else "default",
            "frozen": _frozen, "constant_time_claimed": False}


def public_key(seed: bytes) -> bytes:
    return current().public_key(seed)


def sign(seed: bytes, message: bytes) -> bytes:
    if production() and current().name == "pure":
        raise RuntimeError("a production profile does not sign with the pure-Python backend; select the cryptography "
                           "backend or use Signer.external with a keystore or HSM")
    return current().sign(seed, message)


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    return current().verify(public, message, signature)
