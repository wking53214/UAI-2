"""ed25519: signatures another process can check without sharing a secret.

WHY THIS EXISTS

Every proof CNS issued before this package was an HMAC under a process-local key (`super_gate._ISSUER_KEY`). An
HMAC proves origin only to someone who holds the key, so a SuperGate decision meant nothing outside the process that
made it. A system that wants to accept another system's decision, without becoming part of it, needs the opposite
property: the decider keeps a private key, publishes a public one, and anyone can check.

Ed25519 (RFC 8032) is that, and it is what every mainstream runtime ships (OpenSSL, Node's `crypto`, Go, Rust,
libsodium), so the system on the other end does not need CNS to check a CNS signature. The standard library has no
Ed25519, and the `cns` family takes no dependencies, so this is the RFC's own algorithm written out. The test suite
checks it against the RFC 8032 section 7.1 vectors and against Node's OpenSSL in both directions.

WHAT IT DOES NOT DO

It is not side-channel hardened. Python integers do not run in constant time, so a co-located attacker who can time
many signatures could in principle learn something about the key. Verification has no secret and is unaffected.
For production signing, hand `cns_interop.identity.Signer` a function backed by an HSM, an OS keystore or a
hardened library; the protocol does not care which signer produced a valid signature.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from typing import Optional, Tuple

__all__ = ["public_key", "sign", "verify", "acceptable", "SEED_BYTES", "PUBLIC_BYTES", "SIGNATURE_BYTES"]

SEED_BYTES = 32
PUBLIC_BYTES = 32
SIGNATURE_BYTES = 64

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

Point = Tuple[int, int, int, int]  # extended coordinates (X, Y, Z, T), x = X/Z, y = Y/Z, xy = T/Z


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _add(p: Point, q: Point) -> Point:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s: int, p: Point) -> Point:
    q: Point = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _equal(p: Point, q: Point) -> bool:
    if (p[0] * q[2] - q[0] * p[2]) % _P != 0:
        return False
    return (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _recover_x(y: int, sign: int) -> int:
    if y >= _P:
        raise ValueError("not a point: y is out of range")
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 == 0:
        if sign:
            raise ValueError("not a point: x is zero but its sign bit is set")
        return 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        raise ValueError("not a point: no square root")
    if (x & 1) != sign:
        x = _P - x
    return x


_IDENTITY: Point = (0, 1, 1, 0)
_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_G: Point = (_GX, _GY, 1, _GX * _GY % _P)


def _compress(p: Point) -> bytes:
    zinv = pow(p[2], _P - 2, _P)
    x, y = p[0] * zinv % _P, p[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes) -> Point:
    if len(s) != 32:
        raise ValueError("a point is 32 bytes")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return (x, y, 1, x * y % _P)


def _expand(seed: bytes) -> Tuple[int, bytes]:
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != SEED_BYTES:
        raise ValueError("an Ed25519 private key is a 32-byte seed")
    h = _sha512(bytes(seed))
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    """The 32-byte public key for a 32-byte seed."""
    a, _ = _expand(seed)
    return _compress(_mul(a, _G))


def sign(seed: bytes, message: bytes) -> bytes:
    """A 64-byte signature over `message`. Deterministic: the same seed and message always sign alike."""
    a, prefix = _expand(seed)
    pub = _compress(_mul(a, _G))
    r = int.from_bytes(_sha512(prefix + message), "little") % _L
    big_r = _compress(_mul(r, _G))
    k = int.from_bytes(_sha512(big_r + pub + message), "little") % _L
    s = (r + k * a) % _L
    return big_r + int.to_bytes(s, 32, "little")


@lru_cache(maxsize=4096)
def _public_point(public: bytes) -> Optional[Point]:
    """A public key's decoded point if it is canonical and not of small order, else None. A pure function of 32 bytes, so
    caching it cannot change an answer; it only stops a sender that reuses one key from making the receiver redo the
    expensive part for every message."""
    try:
        a = _decompress(public)
    except ValueError:
        return None
    if _equal(_mul(8, a), _IDENTITY):  # a small-order key (the identity among them) is "signed for" by anyone
        return None
    return a


def _parse(public: bytes, signature: bytes) -> Optional[Tuple[Point, Point, int]]:
    """The checks every UAI-1 implementation shares before any equation is tried: lengths, canonical points, a
    canonical s, and a public key that is not of small order. None means refuse."""
    try:
        if len(public) != PUBLIC_BYTES or len(signature) != SIGNATURE_BYTES:
            return None
        a = _public_point(bytes(public))
        if a is None:
            return None
        big_r = _decompress(bytes(signature[:32]))
        s = int.from_bytes(signature[32:], "little")
    except (ValueError, TypeError):
        return None
    if s >= _L:  # RFC 8032 5.1.7: refuse a non-canonical s, which would make one signature into many
        return None
    return a, big_r, s


def acceptable(public: bytes, signature: bytes) -> bool:
    """Whether `public` and `signature` pass the shared strict checks. A verifier built on another library (see
    crypto_backend.py) calls this first, so that the set of signatures it accepts is the same as this module's."""
    return _parse(public, signature) is not None


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """Whether `signature` is `public`'s signature over `message`. False, never an exception, for anything malformed.

    Stricter than the bare RFC equation in three ways every UAI-1 implementation shares: a public key or R that is not
    the canonical encoding of a curve point is refused, a non-canonical s is refused, and a public key of small order
    is refused (its signatures can be made without any private key)."""
    parsed = _parse(public, signature)
    if parsed is None:
        return False
    a, big_r, s = parsed
    k = int.from_bytes(_sha512(bytes(signature[:32]) + bytes(public) + message), "little") % _L
    return _equal(_mul(s, _G), _add(big_r, _mul(k, a)))
