"""limits: what a receiver spends on a message before it knows who sent it.

An unauthenticated sender costs the receiver parsing, a signature check and, before this module, a signed reply. None of
that is weakened here. These controls make the cost bounded and give the receiver a way to say no cheaply:

  Limits        the largest message a receiver reads (`max_bytes`, applied while reading) and the most values it counts
                in one (`max_nodes`, applied before the signature). The wire ceiling of 1 MiB stays the protocol's; a
                receiver may set its own lower. Measured before this: a 1 MiB list of small integers cost 621 ms.
  RateLimiter   token buckets, one global and one per claimed sender, checked FIRST. The claimed sender is not yet
                authenticated, so an attacker can rotate it: the global bucket is the one that holds. State is bounded
                (`max_senders`), so the limiter itself cannot be used to exhaust memory.

Both are the receiver's own policy. Neither is on the wire, and a receiver that sets none behaves as before.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Dict, Optional

from .envelope import now_ms

__all__ = ["Limits", "TokenBucket", "RateLimiter"]


@dataclass(frozen=True)
class Limits:
    max_bytes: int = 65_536
    max_nodes: int = 20_000

    def __post_init__(self) -> None:
        for name in ("max_bytes", "max_nodes"):
            v = getattr(self, name)
            if isinstance(v, bool) or not isinstance(v, int) or v < 1:
                raise ValueError(f"{name} is a positive integer")


class TokenBucket:
    """`rate_per_s` tokens a second, at most `burst` stored. `take()` is True when a token was available."""

    def __init__(self, rate_per_s: float, burst: int, clock: Callable[[], int] = now_ms) -> None:
        if rate_per_s <= 0 or burst < 1:
            raise ValueError("a bucket needs a positive rate and a burst of at least 1")
        self._rate, self._burst, self._clock = rate_per_s, burst, clock
        self._tokens, self._at = float(burst), clock()

    def take(self) -> bool:
        t = self._clock()
        self._tokens = min(self._burst, self._tokens + max(0, t - self._at) * self._rate / 1000.0)
        self._at = t
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


class RateLimiter:
    def __init__(self, *, global_rate: float, global_burst: int, sender_rate: float, sender_burst: int,
                 max_senders: int = 10_000, clock: Callable[[], int] = now_ms) -> None:
        self._global = TokenBucket(global_rate, global_burst, clock)
        self._rate, self._burst, self._clock, self._max = sender_rate, sender_burst, clock, max_senders
        self._senders: "OrderedDict[str, TokenBucket]" = OrderedDict()
        self._lock = threading.Lock()
        self.limited_global = 0
        self.limited_sender = 0

    def allow(self, claimed_sender: Optional[str]) -> bool:
        """Whether to spend anything on a message that CLAIMS to be from `claimed_sender`. The global bucket is charged
        first, so rotating the claim never gets past it."""
        with self._lock:
            if not self._global.take():
                self.limited_global += 1
                return False
            key = claimed_sender if isinstance(claimed_sender, str) else ""
            bucket = self._senders.get(key)
            if bucket is None:
                bucket = self._senders[key] = TokenBucket(self._rate, self._burst, self._clock)
                while len(self._senders) > self._max:
                    self._senders.popitem(last=False)  # the oldest claim is forgotten: state stays bounded
            else:
                self._senders.move_to_end(key)
            if not bucket.take():
                self.limited_sender += 1
                return False
            return True

    def tracked(self) -> Dict[str, int]:
        with self._lock:
            return {"senders": len(self._senders)}
