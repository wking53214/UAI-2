"""fencing: a protected target that refuses the action of a holder whose lease has been taken over.

A lease alone gives at-least-once delivery: a holder that stalls past its lease (a pause, a slow network) can still act
after a new holder was granted the same message. Only the TARGET can stop that, by remembering the highest fence it has
acted on and refusing any lower one. `Reservation.fence` only grows across every reservation a ledger grants, so the
stale holder's fence is lower than the new holder's.

`FencedTarget` is the reference check. A real target keeps `highest` in the same transaction as its own write (for a SQL
target: `UPDATE fences SET highest = %s WHERE resource = %s AND highest <= %s`, acting only if one row changed). Where the
target cannot do that, the action is at-least-once and must be idempotent on the reservation's key; this module makes no
exactly-once claim for such a target.
"""

from __future__ import annotations

import threading
from typing import Dict

from .envelope import Refused

__all__ = ["FencedTarget"]


class FencedTarget:
    def __init__(self, *, require_fence: bool = True) -> None:
        self._highest: Dict[str, int] = {}
        self._lock = threading.Lock()
        self._require = require_fence

    def check(self, resource: str, fence: int) -> None:
        """Raise Refused('fenced') if `fence` is lower than one already acted on for `resource`, or is absent (0) when a
        fence is required. Otherwise record it. An equal fence is the same holder acting again, which is allowed."""
        if isinstance(fence, bool) or not isinstance(fence, int) or fence < 0:
            raise Refused("fenced", "a fence is a non-negative integer")
        if fence == 0 and self._require:
            raise Refused("fenced", "this ledger issued no fence, so a stale holder cannot be told from the current one")
        with self._lock:
            if fence < self._highest.get(resource, 0):
                raise Refused("fenced", "a holder with a newer fence has already acted on this resource")
            self._highest[resource] = max(fence, self._highest.get(resource, 0))
