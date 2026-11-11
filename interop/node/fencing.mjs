// fencing.mjs: the Node twin of cns_interop/fencing.FencedTarget. A protected target that refuses the action of a holder whose
// lease has been taken over: it remembers the highest fence it has acted on per resource and refuses a lower one. The fence a
// PostgresLedger issues (pg.mjs, Python's ledger_postgres) only grows, so a stale holder's fence is lower than the new one's.
// A real target keeps `highest` in the same transaction as its own write; this is the reference check, in memory, for one
// process. Where a target cannot do that, the action is at-least-once and must be idempotent on the reservation's key.
import { Refused } from "./uai.mjs";

export class FencedTarget {
  constructor({ requireFence = true } = {}) { this._highest = new Map(); this._require = requireFence; }

  // Refused('fenced') if `fence` is lower than one already acted on for `resource`, or is absent (0) when a fence is required,
  // or is not a non-negative integer. Otherwise record it. An equal fence is the same holder acting again, which is allowed.
  check(resource, fence) {
    if (!Number.isSafeInteger(fence) || fence < 0) throw new Refused("fenced", "a fence is a non-negative integer");
    if (fence === 0 && this._require) throw new Refused("fenced", "this ledger issued no fence, so a stale holder cannot be told from the current one");
    const high = this._highest.get(resource) ?? 0;
    if (fence < high) throw new Refused("fenced", "a holder with a newer fence has already acted on this resource");
    this._highest.set(resource, Math.max(fence, high));
  }
}
