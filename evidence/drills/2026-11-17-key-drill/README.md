# Simulated key-compromise drill, 2026-11-17

`key-drill.json` is the output of `python interop/key_drill.py --out key-drill.json` on commit base `8e721ab`.
SHA-256 `8e5af64047ff91aa880fb13b51ebc1e4560ac98527a6d2bded67d1935ad010f2`. It is deterministic (fixed throwaway keys, a simulated clock), so `tests/test_key_drill.py` regenerates it and fails if it differs.

**This is a SIMULATION, not an operational drill.** One machine, the real `cns_interop.revocation` and `cns_interop.trust` code, fixed
test keys. No person, vault, HSM, receiver or delivery channel took part, and no time to respond was measured. It is not third-party validation.

## What it shows (9 scenarios, all matched the expectations written before the run)

- A planned rotation works: the old key is refused, the successor is followed.
- After a compromise, an authority's revoke ends it whichever came first: the attacker's rotate (its successor is withdrawn) or the
  revoke (a later rotate by the stolen key is ignored).
- **Two things the custody draft did not say** (observed, not assumed):
  1. *First statement wins.* If the attacker's rotate arrives first, the owner's own later rotate to the real successor does not take effect, and the
     attacker's successor stays followed until an authority revokes.
  2. *A self-revoke does not help.* The key revoking itself leaves the attacker's successor followed; only a revoke from an authority the receiver lists withdraws it.
- Recovery after a compromise is a **new identity pinned out of band** by each receiver, not a rotation.
- A receiver that never listed the authority refuses its revoke, and a receiver never sent the revoke keeps trusting the key. Nothing in the
  software distributes revocations.
- A stale list refuses (`unavailable`) only if the receiver set `max_staleness_ms`.

## What it does not show

How long a real response takes; whether a person can follow the procedure; any HSM, vault or keystore; delivery of revocations to real
receivers; the Node receiver (it covers the Python code only).
