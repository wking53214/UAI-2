# Signing-key custody and compromise recovery

**Status: DRAFT for the project owner.** Part 1 is what the code does today, each point read from the source or backed by a
named test. Part 2 is a procedure built on Part 1. Every line marked **DECIDE** is an operating choice this repository
cannot make for you; fill it in before relying on this page. Nothing here has been exercised as a drill.

Labels: **CODE** means read from the source and checked, **TESTED** means a named test in this repository holds it,
**INFERRED** means a consequence I drew and no test shows, **OPEN** means not provided.

## Part 1. What the software does

### The key and the identity are the same thing

- An identity is `uai:ed25519:` plus the public key (`docs/interop/UAI-1.md` section 3). **CODE.** There is no separate
  name that can stay the same while the key changes. Replacing a key means a new identity, and every receiver has to be
  told.
- A `Signer` is built from a 32-byte seed. It refuses pickling, copying and serializing, so the key cannot reach a cache,
  queue or log by accident (`cns_interop/identity.py`). **CODE.**
- `Signer.generate()` draws a seed from the operating system's random source. **CODE.**

### Where the key can live

| Mode | What it means | Status |
|---|---|---|
| Seed in the process | the key is in process memory | works; **not allowed** under `UAI_PROFILE=production` with the pure-Python backend (the signer refuses to start) |
| Seed in the process, OpenSSL backend | same, with `UAI_CRYPTO_BACKEND=cryptography`, which production requires | **CODE.** Key material is still in process memory |
| `Signer.external(agent, sign)` | the key lives in an HSM or keystore; you supply a function that signs bytes | the hook exists and **checks every signature against the identity before it leaves**, so a misconfigured keystore is an error, not a stream of messages every receiver refuses (**CODE**). **No hardware implementation was run here** (`SECURITY_PROFILES.md`) |

**OPEN:** no code reads a key from an operating-system keystore, a file permission check, or a secrets manager. Getting the
seed to the process is entirely the operator's job.

### What a receiver does about a compromised or retired key

- **Revoke.** `revocation.revoke(signer, subject, reason=...)` makes a signed statement that an identity or endorsement is
  untrustworthy. It has **no expiry** and there is **no un-revoke** (`UAI-1.md` section 3). Only the subject itself or an
  authority the receiver lists can revoke; nobody else is heard. A revoke only ever reduces trust. **TESTED**
  (`cns_interop/tests/test_revocation.py::test_a_subject_and_a_listed_authority_may_revoke_and_nobody_else_may`).
- **Rotate.** `revocation.rotate(signer, successor, reason=...)` says "my identity is replaced by `successor`". A receiver
  follows it only if it opted in (`follow_rotation`) **and** the old identity is pinned. **TESTED**
  (`::test_rotation_is_ignored_unless_the_receiver_follows_it_and_only_from_a_pinned_predecessor`).
- **An authority revoking a key that already rotated also withdraws the successor it named.** **TESTED**
  (`::test_an_authority_revoking_a_compromised_key_also_withdraws_the_successor_it_named`).
- **Revocation binds from its effective time, survives a restart, and a stored revocation stops a guard before and after it
  authorizes.** **TESTED** (`::test_a_revocation_binds_from_its_effective_time_and_survives_a_restart`,
  `::test_a_stored_revocation_stops_a_guard_before_and_after_it_authorizes`).
- **A stale list refuses.** With `max_staleness_ms` set, a revocation store that has not been refreshed recently makes the
  receiver answer `unavailable` rather than assume nothing was revoked. **TESTED**
  (`::test_a_stale_or_never_refreshed_list_refuses_instead_of_assuming_nothing_was_revoked`). **CODE:** the limit is off
  unless the receiver sets it.
- **An unreadable store is "unavailable", never "empty".** **TESTED** (`::test_an_unreadable_store_is_unavailable_not_empty`).
- **The Node receiver supports revocation too** (`interop/node/revocation.test.mjs`). **TESTED.**

### Why rotation alone is not compromise recovery (INFERRED)

A rotate statement is signed by the old key. Someone holding a stolen key can sign a rotate naming a successor of their
own. The receiver protections that stop this are the ones above: it follows a rotate only if it chose to, only from a
pinned predecessor, and an authority's revoke withdraws the successor. So after a compromise, **the revoke from an
authority the receiver already trusts is what ends the incident**, not the compromised key's own rotate. Plan on that.
No test builds this exact attack; it follows from the rules above.

### What the software does not do (OPEN)

- It does not **distribute** revocations. "Statements are signed and stored by each receiver; how they reach it is its own
  business" (`UAI-1.md` section 8). There is no published revocation list and no push channel.
- It does not **detect** a compromise. Nothing watches for a key signing something its owner did not.
- It does not **back up or escrow** keys, enforce key age, or schedule rotation.
- It does not check a **key's file permissions** or where a seed was loaded from.
- Signatures are not shown to be constant time (`SECURITY_PROFILES.md`); no timing measurement was made.

## Part 2. Procedure to adopt (fill in every DECIDE)

### 2.1 Roles

| Role | Who | DECIDE |
|---|---|---|
| Key owner (may sign with the decider key) | | name a person or service account |
| Revocation authority (may revoke on behalf of the identity) | | a **separate** key from the decider key, kept offline, so a stolen decider key cannot revoke itself away or block its own revocation |
| Receiver operators (hold the pin list and the revocation store) | | |

Keep the revocation authority's key apart from every key it can revoke. A single key that signs decisions and also holds
the only power to revoke it leaves no recovery path when it is stolen. **INFERRED** from the rules in Part 1.

### 2.2 Generation and storage

1. Generate the decider key with `Signer.generate()` on a machine you trust, or inside the HSM or keystore if you use
   `Signer.external`. **DECIDE** which.
2. Production profile: set `UAI_PROFILE=production` and `UAI_CRYPTO_BACKEND=cryptography` (required; the process refuses
   the pure backend with a local seed).
3. Where the seed is stored at rest and how it reaches the process: **DECIDE** (environment variable from a secrets
   manager, mounted file with mode 0400, or an HSM behind `Signer.external`). The software enforces none of these.
4. Record the public identity (`uai:ed25519:...`) and its creation date in a register: **DECIDE** where.

### 2.3 Planned rotation (no compromise)

1. Generate the successor. Publish its identity to every receiver out of band.
2. Have each receiver **pin the successor** before the old key stops signing.
3. Sign `rotate(old_signer, successor, reason="scheduled rotation")` and deliver it. Receivers that set `follow_rotation`
   follow it from the pinned predecessor.
4. Stop signing with the old key. Have each receiver unpin it. **DECIDE** the rotation interval and who checks each
   receiver finished.

### 2.4 Suspected compromise (the order matters)

1. **Revoke first.** From the **revocation authority**, sign `revoke(authority_signer, compromised_identity,
   reason="suspected compromise", effective_at=<earliest time you believe the key was exposed>)`. Revocation binds from its
   effective time, so set it to the earliest plausible exposure, not to now. Anything the key signed after that time should
   be re-judged by each receiver. **DECIDE** who may order this and how fast.
2. **Get it to every receiver.** The software gives you no channel. **DECIDE** the channel (email to named operators, a
   shared signed file, an admin API) and the time limit. Until a receiver has the statement it still trusts the key.
3. **Shorten staleness where you can.** Receivers that set `max_staleness_ms` refuse when they have not refreshed in time,
   which is the safe direction. **DECIDE** the value per receiver.
4. **Stop the old key signing.** Remove it from its store or disable it in the HSM.
5. **Bring up a replacement** identity (2.2), have receivers pin it, and tell them. Do not use `rotate` from the
   compromised key as the recovery step (see Part 1, "Why rotation alone is not compromise recovery").
6. **Review.** Each receiver's audit record (`GrantTable` audit chain) shows every decision it permitted under the old key.
   Find those after the effective time and decide whether to reverse them. **DECIDE** who reviews and how.

### 2.5 Loss of the key (no theft)

The identity cannot sign again. Treat it like 2.4 steps 1, 4 and 5, with reason "lost". A lost key cannot be revoked by
itself, which is why the revocation authority must be separate.

### 2.6 Loss of the revocation authority's key

**OPEN, and the most dangerous gap.** A receiver lists its authorities itself, so recovery is a receiver-side change: each
receiver adds a new authority. **DECIDE** how you would reach every receiver quickly, and keep a second authority key in a
separate place for exactly this case.

### 2.7 Drill

Nothing in Part 2 has been run. Before relying on it, rehearse 2.4 against a test deployment: revoke a test key, time how
long until every test receiver refuses it, and write down what you find. **DECIDE** the date.

## What closing this gap still needs

| Item | Who |
|---|---|
| Every DECIDE above filled in | project owner |
| A drill of 2.4, with timings and results recorded here | operator |
| A channel to deliver revocations | operator; a published revocation list is a protocol change and is out of scope for this page |
