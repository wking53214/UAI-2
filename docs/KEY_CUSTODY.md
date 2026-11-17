# Signing-key custody and compromise recovery

**Status: DRAFT for the project owner, partly filled in on 2026-11-17 (see the DECIDED marks).** Part 1 is what the code does today, each point read from the source or backed by a
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

### Why rotation alone is not compromise recovery (SIMULATED)

A rotate statement is signed by the old key. Someone holding a stolen key can sign a rotate naming a successor of their
own. The receiver protections that stop this are the ones above: it follows a rotate only if it chose to, only from a
pinned predecessor, and an authority's revoke withdraws the successor. So after a compromise, **the revoke from an
authority the receiver already trusts is what ends the incident**, not the compromised key's own rotate. Plan on that.
A software simulation of this attack now exists (`interop/key_drill.py`, report and hash in
`evidence/drills/2026-11-17-key-drill/`, held by `tests/test_key_drill.py`). It is a simulation on one machine, not an operational
drill. It shows that an authority's revoke ends the incident whether it arrives before or after the attacker's rotate, and adds two facts
the draft did not have:

- **First statement wins.** If the attacker's rotate reaches a receiver first, the owner's own later rotate to the real successor does not
  take effect there, and the attacker's successor stays followed until an authority revokes.
- **A self-revoke does not withdraw it.** Only a revoke from an authority the receiver lists withdraws the successor the key named.

So the owner cannot repair a stolen key by acting as itself; recovery needs the separate authority (2.1) and a new identity (2.4).

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
| Key owner (may sign with the decider key) | The project owner, William N. King, and no one else | **DECIDED 2026-11-17 (project owner)**: one accountable person |
| Revocation authority (may revoke on behalf of the identity) | A separate key from the decider key, kept offline on a hardware token in a safe | **DECIDED 2026-11-17 (project owner)**. Still DECIDE: who opens the safe in an emergency, and where the safe is |
| Receiver operators (hold the pin list and the revocation store) | | **DECIDE** name each operator; section 2.4 emails them |

Keep the revocation authority's key apart from every key it can revoke. A single key that signs decisions and also holds
the only power to revoke it leaves no recovery path when it is stolen. **INFERRED** from the rules in Part 1.

### 2.2 Generation and storage

1. Generate the decider key with `Signer.generate()` on a machine you trust, or inside the HSM or keystore if you use
   `Signer.external`. **DECIDE** which. (Storage in 3 below was decided as a secrets manager, which fits `Signer.generate()` on a trusted machine, then loading the seed into the manager.)
2. Production profile: set `UAI_PROFILE=production` and `UAI_CRYPTO_BACKEND=cryptography` (required; the process refuses
   the pure backend with a local seed).
3. Where the seed is stored at rest and how it reaches the process: **DECIDED 2026-11-17 (project owner)**: a secrets manager, which hands the seed to the
   process as an environment variable. The software enforces none of this. Still **DECIDE** which secrets manager product.
4. Record the public identity (`uai:ed25519:...`) and its creation date in a register: **DECIDE** where.

### 2.3 Planned rotation (no compromise)

1. Generate the successor. Publish its identity to every receiver out of band.
2. Have each receiver **pin the successor** before the old key stops signing.
3. Sign `rotate(old_signer, successor, reason="scheduled rotation")` and deliver it. Receivers that set `follow_rotation`
   follow it from the pinned predecessor.
4. Stop signing with the old key. Have each receiver unpin it. Rotation interval **DECIDED 2026-11-17 (project owner)**: every 12 months. Still **DECIDE**
   who checks that each receiver finished.

### 2.4 Suspected compromise (the order matters)

1. **Revoke first.** From the **revocation authority**, sign `revoke(authority_signer, compromised_identity,
   reason="suspected compromise", effective_at=<earliest time you believe the key was exposed>)`. Revocation binds from its
   effective time, so set it to the earliest plausible exposure, not to now. Anything the key signed after that time should
   be re-judged by each receiver. **DECIDE** who may order this and how fast.
2. **Get it to every receiver.** The software gives you no channel. Channel **DECIDED 2026-11-17 (project owner)**: email to the named receiver
   operators (see 2.1). Still **DECIDE** the time limit. Until a receiver has the statement it still trusts the key.
3. **Shorten staleness where you can.** Receivers that set `max_staleness_ms` refuse when they have not refreshed in time,
   which is the safe direction. Value **DECIDED 2026-11-17 (project owner)**: 24 hours, `max_staleness_ms = 86_400_000`, on every receiver. A receiver
   that is offline for more than a day refuses requests until it refreshes.
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
receiver adds a new authority. A second authority key, kept in a place separate from the first, is **DECIDED 2026-11-17 (project owner)**. Still
**DECIDE** where it is kept and how you would reach every receiver quickly.

### 2.7 Drill

Part 2 has not been run by a person. A **software simulation** of the order of events in 2.4 has been run (see Part 1); it measured
no time and involved no operator, key store or receiver. Before relying on this procedure, rehearse 2.4 against a test deployment: revoke a test key, time how
long until every test receiver refuses it, and write down what you find. Date **DECIDED 2026-11-17 (project owner)**: not scheduled. Until a date is set and the drill is run, treat this procedure as unproven.

## What closing this gap still needs

| Item | Who |
|---|---|
| Every DECIDE above filled in (open now: receiver operators, key generation method, secrets manager product, where the register lives, who orders a revocation and how fast, the revocation time limit, who reviews afterwards, safe access, where the second authority key is kept) | project owner |
| A drill of 2.4, with timings and results recorded here | operator |
| A channel to deliver revocations | operator; a published revocation list is a protocol change and is out of scope for this page |
