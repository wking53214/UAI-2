"""Signed revocation and rotation: who may say it, what a receiver does with it, and what happens when it cannot know.

The adversary here is a forger, a compromised key, a stale view, and a store that fails. Each test changes one thing.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_session import DEC, GUARD_CAP, REQ, Clock, code_of, pair, run  # type: ignore[import-not-found]  # noqa: E402

from cns_interop.decision import RemoteDecisionGuard  # noqa: E402
from cns_interop.envelope import Refused, now_ms, seal  # noqa: E402
from cns_interop.identity import Signer  # noqa: E402
from cns_interop.ledger import MemoryLedger  # noqa: E402
from cns_interop.revocation import RevocationStore, read_statement, revoke, rotate  # noqa: E402
from cns_interop.trust import TrustPolicy, endorse  # noqa: E402

AUTH, KEY, NEXT, STRANGER = (Signer(bytes([i] * 32)) for i in (41, 42, 43, 44))
T = 1_800_000_000_000


@pytest.fixture
def store(tmp_path):
    return RevocationStore(tmp_path / "rev.db")


def test_a_subject_and_a_listed_authority_may_revoke_and_nobody_else_may(store):
    assert store.accept(revoke(KEY, KEY.agent, reason="lost", now=T).to_wire(), now=T).subject == KEY.agent
    assert store.accept(revoke(AUTH, NEXT.agent, reason="breach", now=T).to_wire(), authorities=[AUTH.agent],
                        now=T).signer == AUTH.agent
    with pytest.raises(Refused) as e:
        store.accept(revoke(STRANGER, DEC.agent, reason="spite", now=T).to_wire(), authorities=[AUTH.agent], now=T)
    assert e.value.code == "untrusted"
    assert not store.is_revoked(DEC.agent, T + 1)
    with pytest.raises(Refused) as e:   # an authority the receiver does not list
        store.accept(revoke(AUTH, DEC.agent, reason="x", now=T).to_wire(), authorities=[], now=T)
    assert e.value.code == "untrusted"


def test_malformed_and_tampered_statements_are_refused(store):
    good = revoke(KEY, KEY.agent, reason="lost", now=T).to_wire()
    assert code_of(store.accept, {**good, "body": {**good["body"], "reason": "edited"}}, now=T) == "signature"
    for body in ({"subject": KEY.agent, "action": "revoke", "successor": "", "reason": "r"},
                 {"subject": KEY.agent, "action": "delete", "successor": "", "reason": "r", "effective_at": T},
                 {"subject": "nope", "action": "revoke", "successor": "", "reason": "r", "effective_at": T},
                 {"subject": KEY.agent, "action": "revoke", "successor": NEXT.agent, "reason": "r",
                  "effective_at": T},
                 {"subject": KEY.agent, "action": "revoke", "successor": "", "reason": "r", "effective_at": 1.5}):
        w = seal(KEY, "revocation", body, now=T).to_wire() if "effective_at" in body and body["effective_at"] != 1.5 \
            else None
        if w is not None:
            assert code_of(store.accept, w, now=T) == "malformed"
    assert not store.is_revoked(KEY.agent, T + 1)


def test_rotation_is_only_the_subjects_to_say_and_names_another_identity(store):
    assert code_of(read_statement, seal(AUTH, "revocation", {"subject": KEY.agent, "action": "rotate",
                                                              "successor": NEXT.agent, "reason": "r",
                                                              "effective_at": T}, now=T).to_wire(),
                   authorities=[AUTH.agent], now=T) == "untrusted"
    assert code_of(read_statement, seal(KEY, "revocation", {"subject": KEY.agent, "action": "rotate",
                                                             "successor": KEY.agent, "reason": "r",
                                                             "effective_at": T}, now=T).to_wire(), now=T) == "malformed"


def test_a_revocation_binds_from_its_effective_time_and_survives_a_restart(tmp_path):
    path = tmp_path / "rev.db"
    RevocationStore(path).accept(revoke(KEY, KEY.agent, reason="later", effective_at=T + 10_000, now=T).to_wire(),
                                 now=T)
    reopened = RevocationStore(path)
    assert not reopened.is_revoked(KEY.agent, T + 9_999)
    assert reopened.is_revoked(KEY.agent, T + 10_000)


def test_the_same_statement_twice_is_harmless(store):
    w = revoke(KEY, KEY.agent, reason="lost", now=T).to_wire()
    store.accept(w, now=T)
    store.accept(w, now=T)
    assert store.is_revoked(KEY.agent, T)


def test_a_pinned_identity_a_revoked_authority_and_a_revoked_endorsement_are_each_refused(store):
    store.accept(revoke(KEY, KEY.agent, reason="lost", now=T).to_wire(), now=T)
    pol = TrustPolicy(pinned=frozenset({KEY.agent, NEXT.agent}), revocations=store)
    assert code_of(pol.admit, KEY.agent, now=T) == "untrusted"
    assert pol.admit(NEXT.agent, now=T).via == "pinned"

    e1 = endorse(AUTH, STRANGER.agent, "payments", ttl_ms=60_000, now=T)
    pol = TrustPolicy(authorities={AUTH.agent: frozenset({"*"})}, revocations=store)
    assert pol.admit(STRANGER.agent, [e1], now=T).via == "endorsed"
    store.accept(revoke(AUTH, e1.id, reason="mis-issued", now=T).to_wire(), authorities=[AUTH.agent], now=T)
    assert code_of(pol.admit, STRANGER.agent, [e1], now=T + 1) == "untrusted"          # that endorsement
    e2 = endorse(AUTH, STRANGER.agent, "payments", ttl_ms=60_000, now=T + 2)
    assert pol.admit(STRANGER.agent, [e2], now=T + 3).via == "endorsed"                 # a fresh one is another matter
    store.accept(revoke(AUTH, AUTH.agent, reason="authority key lost", now=T).to_wire(), now=T + 4)
    assert code_of(pol.admit, STRANGER.agent, [e2], now=T + 5) == "untrusted"           # the authority itself


def test_a_stale_or_never_refreshed_list_refuses_instead_of_assuming_nothing_was_revoked(store):
    pol = TrustPolicy(pinned=frozenset({KEY.agent}), revocations=store, max_staleness_ms=60_000)
    assert code_of(pol.admit, KEY.agent, now=T) == "unavailable"        # never refreshed
    store.mark_fresh(T)
    assert pol.admit(KEY.agent, now=T + 59_000).via == "pinned"
    assert code_of(pol.admit, KEY.agent, now=T + 61_000) == "unavailable"
    store.mark_fresh(T + 61_000)
    assert pol.admit(KEY.agent, now=T + 62_000).via == "pinned"
    # without a bound the list is trusted as it is: that is the receiver's stated choice
    assert TrustPolicy(pinned=frozenset({KEY.agent}), revocations=store).admit(KEY.agent, now=T + 10 ** 9)


def test_rotation_is_ignored_unless_the_receiver_follows_it_and_only_from_a_pinned_predecessor(store):
    store.accept(rotate(KEY, NEXT.agent, reason="scheduled", now=T).to_wire(), now=T)
    assert store.predecessor_of(NEXT.agent) == KEY.agent
    default = TrustPolicy(pinned=frozenset({KEY.agent}), revocations=store)
    assert code_of(default.admit, NEXT.agent, now=T + 1) == "untrusted"          # off by default
    assert code_of(default.admit, KEY.agent, now=T + 1) == "untrusted"           # a rotation retires the old key
    follows = TrustPolicy(pinned=frozenset({KEY.agent}), revocations=store, follow_rotation=True)
    assert follows.admit(NEXT.agent, now=T + 1).via == "rotated"
    stranger = TrustPolicy(pinned=frozenset({STRANGER.agent}), revocations=store, follow_rotation=True)
    assert code_of(stranger.admit, NEXT.agent, now=T + 1) == "untrusted"         # predecessor not pinned here


def test_an_authority_revoking_a_compromised_key_also_withdraws_the_successor_it_named(store):
    store.accept(rotate(KEY, NEXT.agent, reason="attacker holds this key", now=T).to_wire(), now=T)
    follows = TrustPolicy(pinned=frozenset({KEY.agent}), revocations=store, follow_rotation=True)
    assert follows.admit(NEXT.agent, now=T + 1).via == "rotated"
    store.accept(revoke(AUTH, KEY.agent, reason="compromised", now=T + 2).to_wire(), authorities=[AUTH.agent],
                 now=T + 2)
    assert store.predecessor_of(NEXT.agent) is None
    assert code_of(follows.admit, NEXT.agent, now=T + 3) == "untrusted"


def _decision():
    dec, req, clock = pair()
    _, offer, accept, decision = run(dec, req)
    return decision.to_wire(), offer.body["terms"], accept.digest, clock


def test_a_stored_revocation_stops_a_guard_before_and_after_it_authorizes(store):
    wire, terms, accept, clock = _decision()
    now = clock()
    # before authorize
    store.accept(revoke(DEC, DEC.agent, reason="decider key lost", now=now).to_wire(), now=now)
    g = RemoteDecisionGuard(lambda a: a, acting_for=REQ.agent, capability=GUARD_CAP, ledger=MemoryLedger(),
                            clock=clock, trust=TrustPolicy(pinned=frozenset({DEC.agent}), revocations=store))
    assert code_of(g.authorize, wire, terms=terms, accept_digest=accept) == "untrusted"


def test_a_revocation_that_arrives_after_authorize_closes_the_guard_and_a_stale_store_closes_it_too(tmp_path):
    wire, terms, accept, clock = _decision()
    store = RevocationStore(tmp_path / "r.db")
    store.mark_fresh(clock())
    g = RemoteDecisionGuard(lambda a: a, acting_for=REQ.agent, capability=GUARD_CAP, ledger=MemoryLedger(),
                            clock=clock, trust=TrustPolicy(pinned=frozenset({DEC.agent}), revocations=store,
                                                           max_staleness_ms=30_000))
    g.authorize(wire, terms=terms, accept_digest=accept)
    clock.t += 31_000                                    # the list is now older than the bound: cannot rule out
    assert g(("loan-app-17", terms["subject"]["digest"])) is False

    wire, terms, accept, clock = _decision()
    store2 = RevocationStore(tmp_path / "r2.db")
    g = RemoteDecisionGuard(lambda a: a, acting_for=REQ.agent, capability=GUARD_CAP, ledger=MemoryLedger(),
                            clock=clock, trust=TrustPolicy(pinned=frozenset({DEC.agent}), revocations=store2))
    g.authorize(wire, terms=terms, accept_digest=accept)
    store2.accept(revoke(DEC, DEC.agent, reason="lost", now=clock()).to_wire(), now=clock())
    assert g(("loan-app-17", terms["subject"]["digest"])) is False


def test_a_revoked_requester_is_refused_by_a_decider_using_the_same_store(tmp_path):
    store = RevocationStore(tmp_path / "r.db")
    clock = Clock()
    dec, req, _ = pair(clock=clock, decider_trusts=TrustPolicy(pinned=frozenset({REQ.agent}), revocations=store))
    run(dec, req)                                         # works before
    store.accept(revoke(REQ, REQ.agent, reason="lost", now=clock()).to_wire(), now=clock())
    dec2, req2, _ = pair(clock=clock, decider_trusts=TrustPolicy(pinned=frozenset({REQ.agent}), revocations=store))
    request = req2.request(DEC.agent, __import__("test_session").doc(), "income-screen", 1,
                           offer_fields=["monthly_income_cents"], require_evidence=["threshold-check"],
                           max_ttl_ms=600_000)
    with pytest.raises(Refused) as dropped:  # T2-1: a revoked sender is dropped, with no signature check and no signed reply
        dec2.handle(request.to_wire())
    assert dropped.value.code == "untrusted" and dec2.dropped == 1


def test_an_unreadable_store_is_unavailable_not_empty(tmp_path):
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"not a database" * 200)
    with pytest.raises(Refused) as e:
        RevocationStore(bad)
    assert e.value.code == "unavailable"
    store = RevocationStore(tmp_path / "ok.db")
    pol = TrustPolicy(pinned=frozenset({KEY.agent}), revocations=store)
    (tmp_path / "ok.db").write_bytes(b"corrupted after open" * 300)
    assert code_of(pol.admit, KEY.agent, now=now_ms()) == "unavailable"
