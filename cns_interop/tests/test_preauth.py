"""What a receiver spends on a message before it knows who sent it, and the controls that bound it (T2).

The claims are about WORK, not wall-clock: a spy counts signature checks and signatures made, so the tests do not depend on
how fast the machine is. One timing test, with a very wide margin, checks the benchmark harness agrees.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_session import DEC, REQ, code_of, pair  # type: ignore[import-not-found]  # noqa: E402

from cns_interop import crypto_backend as cb  # noqa: E402
from cns_interop import ed25519, session  # noqa: E402
from cns_interop.envelope import Refused, bounded_nodes, now_ms, seal  # noqa: E402
from cns_interop.identity import Signer  # noqa: E402
from cns_interop.limits import Limits, RateLimiter, TokenBucket  # noqa: E402
from cns_interop.negotiate import request_body  # noqa: E402
from cns_interop.wire import loads  # noqa: E402

STRANGER = Signer(bytes([91] * 32))


@pytest.fixture
def spy(monkeypatch):
    calls = {"verify": 0, "sign": 0}
    real_verify, real_seal = cb.verify, session.seal

    def verify(*a, **k):
        calls["verify"] += 1
        return real_verify(*a, **k)

    def counting_seal(*a, **k):
        calls["sign"] += 1
        return real_seal(*a, **k)

    monkeypatch.setattr(cb, "verify", verify)
    monkeypatch.setattr(session, "seal", counting_seal)
    return calls


def request_from(signer):
    return seal(signer, "request", request_body("income-screen", 1, identity="d", digest="ab" * 32,
                                                offer_fields=["monthly_income_cents"], require_evidence=[],
                                                max_ttl_ms=1000), to=DEC.agent, ttl_ms=60_000).to_wire()


def fresh(spy):
    spy.update(verify=0, sign=0)  # building a pair verifies a manifest; the claims below are about what comes after


def test_an_unknown_sender_costs_no_signature_check_and_gets_nothing_signed(spy):
    dec, _, _ = pair()
    fresh(spy)
    for _ in range(25):
        assert code_of(dec.handle, request_from(STRANGER)) == "untrusted"
    assert spy == {"verify": 0, "sign": 0} and dec.dropped == 25


def test_the_signed_refusal_is_still_there_but_only_when_the_receiver_asks_for_it(spy):
    dec, _, _ = pair(unknown_sender="refuse", clock=now_ms)  # real time: this message really is verified and answered
    fresh(spy)
    reply = dec.handle(request_from(STRANGER))
    assert reply.kind == "refuse" and spy["verify"] >= 1 and spy["sign"] == 1
    with pytest.raises(ValueError):
        pair(unknown_sender="shrug")


def test_a_pinned_sender_is_unaffected_and_a_revoked_one_is_dropped_before_any_check(spy):
    dec, req, _ = pair()
    _, _, _, decision = __import__("test_session").run(dec, req)
    assert decision.kind == "decision" and spy["verify"] > 0           # the normal path still verifies everything
    spy["verify"] = 0
    revoked = TrustPolicy_with_revoked(REQ.agent)
    dec2, _, _ = pair(decider_trusts=revoked)
    fresh(spy)
    assert code_of(dec2.handle, request_from(REQ)) == "untrusted" and spy["verify"] == 0


def TrustPolicy_with_revoked(agent):
    from cns_interop.trust import TrustPolicy
    return TrustPolicy(pinned=frozenset({agent}), revoked=frozenset({agent}))


def test_a_sender_claim_that_is_not_text_is_left_to_the_structural_checks_and_is_still_refused(spy):
    dec, _, _ = pair()
    fresh(spy)
    for bad in (1, None, ["x"], {"a": 1}):
        w = request_from(REQ)
        w["from"] = bad
        assert code_of(dec.handle, w) == "malformed"
    assert spy["verify"] == 0                                           # structure fails first; nothing was verified


# ------------------------------------------------------------------------------------------------ bounded values
def test_a_message_with_too_many_values_is_refused_before_the_signature_and_the_bound_is_exact(spy):
    body = {"a": [1] * 300}
    count = bounded_nodes(body, 10 ** 9)                                # the body, its key, the list and 300 integers
    assert count == 303
    dec, _, _ = pair(limits=Limits(max_nodes=count))
    w = {**request_from(REQ), "body": body}
    fresh(spy)
    assert code_of(dec.handle, w) == "signature" and spy["verify"] == 1   # at the bound it reaches the signature check
    dec2, _, _ = pair(limits=Limits(max_nodes=count - 1))
    fresh(spy)
    assert code_of(dec2.handle, w) == "profile" and spy["verify"] == 0


def test_the_bound_does_its_own_work_in_proportion_to_the_limit_not_to_the_message():
    steps = []

    class Counting(list):
        def __iter__(self):
            for x in super().__iter__():
                steps.append(1)
                yield x
    with pytest.raises(Refused) as e:
        bounded_nodes({"a": Counting([1] * 2_000_000)}, 1_000)
    assert e.value.code == "profile" and not steps                       # the list was refused from its length, never walked
    with pytest.raises(Refused):
        bounded_nodes([[1] * 400 for _ in range(400)], 50_000)           # many modest lists: stops when the sum passes the limit


def test_nesting_and_wide_mappings_are_bounded_too():
    deep = {"a": 1}
    for _ in range(10_000):
        deep = {"a": deep}
    assert code_of(bounded_nodes, deep, 5_000) == "profile"
    assert code_of(bounded_nodes, {f"k{i}": i for i in range(10_000)}, 5_000) == "profile"
    assert bounded_nodes({"a": [1, 2, {"b": None}]}, 100) == 8


def test_a_receiver_can_read_fewer_bytes_than_the_protocol_ceiling_and_never_more():
    text = '{"a":"' + "x" * 1_000 + '"}'
    assert loads(text, max_bytes=2_000)["a"].startswith("x")
    assert code_of(loads, text, max_bytes=500) == "malformed"
    assert code_of(loads, text.encode(), max_bytes=500) == "malformed"
    assert loads(text, max_bytes=10 ** 9)                               # a larger cap cannot exceed the 1 MiB ceiling
    assert code_of(loads, '{"a":"' + "x" * (1 << 20) + '"}', max_bytes=10 ** 9) == "malformed"


# ------------------------------------------------------------------------------------------------ rate limiting
def test_a_token_bucket_refills_with_time_and_never_stores_more_than_its_burst():
    t = [0]
    b = TokenBucket(10, 3, clock=lambda: t[0])                          # 10 a second, burst 3
    assert [b.take() for _ in range(5)] == [True, True, True, False, False]
    t[0] = 100                                                          # 0.1 s: one token
    assert [b.take(), b.take()] == [True, False]
    t[0] = 10_000_000                                                   # a very long idle does not store a huge credit
    assert sum(b.take() for _ in range(10)) == 3
    with pytest.raises(ValueError):
        TokenBucket(0, 1)


def test_rotating_the_claimed_identity_does_not_get_past_the_global_bucket_and_state_stays_bounded():
    lim = RateLimiter(global_rate=1, global_burst=20, sender_rate=1, sender_burst=1, max_senders=100, clock=lambda: 0)
    passed = sum(lim.allow(f"uai:ed25519:{i:064x}") for i in range(100_000))
    assert passed == 20 and lim.limited_global == 99_980
    assert lim.tracked()["senders"] <= 100                              # the limiter cannot be used to exhaust memory


def test_one_sender_is_held_to_its_own_bucket_while_others_are_served():
    lim = RateLimiter(global_rate=1000, global_burst=1000, sender_rate=1, sender_burst=2, clock=lambda: 0)
    assert [lim.allow("loud") for _ in range(4)] == [True, True, False, False]
    assert lim.allow("quiet") and lim.limited_sender == 2


def test_a_decider_with_a_limiter_spends_nothing_on_what_it_turns_away(spy):
    lim = RateLimiter(global_rate=1, global_burst=3, sender_rate=1, sender_burst=3, clock=lambda: 0)
    dec, _, _ = pair(limiter=lim)
    fresh(spy)
    outcomes = [code_of(dec.handle, request_from(STRANGER)) for _ in range(10)]
    assert outcomes.count("rate_limited") == 7 and outcomes.count("untrusted") == 3
    assert spy == {"verify": 0, "sign": 0} and dec.rate_limited == 7


# ------------------------------------------------------------------------------------------------ key cache
def test_the_public_key_cache_changes_no_answer_and_small_order_keys_stay_refused():
    from test_crypto_backend import corpus  # type: ignore[import-not-found]
    cases = corpus()
    ed25519._public_point.cache_clear()
    cold = [ed25519.verify(p, m, s) for p, m, s in cases]
    warm = [ed25519.verify(p, m, s) for p, m, s in cases]
    assert cold == warm and any(cold) and not all(cold)
    assert ed25519._public_point.cache_info().hits > 0
    identity = bytes.fromhex("01" + "00" * 31)
    for _ in range(3):
        assert ed25519.verify(identity, b"m", identity + b"\x00" * 32) is False


# ------------------------------------------------------------------------------------------------ the harness
def test_the_benchmark_harness_agrees_with_the_counters_with_a_very_wide_margin():
    from interop.bench import preauth
    res = preauth.run(quick=True)
    pure = res["pure"]
    refuse = pure["unknown sender, signed refusal (revision 2 behavior)"]["median_ms"]
    drop = pure["unknown sender, dropped (revision 3 default)"]["median_ms"]
    assert drop * 20 < refuse                                           # measured about 3800 times; 20 is the floor asserted
    unbounded = pure["1 MiB list of small integers, no node bound (revision 2)"]["median_ms"]
    bounded = pure["1 MiB list of small integers, max_nodes=20000 (revision 3)"]["median_ms"]
    assert bounded * 5 < unbounded                                      # measured about 48 times
    assert res["rate limiter"]["let_through"] == 50
