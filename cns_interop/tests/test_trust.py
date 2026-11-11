"""Trust is the receiver's: pinned, or endorsed by an authority the receiver recognises for that domain, and nothing else."""

from __future__ import annotations

import pytest

from cns_interop.envelope import Refused, seal
from cns_interop.identity import Signer
from cns_interop.trust import TrustPolicy, endorse

T0 = 1_800_000_000_000
AUTH = Signer(bytes([7] * 32))
OTHER_AUTH = Signer(bytes([8] * 32))
AGENT = Signer(bytes([9] * 32))
STRANGER = Signer(bytes([10] * 32))
POLICY = TrustPolicy(pinned=frozenset({STRANGER.agent}), authorities={AUTH.agent: frozenset({"lending"})})


def card(signer=AUTH, agent=AGENT.agent, domain="lending", ttl=60_000):
    return endorse(signer, agent, domain, ttl_ms=ttl, now=T0).to_wire()


def no(*a, **kw):
    kw.setdefault("now", T0)
    with pytest.raises(Refused) as caught:
        POLICY.admit(*a, **kw)
    assert caught.value.code == "untrusted"
    return caught.value.reason


def test_pinned_and_endorsed_are_the_two_ways_in():
    assert POLICY.admit(STRANGER.agent, now=T0).via == "pinned"
    got = POLICY.admit(AGENT.agent, [card()], now=T0, domain="lending")
    assert (got.via, got.authority, got.domain) == ("endorsed", AUTH.agent, "lending")


def test_nobody_else():
    assert "not pinned" in no(AGENT.agent)


def test_an_unknown_authority_cannot_vouch():
    assert "does not recognise" in no(AGENT.agent, [card(OTHER_AUTH)])


def test_an_authority_vouches_only_for_its_domains():
    assert "may not vouch" in no(AGENT.agent, [card(domain="medical")])
    assert "not 'medical'" in no(AGENT.agent, [card()], domain="medical")


def test_an_endorsement_for_someone_else_does_not_transfer():
    assert "different identity" in no(AGENT.agent, [card(agent=OTHER_AUTH.agent)])


def test_endorsements_expire_and_must_expire():
    assert "expired" in no(AGENT.agent, [card(ttl=1000)], now=T0 + 1000)
    forever = seal(AUTH, "endorsement", {"subject": AGENT.agent, "domain": "lending"}, to=AGENT.agent, now=T0)
    assert "no expiry" in no(AGENT.agent, [forever.to_wire()])


def test_a_forged_or_edited_endorsement_is_refused():
    w = card()
    w["body"]["domain"] = "lending-plus"
    assert "signature" in no(AGENT.agent, [w])


def test_revocation_beats_every_yes():
    c = card()
    for revoked in (AGENT.agent, AUTH.agent, c["id"]):
        p = TrustPolicy(pinned=POLICY.pinned, authorities=POLICY.authorities, revoked=frozenset({revoked}))
        with pytest.raises(Refused):
            p.admit(AGENT.agent, [c], now=T0)
    with pytest.raises(Refused):
        TrustPolicy(pinned=POLICY.pinned, revoked=frozenset({STRANGER.agent})).admit(STRANGER.agent, now=T0)


def test_an_endorsement_cannot_be_dressed_up_as_another_kind():
    w = seal(AUTH, "request", {"subject": AGENT.agent, "domain": "lending"}, to=AGENT.agent, ttl_ms=9, now=T0).to_wire()
    assert "kind" in no(AGENT.agent, [w])
