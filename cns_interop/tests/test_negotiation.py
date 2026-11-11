"""Discovery, negotiation and selective disclosure: each side keeps its authority, and nothing is seen that was not agreed."""

from __future__ import annotations

import pytest

from cns_interop.disclosure import commit, open_disclosure
from cns_interop.envelope import Refused, seal
from cns_interop.identity import Signer
from cns_interop.manifest import Capability, publish, read_manifest
from cns_interop.negotiate import check_terms, propose_terms, request_body, terms_digest
from cns_interop.trust import TrustPolicy, endorse

T0 = 1_800_000_000_000
REQ = Signer(bytes([21] * 32))
DEC = Signer(bytes([22] * 32))
AUTH = Signer(bytes([23] * 32))
CAP = Capability(name="income-screen", version=1, summary="screens stated income against a threshold",
                 accepts=("doc_type", "monthly_income_cents", "employer"), requires=("monthly_income_cents",),
                 evidence=("threshold-check",), max_ttl_ms=300_000)
DOC = commit("loan-app-17", {"monthly_income_cents": 512_000, "doc_type": "paystub", "name": "Pat Doe",
                             "ssn": "000-00-0000"})


def req(**kw):
    args = dict(identity=DOC.identity, digest=DOC.digest, offer_fields=["monthly_income_cents", "doc_type"],
                require_evidence=["threshold-check"], max_ttl_ms=600_000)
    args.update(kw)
    return request_body("income-screen", 1, **args)


def code_of(fn, *a, **kw):
    with pytest.raises(Refused) as caught:
        fn(*a, **kw)
    return caught.value.code


# discovery

def test_a_manifest_is_read_back_and_its_sender_admitted_through_an_endorsement():
    card = endorse(AUTH, DEC.agent, "lending", ttl_ms=60_000, now=T0)
    m = publish(DEC, "screener", "python/cns_interop", [CAP], endorsements=[card], now=T0)
    trust = TrustPolicy(authorities={AUTH.agent: frozenset({"lending"})})
    manifest, admission = read_manifest(m.to_wire(), now=T0, trust=trust, domain="lending")
    assert manifest.capability("income-screen", 1) == CAP and admission.via == "endorsed"
    assert code_of(manifest.capability, "income-screen", 2) == "capability"


def test_a_manifest_from_an_unadmitted_sender_is_refused():
    m = publish(DEC, "screener", "x", [CAP], now=T0)
    assert code_of(read_manifest, m.to_wire(), now=T0, trust=TrustPolicy()) == "untrusted"


def test_no_shared_protocol_version_is_a_refusal_not_a_guess():
    body = publish(DEC, "screener", "x", [CAP], now=T0).body
    body["protocols"] = ["uai/9"]
    assert code_of(read_manifest, seal(DEC, "manifest", body, now=T0).to_wire(), now=T0) == "version"


@pytest.mark.parametrize("change", [
    lambda c: c.update(requires=["ssn"]), lambda c: c.update(version=0), lambda c: c.update(max_ttl_ms=-1),
    lambda c: c.update(accepts=["A"]), lambda c: c.update(extra=1), lambda c: c.update(accepts=["x", "x"]),
])
def test_a_malformed_capability_is_refused(change):
    body = publish(DEC, "screener", "x", [CAP], now=T0).body
    change(body["capabilities"][0])
    assert code_of(read_manifest, seal(DEC, "manifest", body, now=T0).to_wire(), now=T0) == "malformed"


# negotiation

def test_terms_are_the_intersection_and_both_sides_agree_on_them():
    terms = propose_terms(CAP, req(offer_fields=["monthly_income_cents", "doc_type", "name"]),
                          decider=DEC.agent, requester=REQ.agent)
    assert terms["disclose"] == ["doc_type", "monthly_income_cents"]  # "name" offered but not accepted: not seen
    assert terms["decision_ttl_ms"] == 300_000
    assert check_terms(terms, req(offer_fields=["monthly_income_cents", "doc_type", "name"]),
                       decider=DEC.agent, requester=REQ.agent) == terms
    assert len(terms_digest(terms)) == 64


def test_the_decider_refuses_when_a_required_field_is_withheld_or_evidence_is_unavailable():
    assert code_of(propose_terms, CAP, req(offer_fields=["doc_type"]), decider=DEC.agent,
                   requester=REQ.agent) == "terms"
    assert code_of(propose_terms, CAP, req(require_evidence=["credit-pull"]), decider=DEC.agent,
                   requester=REQ.agent) == "terms"


@pytest.mark.parametrize("tamper", [
    lambda t: t.update(disclose=["doc_type", "monthly_income_cents", "ssn"]),
    lambda t: t.update(decision_ttl_ms=10 ** 9), lambda t: t.update(evidence=[]),
    lambda t: t.update(subject={"identity": "loan-app-18", "digest": DOC.digest}),
    lambda t: t.update(decider=REQ.agent), lambda t: t.update(version=2),
])
def test_the_requester_refuses_terms_that_overreach(tamper):
    terms = propose_terms(CAP, req(), decider=DEC.agent, requester=REQ.agent)
    tamper(terms)
    assert code_of(check_terms, terms, req(), decider=DEC.agent, requester=REQ.agent) in {"terms", "malformed"}


# selective disclosure

def test_the_decider_sees_exactly_the_agreed_fields_and_the_whole_document_is_still_named():
    shown = DOC.reveal(["doc_type", "monthly_income_cents"])
    got = open_disclosure(DOC.digest, shown, ["doc_type", "monthly_income_cents"])
    assert got == {"doc_type": "paystub", "monthly_income_cents": 512_000}
    assert "ssn" in shown["commitments"] and "ssn" not in shown["disclosed"]


def test_over_disclosure_is_refused_not_ignored():
    assert code_of(open_disclosure, DOC.digest, DOC.reveal(["doc_type", "monthly_income_cents", "ssn"]),
                   ["doc_type", "monthly_income_cents"]) == "disclosure"


def test_under_disclosure_is_refused():
    assert code_of(open_disclosure, DOC.digest, DOC.reveal(["doc_type"]),
                   ["doc_type", "monthly_income_cents"]) == "disclosure"


def test_an_altered_value_or_commitment_does_not_open():
    shown = DOC.reveal(["monthly_income_cents"])
    shown["disclosed"]["monthly_income_cents"]["value"] = 999_999
    assert code_of(open_disclosure, DOC.digest, shown, ["monthly_income_cents"]) == "disclosure"
    shown = DOC.reveal(["monthly_income_cents"])
    shown["commitments"]["ssn"] = "0" * 64
    assert code_of(open_disclosure, DOC.digest, shown, ["monthly_income_cents"]) == "disclosure"


def test_salts_are_fresh_per_field_and_per_document():
    again = commit("loan-app-17", dict(DOC.values))
    assert again.digest != DOC.digest and len(set(DOC.salts.values())) == len(DOC.salts)
