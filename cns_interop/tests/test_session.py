"""A whole UAI-1 exchange in one test process, and every way the exchange is pushed off its rails.

The cross-process, cross-language version of the happy path is test_two_systems.py. This file is about the rails.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from cns.gate import GateOutcome, GatePosition, GateResult, subject_digest

from cns_composition.super_gate import Judged, SuperGate
from cns_interop.decision import RemoteDecisionGuard, issue, verify_decision
from cns_interop.disclosure import commit
from cns_interop.envelope import Refused, now_ms, seal
from cns_interop.identity import Signer
from cns_interop.ledger import FileLedger, MemoryLedger
from cns_interop.manifest import Capability
from cns_interop.negotiate import terms_digest
from cns_interop.session import Decider, Judgment, Requester
from cns_interop.trust import TrustPolicy

T0 = 1_800_000_000_000
REQ, DEC, EVE = Signer(bytes([31] * 32)), Signer(bytes([32] * 32)), Signer(bytes([33] * 32))
CAP = Capability(name="income-screen", version=1, summary="income at or above a threshold",
                 accepts=("doc_type", "monthly_income_cents"), requires=("monthly_income_cents",),
                 evidence=("threshold-check",), max_ttl_ms=300_000)
THRESHOLD = 400_000
DEC_ONLY = TrustPolicy(pinned=frozenset({DEC.agent}))
GUARD_CAP = (CAP.name, CAP.version)  # what the guards below protect: actions the income screen permits


def screen(cap, disclosed, subject):
    income = disclosed["monthly_income_cents"]
    check = {"threshold_cents": THRESHOLD, "observed_cents": income}
    if income >= THRESHOLD:
        return Judgment("pass", ("income meets the threshold",), {"threshold-check": check})
    return Judgment("retry", (f"income {income} is below {THRESHOLD}",))


class Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t


def pair(judge=screen, *, decider_trusts=None, clock=None, **decider_kw):
    clock = clock or Clock()
    dec = Decider(DEC, name="screener", implementation="python/test", capabilities=[(CAP, judge)],
                  trust=decider_trusts or TrustPolicy(pinned=frozenset({REQ.agent})), clock=clock, **decider_kw)
    req = Requester(REQ, trust=TrustPolicy(pinned=frozenset({DEC.agent})), clock=clock)
    req.discover(dec.manifest().to_wire())
    return dec, req, clock


def doc(income=512_000):
    return commit("loan-app-17", {"monthly_income_cents": income, "doc_type": "paystub", "ssn": "000-00-0000"})


def run(dec, req, document=None, **kw):
    document = document or doc()
    request = req.request(DEC.agent, document, "income-screen", 1, offer_fields=["monthly_income_cents", "doc_type"],
                          require_evidence=["threshold-check"], max_ttl_ms=kw.get("max_ttl_ms", 600_000))
    offer = dec.handle(request.to_wire())
    accept = req.on_reply(offer.to_wire())
    decision = dec.handle(accept.to_wire())
    return request, offer, accept, decision


def code_of(fn, *a, **kw):
    with pytest.raises(Refused) as caught:
        fn(*a, **kw)
    return caught.value.code


def test_the_whole_exchange_and_a_guard_that_acts_once_on_the_one_document():
    dec, req, clock = pair()
    _, offer, accept, decision = run(dec, req)
    terms = offer.body["terms"]
    assert terms["disclose"] == ["doc_type", "monthly_income_cents"]  # never the ssn
    assert "ssn" not in accept.body["disclosure"]["disclosed"]
    got = req.on_reply(decision.to_wire())
    assert got.allowed and got.evidence["threshold-check"]["observed_cents"] == 512_000

    # The same decision, verified independently by a separate guard (the process that acts), with its own ledger.
    guard = RemoteDecisionGuard(lambda a: a, acting_for=REQ.agent, capability=GUARD_CAP, trust=DEC_ONLY, ledger=MemoryLedger(), clock=clock)
    guard.authorize(decision.to_wire(), terms=terms, accept_digest=accept.digest)
    d = doc()
    assert guard(("loan-app-17", "some-other-digest")) is False
    assert guard(("loan-app-17", terms["subject"]["digest"])) is True
    assert guard(("loan-app-17", terms["subject"]["digest"])) is False  # one use
    assert d.digest != terms["subject"]["digest"]  # a re-commit of the same values is a different document


def test_a_below_threshold_decision_verifies_but_opens_nothing():
    dec, req, clock = pair()
    _, offer, accept, decision = run(dec, req, doc(100))
    got = req.on_reply(decision.to_wire())
    assert got.verdict == "retry" and not got.allowed
    guard = RemoteDecisionGuard(lambda a: a, acting_for=REQ.agent, capability=GUARD_CAP, trust=DEC_ONLY, ledger=MemoryLedger(), clock=clock)
    assert code_of(guard.authorize, decision.to_wire(), terms=offer.body["terms"],
                   accept_digest=accept.digest) == "refused"


def test_a_decision_is_accepted_once_per_ledger():
    dec, req, clock = pair()
    _, offer, accept, decision = run(dec, req)
    ledger = MemoryLedger()
    verify_decision(decision.to_wire(), terms=offer.body["terms"], accept_digest=accept.digest, ledger=ledger, now=T0)
    assert code_of(verify_decision, decision.to_wire(), terms=offer.body["terms"], accept_digest=accept.digest,
                   ledger=ledger, now=T0) == "replayed"


def test_a_file_ledger_is_shared_by_two_guards_as_if_two_processes(tmp_path):
    dec, req, clock = pair()
    _, offer, accept, decision = run(dec, req)
    path = tmp_path / "spent.jsonl"
    g1 = RemoteDecisionGuard(lambda a: a, acting_for=REQ.agent, capability=GUARD_CAP, trust=DEC_ONLY, ledger=FileLedger(path), clock=clock)
    g2 = RemoteDecisionGuard(lambda a: a, acting_for=REQ.agent, capability=GUARD_CAP, trust=DEC_ONLY, ledger=FileLedger(path), clock=clock)
    g1.authorize(decision.to_wire(), terms=offer.body["terms"], accept_digest=accept.digest)
    assert code_of(g2.authorize, decision.to_wire(), terms=offer.body["terms"],
                   accept_digest=accept.digest) == "replayed"


def test_a_decision_cannot_be_used_by_anyone_it_was_not_addressed_to():
    dec, req, clock = pair()
    _, offer, accept, decision = run(dec, req)
    stolen_terms = dict(offer.body["terms"], requester=EVE.agent)
    assert code_of(verify_decision, decision.to_wire(), terms=stolen_terms, accept_digest=accept.digest,
                   ledger=MemoryLedger(), now=T0) == "audience"


def test_a_decision_signed_by_anyone_but_the_decider_is_refused():
    dec, req, clock = pair()
    _, offer, accept, _ = run(dec, req)
    terms = offer.body["terms"]
    forged = seal(EVE, "decision", {"verdict": "pass", "terms_digest": terms_digest(terms),
                                    "subject": terms["subject"], "reasons": [], "evidence": [], "cns_root": ""},
                  to=REQ.agent, reply_to=accept, ttl_ms=1000, now=T0)
    assert code_of(req.on_reply, forged.to_wire()) == "untrusted"


def test_a_decision_for_another_accept_other_terms_or_too_long_a_life_is_refused():
    dec, req, clock = pair()
    _, offer, accept, decision = run(dec, req)
    terms = offer.body["terms"]
    assert code_of(verify_decision, decision.to_wire(), terms=terms, accept_digest="0" * 64,
                   ledger=MemoryLedger(), now=T0) == "terms"
    assert code_of(verify_decision, decision.to_wire(), terms=dict(terms, evidence=[]), accept_digest=accept.digest,
                   ledger=MemoryLedger(), now=T0) == "terms"
    long_lived = seal(DEC, "decision", dict(decision.body), to=REQ.agent, reply_to=accept,
                      ttl_ms=terms["decision_ttl_ms"] + 1, now=T0)
    assert code_of(verify_decision, long_lived.to_wire(), terms=terms, accept_digest=accept.digest,
                   ledger=MemoryLedger(), now=T0) == "terms"


def test_a_tampered_or_expired_decision_is_refused():
    dec, req, clock = pair()
    _, offer, accept, decision = run(dec, req)
    w = decision.to_wire()
    w["body"]["verdict"] = "pass"
    w["body"]["evidence"][0]["content"]["observed_cents"] = 1
    assert code_of(req.on_reply, w) == "signature"
    clock.t = decision.expires_at
    assert code_of(req.on_reply, decision.to_wire()) == "expired"


def test_evidence_must_match_its_digest_even_from_the_real_decider():
    dec, req, clock = pair()
    _, offer, accept, decision = run(dec, req)
    body = dict(decision.body)
    body["evidence"] = [dict(body["evidence"][0], digest="0" * 64)]
    resigned = seal(DEC, "decision", body, to=REQ.agent, reply_to=accept, ttl_ms=1000, now=T0)
    assert code_of(verify_decision, resigned.to_wire(), terms=offer.body["terms"], accept_digest=accept.digest,
                   ledger=MemoryLedger(), now=T0) == "malformed"


def test_an_unadmitted_requester_is_told_no_and_learns_why():
    dec, req, clock = pair(decider_trusts=TrustPolicy(), unknown_sender="refuse")  # the signed refusal is now opt-in (T2-1)
    request = req.request(DEC.agent, doc(), "income-screen", 1, offer_fields=["monthly_income_cents"],
                          max_ttl_ms=600_000)
    refuse = dec.handle(request.to_wire())
    assert refuse.kind == "refuse"
    with pytest.raises(Refused) as caught:
        req.on_reply(refuse.to_wire())
    assert caught.value.code == "declined" and "not pinned" in caught.value.reason


def test_a_requester_talks_only_to_deciders_it_admitted():
    req = Requester(REQ, trust=TrustPolicy(), clock=Clock())
    assert code_of(req.request, DEC.agent, doc(), "income-screen", 1, offer_fields=[], max_ttl_ms=1) == "untrusted"
    dec, _, _ = pair()
    assert code_of(req.discover, dec.manifest().to_wire()) == "untrusted"


def test_withholding_a_required_field_gets_a_reasoned_refusal_before_anything_is_disclosed():
    dec, req, clock = pair()
    request = req.request(DEC.agent, doc(), "income-screen", 1, offer_fields=["doc_type"], max_ttl_ms=600_000)
    refuse = dec.handle(request.to_wire())
    assert refuse.kind == "refuse" and refuse.body["code"] == "terms"


def test_a_requester_that_over_discloses_is_refused_and_the_extra_field_is_not_judged():
    seen = []
    dec, req, clock = pair(judge=lambda c, d, s: seen.append(d) or Judgment("pass"))
    request = req.request(DEC.agent, doc(), "income-screen", 1, offer_fields=["monthly_income_cents", "doc_type"],
                          max_ttl_ms=600_000)
    offer = dec.handle(request.to_wire())
    terms = offer.body["terms"]
    leaky = seal(REQ, "accept", {"terms_digest": terms_digest(terms),
                                 "disclosure": doc().reveal(["monthly_income_cents", "doc_type", "ssn"])},
                 to=DEC.agent, reply_to=offer, ttl_ms=1000, now=T0)
    reply = dec.handle(leaky.to_wire())
    assert reply.kind == "refuse" and reply.body["code"] == "disclosure" and seen == []


def test_replays_and_second_accepts_get_nothing():
    dec, req, clock = pair()
    request, offer, accept, _ = run(dec, req)
    assert code_of(dec.handle, request.to_wire()) == "replayed"
    assert code_of(dec.handle, accept.to_wire()) == "terms"  # the offer is closed after one accept


def test_a_message_that_never_expires_is_not_part_of_a_session():
    dec, req, clock = pair()
    forever = seal(REQ, "request", {}, to=DEC.agent, now=T0)
    assert code_of(dec.handle, forever.to_wire()) == "malformed"


def test_a_capability_that_crashes_or_misreports_decides_terminal_breach_signed():
    def crash(c, d, s):
        raise RuntimeError("model unavailable")

    for judge in (crash, lambda c, d, s: Judgment("pass", evidence={})):
        dec, req, clock = pair(judge=judge)
        *_, decision = run(dec, req)
        got = req.on_reply(decision.to_wire())
        assert got.verdict == "terminal_breach" and not got.allowed


# The bridge from an in-process CNS SuperGate to a portable decision.

class IncomeGate:
    name, position = "income", GatePosition.ALPHA

    def check(self, candidate):
        ok = candidate["income"] >= THRESHOLD
        return GateResult(gate=self.name, position=self.position,
                          outcome=GateOutcome.PASS if ok else GateOutcome.RETRY, reason="income checked",
                          subject=candidate["identity"], subject_digest=subject_digest({"c": candidate}))


class DocGate:
    name, position = "doctype", GatePosition.OMEGA

    def check(self, candidate):
        return GateResult(gate=self.name, position=self.position, outcome=GateOutcome.PASS, reason="doc type ok",
                          subject=candidate["identity"], subject_digest=subject_digest({"c": candidate}))


def roster_judge(cap, disclosed, subject):
    reads = {"Governance_Gateway:income": lambda c: Judged(c["identity"], c["digest"]),
             "DIT:doctype": lambda c: Judged(c["identity"], c["digest"])}
    gate = SuperGate([("Governance_Gateway", IncomeGate()), ("DIT", DocGate())],
                     required=("Governance_Gateway:income", "DIT:doctype", "CNS:same_subject"), same_subject=reads)
    cand = {"identity": subject["identity"], "digest": subject["digest"], "income": disclosed["monthly_income_cents"]}
    decision = gate.decide({"Governance_Gateway:income": cand, "DIT:doctype": cand})
    return decision, {"threshold-check": {"roster_root": decision.root}}


def test_a_super_gate_decision_crosses_the_boundary_with_its_root():
    dec, req, clock = pair(judge=roster_judge)
    *_, decision = run(dec, req)
    got = req.on_reply(decision.to_wire())
    assert got.allowed and len(got.cns_root) == 64 and got.evidence["threshold-check"]["roster_root"] == got.cns_root


def test_a_super_gate_refusal_crosses_as_a_refusal():
    dec, req, clock = pair(judge=roster_judge)
    *_, decision = run(dec, req, doc(1))
    got = req.on_reply(decision.to_wire())
    assert got.verdict == "retry" and got.reasons


def test_a_hand_built_cns_decision_is_not_laundered_into_a_signature():
    from dataclasses import replace

    def forged(cap, disclosed, subject):
        decision, ev = roster_judge(cap, disclosed, subject)
        return replace(decision, proof="0" * 64), ev

    dec, req, clock = pair(judge=forged)
    *_, decision = run(dec, req)
    got = req.on_reply(decision.to_wire())
    assert got.verdict == "terminal_breach" and "SuperGate in this process" in got.reasons[0]


def test_issue_refuses_a_pass_without_its_evidence_and_a_signer_who_is_not_the_decider():
    dec, req, clock = pair()
    _, offer, accept, _ = run(dec, req)
    with pytest.raises(ValueError):
        issue(DEC, accept, offer.body["terms"], "pass", evidence={}, now=T0)
    with pytest.raises(ValueError):
        issue(EVE, accept, offer.body["terms"], "retry", now=T0)


def test_an_accept_that_arrives_after_its_offer_lapsed_is_refused():
    dec, _, clock = pair()
    req = Requester(REQ, trust=TrustPolicy(pinned=frozenset({DEC.agent})), clock=clock, message_ttl_ms=600_000)
    req.discover(dec.manifest().to_wire())
    request = req.request(DEC.agent, doc(), "income-screen", 1, offer_fields=["monthly_income_cents", "doc_type"],
                          require_evidence=["threshold-check"], max_ttl_ms=600_000)
    offer = dec.handle(request.to_wire())
    accept = req.on_offer(offer.to_wire())
    clock.t = offer.expires_at
    with pytest.raises(Refused) as caught:
        dec.handle(accept.to_wire())
    assert caught.value.code == "expired" and "offer" in caught.value.reason  # the offer lapsed, not the accept


# Findings of the independent review (2026-10-30), each kept as a test.

def test_a_guard_trusts_its_own_list_of_deciders_not_the_terms_it_is_handed():
    dec, req, clock = pair()
    _, offer, accept, _ = run(dec, req)
    forged_terms = dict(offer.body["terms"], decider=EVE.agent)
    forged = issue(EVE, accept, forged_terms, "pass", evidence={"threshold-check": {}}, now=T0)
    guard = RemoteDecisionGuard(lambda a: a, acting_for=REQ.agent, capability=GUARD_CAP, trust=DEC_ONLY, ledger=MemoryLedger(), clock=clock)
    assert code_of(guard.authorize, forged.to_wire(), terms=forged_terms, accept_digest=accept.digest) == "untrusted"


def test_a_guard_acts_only_for_its_own_identity():
    dec, req, clock = pair()
    _, offer, accept, decision = run(dec, req)
    guard = RemoteDecisionGuard(lambda a: a, acting_for=EVE.agent, capability=GUARD_CAP, trust=DEC_ONLY, ledger=MemoryLedger(), clock=clock)
    assert code_of(guard.authorize, decision.to_wire(), terms=offer.body["terms"],
                   accept_digest=accept.digest) == "audience"


def test_a_guard_opens_once_under_concurrent_calls():
    import threading
    import time

    dec, req, clock = pair()
    _, offer, accept, decision = run(dec, req)
    digest = offer.body["terms"]["subject"]["digest"]

    def slow(a):
        time.sleep(0.05)
        return a

    guard = RemoteDecisionGuard(slow, acting_for=REQ.agent, capability=GUARD_CAP, trust=DEC_ONLY, ledger=MemoryLedger(), clock=clock)
    guard.authorize(decision.to_wire(), terms=offer.body["terms"], accept_digest=accept.digest)
    results = []
    threads = [threading.Thread(target=lambda: results.append(guard(("loan-app-17", digest)))) for _ in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert sorted(results) == [False] * 7 + [True]


def test_a_decision_from_anyone_else_does_not_use_up_the_accept():
    dec, req, clock = pair()
    _, offer, accept, decision = run(dec, req)
    terms = offer.body["terms"]
    junk = seal(EVE, "decision", {"verdict": "retry", "terms_digest": terms_digest(terms), "subject": terms["subject"],
                                  "reasons": [], "evidence": [], "cns_root": ""},
                to=REQ.agent, reply_to=accept, ttl_ms=1000, now=T0)
    assert code_of(req.on_decision, junk.to_wire()) == "untrusted"
    assert req.on_decision(decision.to_wire()).allowed  # the genuine decision still lands


def test_an_unadmitted_manifest_leaves_nothing_behind_and_endorsement_piles_are_not_read():
    from cns_interop.manifest import publish
    from cns_interop.trust import MAX_ENDORSEMENTS, endorse

    dec, req, clock = pair(decider_trusts=TrustPolicy())
    stranger_manifest = publish(EVE, "x", "x", [], now=T0)
    assert code_of(dec.handle, stranger_manifest.to_wire()) == "untrusted"
    assert dec._admitted == {}
    pile = [endorse(DEC, EVE.agent, "d", ttl_ms=1000, now=T0) for _ in range(MAX_ENDORSEMENTS + 1)]
    assert code_of(dec.handle, publish(EVE, "x", "x", [], endorsements=pile, now=T0).to_wire()) == "malformed"


def test_an_endorsed_requester_is_admitted_once_and_until_the_endorsement_lapses():
    from cns_interop.trust import endorse

    auth = Signer(bytes([34] * 32))
    clock = Clock()
    dec = Decider(DEC, name="screener", implementation="python/test", capabilities=[(CAP, screen)],
                  trust=TrustPolicy(authorities={auth.agent: frozenset({"lending"})}), clock=clock)
    req = Requester(REQ, trust=DEC_ONLY, clock=clock)
    req.discover(dec.manifest().to_wire())
    card = endorse(auth, REQ.agent, "lending", ttl_ms=30_000, now=T0)
    assert dec.handle(req.manifest(endorsements=[card]).to_wire()) is None
    first = req.request(DEC.agent, doc(), "income-screen", 1, offer_fields=["monthly_income_cents"],
                        max_ttl_ms=600_000)
    assert dec.handle(first.to_wire()).kind == "offer"
    clock.t = T0 + 30_000
    late = req.request(DEC.agent, doc(), "income-screen", 1, offer_fields=["monthly_income_cents"],
                       max_ttl_ms=600_000)
    with pytest.raises(Refused) as lapsed:  # T2-1: a sender no longer admitted is dropped, with no signed reply
        dec.handle(late.to_wire())
    assert lapsed.value.code == "untrusted" and dec.dropped == 1


def test_a_session_message_cannot_ask_to_be_remembered_forever():
    dec, req, clock = pair()
    forever_ish = seal(REQ, "request", {}, to=DEC.agent, ttl_ms=2 ** 52, now=T0)
    assert code_of(dec.handle, forever_ish.to_wire()) == "malformed"


# Judging a document the decider already holds: nothing is disclosed (UAI-1 section 6).

HELD_CAP = Capability(name="held-document", version=1, summary="judges a document the decider already holds",
                      accepts=(), requires=(), evidence=(), max_ttl_ms=60_000)


def held_pair(judge):
    clock = Clock()
    dec = Decider(DEC, name="roster", implementation="python/test", capabilities=[(HELD_CAP, judge)],
                  trust=TrustPolicy(pinned=frozenset({REQ.agent})), clock=clock)
    req = Requester(REQ, trust=DEC_ONLY, clock=clock)
    req.discover(dec.manifest().to_wire())
    return dec, req, clock


def test_a_judgment_of_a_held_document_discloses_nothing_and_binds_the_document_named():
    seen = []
    dec, req, clock = held_pair(lambda c, d, s: seen.append((d, s)) or Judgment("pass"))
    request = req.request_judgment(DEC.agent, "doc-1", "ab" * 32, "held-document", 1, max_ttl_ms=60_000)
    offer = dec.handle(request.to_wire())
    accept = req.on_offer(offer.to_wire())
    assert offer.body["terms"]["disclose"] == [] and accept.body["disclosure"] is None
    got = req.on_decision(dec.handle(accept.to_wire()).to_wire())
    assert got.allowed and got.subject == {"identity": "doc-1", "digest": "ab" * 32}
    assert seen == [({}, {"identity": "doc-1", "digest": "ab" * 32})]


def test_when_nothing_was_agreed_nothing_may_arrive():
    dec, req, clock = held_pair(lambda c, d, s: Judgment("pass"))
    request = req.request_judgment(DEC.agent, "doc-1", "ab" * 32, "held-document", 1, max_ttl_ms=60_000)
    offer = dec.handle(request.to_wire())
    terms = offer.body["terms"]
    leaky = seal(REQ, "accept", {"terms_digest": terms_digest(terms), "disclosure": doc().reveal(["ssn"])},
                 to=DEC.agent, reply_to=offer, ttl_ms=1000, now=T0)
    reply = dec.handle(leaky.to_wire())
    assert reply.kind == "refuse" and reply.body["code"] == "disclosure"


# Audit 2026-10-30: a guard knows which capability it protects.

INGEST = Capability(name="ingest", version=1, summary="take the document in", accepts=("doc_type",), requires=(),
                    evidence=(), max_ttl_ms=300_000)


def ingest_exchange():
    """One decider offering the income screen and `ingest`; the requester asks for `ingest` of a document."""
    clock = Clock()
    dec = Decider(DEC, name="screener", implementation="python/test",
                  capabilities=[(CAP, screen), (INGEST, lambda cap, disclosed, subject: Judgment("pass", ("taken in",)))],
                  trust=TrustPolicy(pinned=frozenset({REQ.agent})), clock=clock)
    req = Requester(REQ, trust=TrustPolicy(pinned=frozenset({DEC.agent})), clock=clock)
    req.discover(dec.manifest().to_wire())
    request = req.request(DEC.agent, doc(), "ingest", 1, offer_fields=["doc_type"], require_evidence=[],
                          max_ttl_ms=100_000)
    offer = dec.handle(request.to_wire())
    accept = req.on_reply(offer.to_wire())
    return offer, accept, dec.handle(accept.to_wire()), clock


def test_a_decision_negotiated_for_one_capability_does_not_open_a_guard_for_another():
    offer, accept, decision, clock = ingest_exchange()
    terms = offer.body["terms"]
    assert terms["capability"] == "ingest"
    guard = RemoteDecisionGuard(lambda a: a, acting_for=REQ.agent, capability=GUARD_CAP, trust=DEC_ONLY,
                                ledger=MemoryLedger(), clock=clock)
    assert code_of(guard.authorize, decision.to_wire(), terms=terms, accept_digest=accept.digest) == "terms"
    assert guard(("loan-app-17", terms["subject"]["digest"])) is False


def test_a_decision_for_another_version_of_the_capability_is_refused():
    offer, accept, decision, clock = ingest_exchange()
    terms = offer.body["terms"]
    newer = RemoteDecisionGuard(lambda a: a, acting_for=REQ.agent, capability=("ingest", 2), trust=DEC_ONLY,
                                ledger=MemoryLedger(), clock=clock)
    assert code_of(newer.authorize, decision.to_wire(), terms=terms, accept_digest=accept.digest) == "terms"


def test_a_capability_refusal_spends_nothing_and_the_matching_guard_still_opens():
    offer, accept, decision, clock = ingest_exchange()
    terms, ledger = offer.body["terms"], MemoryLedger()
    wrong = RemoteDecisionGuard(lambda a: a, acting_for=REQ.agent, capability=GUARD_CAP, trust=DEC_ONLY,
                                ledger=ledger, clock=clock)
    assert code_of(wrong.authorize, decision.to_wire(), terms=terms, accept_digest=accept.digest) == "terms"
    right = RemoteDecisionGuard(lambda a: a, acting_for=REQ.agent, capability=("ingest", 1), trust=DEC_ONLY,
                                ledger=ledger, clock=clock)
    right.authorize(decision.to_wire(), terms=terms, accept_digest=accept.digest)
    assert right(("loan-app-17", terms["subject"]["digest"])) is True


def test_a_guard_must_be_told_its_capability_and_it_must_be_a_name_and_a_version():
    kw = dict(acting_for=REQ.agent, trust=DEC_ONLY, ledger=MemoryLedger())
    with pytest.raises(TypeError):
        RemoteDecisionGuard(lambda a: a, **kw)  # type: ignore[call-arg]
    for bad in ("income-screen", ("income-screen",), ("", 1), ("Income Screen", 1), ("income-screen", 0),
                ("income-screen", True), ("income-screen", "1"), (None, 1), ["income-screen", 1, 2]):
        with pytest.raises(ValueError):
            RemoteDecisionGuard(lambda a: a, capability=bad, **kw)  # type: ignore[arg-type]
    RemoteDecisionGuard(lambda a: a, capability=["income-screen", 1], **kw)  # a list reads the same as a tuple


def test_a_guard_closes_when_its_decider_is_revoked_after_it_was_authorized():
    dec, req, clock = pair()
    _, offer, accept, decision = run(dec, req)
    terms = offer.body["terms"]
    trust = TrustPolicy(pinned=frozenset({DEC.agent}))  # this guard's own policy, so the revocation touches no other
    guard = RemoteDecisionGuard(lambda a: a, acting_for=REQ.agent, capability=GUARD_CAP, trust=trust,
                                ledger=MemoryLedger(), clock=clock)
    guard.authorize(decision.to_wire(), terms=terms, accept_digest=accept.digest)
    # The receiver revokes the decider. The policy is frozen, so it is updated the way TrustPolicy itself does it.
    object.__setattr__(trust, "revoked", frozenset({DEC.agent}))
    assert guard(("loan-app-17", terms["subject"]["digest"])) is False


def test_a_revocation_of_someone_else_leaves_an_authorized_guard_open():
    dec, req, clock = pair()
    _, offer, accept, decision = run(dec, req)
    terms = offer.body["terms"]
    trust = TrustPolicy(pinned=frozenset({DEC.agent}))
    guard = RemoteDecisionGuard(lambda a: a, acting_for=REQ.agent, capability=GUARD_CAP, trust=trust,
                                ledger=MemoryLedger(), clock=clock)
    guard.authorize(decision.to_wire(), terms=terms, accept_digest=accept.digest)
    object.__setattr__(trust, "revoked", frozenset({EVE.agent}))
    assert guard(("loan-app-17", terms["subject"]["digest"])) is True


# Audit 2026-10-30: interop/act.py reads its job as strictly as UAI-1 reads an envelope.

ACT_PY = Path(__file__).resolve().parents[2] / "interop" / "act.py"


def act_job():
    """A real, current decision as the job interop/act.py would be handed. Real clock: act.py has no other."""
    dec, req, _ = pair(clock=now_ms)
    _, offer, accept, decision = run(dec, req)
    terms = offer.body["terms"]
    return {"decision": decision.to_wire(), "terms": terms, "accept_digest": accept.digest,
            "artifact": ["loan-app-17", terms["subject"]["digest"]]}


def run_act(stdin, ledger, *, capability="income-screen", version=1):
    root = str(ACT_PY.parents[1])
    env = {"PYTHONPATH": root, "PATH": "/usr/bin:/bin"}
    done = subprocess.run([sys.executable, str(ACT_PY), "--acting-for", REQ.agent, "--capability", capability,
                           "--capability-version", str(version), "--trust", DEC.agent, "--ledger", str(ledger),
                           "--decision-only"],
                          input=stdin, capture_output=True, text=True, env=env, timeout=60)
    assert done.returncode == 0, done.stderr  # a refusal is an answer, not a crash
    return json.loads(done.stdout)


def test_act_py_permits_one_action_on_a_real_job_and_only_for_its_own_capability(tmp_path):
    job = json.dumps(act_job())
    assert run_act(job, tmp_path / "other.jsonl", capability="ingest")["refused"]["code"] == "terms"
    assert run_act(job, tmp_path / "other.jsonl", version=2)["refused"]["code"] == "terms"
    assert run_act(job, tmp_path / "spent.jsonl") == {"permitted": True}
    assert run_act(job, tmp_path / "spent.jsonl")["refused"]["code"] == "replayed"


@pytest.mark.parametrize("bad, code", [
    (lambda text: text[:-1] + ', "artifact": ["loan-app-17", "some-other-digest"]}', "malformed"),  # a key twice
    (lambda text: text[:-1] + ', "note": 1.5}', "profile"),  # a float, even where nothing reads it
    (lambda text: text[:-1] + ', "note": NaN}', "malformed"),
    (lambda text: text[:-1] + ', "note": Infinity}', "malformed"),
    (lambda text: "not json at all", "malformed"),
    (lambda text: "[1, 2]", "malformed"),
], ids=["duplicate-key", "float", "nan", "infinity", "not-json", "not-an-object"])
def test_act_py_refuses_a_job_that_is_not_read_strictly_and_spends_nothing(tmp_path, bad, code):
    job = json.dumps(act_job())
    ledger = tmp_path / "spent.jsonl"
    assert run_act(bad(job), ledger)["refused"]["code"] == code
    assert ledger.read_text() == ""  # nothing was verified, so nothing was spent
    assert run_act(job, ledger) == {"permitted": True}  # and the genuine job still lands


# Follow-up to the 2026-10-30 audit: a live guard can be told to stop trusting a decider.

def authorized_guard(trust=None):
    dec, req, clock = pair()
    _, offer, accept, decision = run(dec, req)
    terms = offer.body["terms"]
    trust = trust or TrustPolicy(pinned=frozenset({DEC.agent}))
    guard = RemoteDecisionGuard(lambda a: a, acting_for=REQ.agent, capability=GUARD_CAP, trust=trust,
                                ledger=MemoryLedger(), clock=clock)
    return guard, decision, terms, accept, ("loan-app-17", terms["subject"]["digest"])


def test_revoke_closes_an_authorized_guard_without_touching_the_policy_it_was_given():
    trust = TrustPolicy(pinned=frozenset({DEC.agent}))
    guard, decision, terms, accept, artifact = authorized_guard(trust)
    guard.authorize(decision.to_wire(), terms=terms, accept_digest=accept.digest)
    guard.revoke(DEC.agent)
    assert guard(artifact) is False
    assert trust.revoked == frozenset()  # the caller's policy is theirs; the guard keeps its own


def test_revoke_before_authorize_makes_authorize_refuse_the_decider():
    guard, decision, terms, accept, artifact = authorized_guard()
    guard.revoke(DEC.agent)
    assert code_of(guard.authorize, decision.to_wire(), terms=terms, accept_digest=accept.digest) == "untrusted"
    assert guard(artifact) is False


def test_revoking_someone_else_changes_nothing_and_revoking_twice_is_harmless():
    guard, decision, terms, accept, artifact = authorized_guard()
    guard.authorize(decision.to_wire(), terms=terms, accept_digest=accept.digest)
    guard.revoke(EVE.agent)
    guard.revoke(EVE.agent)
    assert guard(artifact) is True


def test_revoke_takes_an_agent_identity():
    guard, *_ = authorized_guard()
    for bad in ("", "not-an-identity", None, 7):
        with pytest.raises(ValueError):
            guard.revoke(bad)  # type: ignore[arg-type]
