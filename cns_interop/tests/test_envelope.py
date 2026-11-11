"""The envelope: what a receiver accepts, and every way a sender or a channel could try to make it accept something else."""

from __future__ import annotations

import json

import pytest

from cns_interop import ed25519, wire
from cns_interop.envelope import Refused, open_envelope, seal
from cns_interop.identity import Signer, agent_id, public_of

T0 = 1_800_000_000_000
A = Signer(bytes(range(32)))
B = Signer(bytes(range(1, 33)))


def sent(**kw):
    env = seal(A, "request", {"capability": "screen", "n": 3, "tags": ["x", None, True]}, to=B.agent, now=T0,
               ttl_ms=60_000, **kw)
    return json.loads(wire.dumps(env))


def refused(w, code, **kw):
    kw.setdefault("now", T0)
    with pytest.raises(Refused) as caught:
        open_envelope(w, **kw)
    assert caught.value.code == code, caught.value.reason
    return caught.value


def test_an_envelope_survives_the_wire_and_reads_back_as_sent():
    w = sent()
    env = open_envelope(wire.loads(json.dumps(w, indent=3, sort_keys=False)), now=T0, audience=B.agent)
    assert env.sender == A.agent and env.to == B.agent and env.body["n"] == 3 and env.expires_at == T0 + 60_000


def test_identity_is_the_public_key_and_round_trips():
    assert public_of(A.agent) == ed25519.public_key(bytes(range(32)))
    assert agent_id(public_of(A.agent)) == A.agent
    for bad in ("uai:ed25519:" + "A" * 64, "uai:ed25519:" + "0" * 63, "uai:rsa:" + "0" * 64, "", None):
        with pytest.raises(ValueError):
            public_of(bad)


@pytest.mark.parametrize("field,value", [
    ("kind", "offer"), ("id", "0" * 32), ("from", B.agent), ("to", A.agent), ("conversation", "f" * 32),
    ("in_reply_to", "a" * 64), ("issued_at", T0 - 1), ("expires_at", T0 + 999_999), ("body", {"capability": "x"}),
])
def test_changing_any_signed_field_after_signing_is_caught(field, value):
    w = sent()
    w[field] = value
    refused(w, "signature")


def test_a_body_change_deep_inside_is_caught():
    w = sent()
    w["body"]["tags"][2] = False
    refused(w, "signature")


def test_a_valid_signature_moved_onto_another_senders_name_is_caught():
    w = sent()
    w["from"] = B.agent
    refused(w, "signature")


def test_exactly_the_defined_fields():
    w = sent()
    w["extra"] = 1
    refused(w, "malformed")
    w = sent()
    del w["to"]
    refused(w, "malformed")


def test_another_version_is_refused_not_guessed_at():
    w = sent()
    w["v"] = "uai/2"
    refused(w, "version")


def test_kind_must_be_known_and_wanted():
    w = sent()
    w["kind"] = ["request"]
    refused(w, "malformed")
    refused(sent(), "kind", kinds={"decision"})


def test_time_bounds():
    refused(sent(), "expired", now=T0 + 60_000)
    refused(sent(), "not_yet_valid", now=T0 - 120_001)
    assert open_envelope(sent(), now=T0 - 120_000).id


def test_audience():
    refused(sent(), "audience", audience=A.agent)


@pytest.mark.parametrize("body,code", [
    ({"x": 1.5}, "profile"), ({"x": 2 ** 53}, "profile"), ({"x": b"bytes"}, "profile"), ({"x": "\ud800"}, "profile"),
    ({"x": {1: "a"}}, "profile"),
])
def test_the_value_profile_is_enforced_when_sealing(body, code):
    with pytest.raises(Refused) as caught:
        seal(A, "request", body, now=T0)
    assert caught.value.code == code


def test_deep_nesting_is_refused():
    body: dict = {}
    cur = body
    for _ in range(40):
        cur["n"] = {}
        cur = cur["n"]
    with pytest.raises(Refused):
        seal(A, "request", body)


@pytest.mark.parametrize("text,code", [
    ('{"a":1,"a":2}', "malformed"), ('{"a":1.0}', "profile"), ('{"a":1e3}', "profile"), ('{"a":NaN}', "malformed"),
    ("[1]", "malformed"), ("not json", "malformed"), (b"\xff", "malformed"),
])
def test_the_wire_reader_is_strict(text, code):
    with pytest.raises(Refused) as caught:
        wire.loads(text)
    assert caught.value.code == code


def test_an_oversized_message_is_refused_before_parsing():
    with pytest.raises(Refused):
        wire.loads('{"a":"' + "x" * (1 << 20) + '"}')


def test_a_reply_is_bound_to_the_exact_envelope_it_answers():
    req = open_envelope(sent(), now=T0)
    reply = seal(B, "offer", {"ok": True}, to=A.agent, reply_to=req, now=T0)
    assert reply.conversation == req.conversation and reply.in_reply_to == req.digest


def test_an_external_signer_is_checked_before_its_signature_leaves():
    good = Signer.external(A.agent, lambda m: ed25519.sign(bytes(range(32)), m))
    open_envelope(json.loads(wire.dumps(seal(good, "request", {}, now=T0))), now=T0)
    wrong_key = Signer.external(A.agent, lambda m: ed25519.sign(bytes(range(1, 33)), m))
    with pytest.raises(ValueError):
        seal(wrong_key, "request", {}, now=T0)


def test_a_signer_never_shows_its_key():
    assert bytes(range(32)).hex() not in repr(A) and "seed" not in repr(A)


@pytest.mark.parametrize("text", ["[" * 100_000 + "]" * 100_000, '{"a":' + "9" * 5000 + "}"])
def test_hostile_json_is_refused_not_a_crash(text):
    with pytest.raises(Refused):
        wire.loads(text)
