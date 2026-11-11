"""The two Ed25519 backends accept exactly the same signatures, and a Signer never leaks its key by being serialized.

The `cryptography` package is in the dev extra, so these tests run in CI. If it is missing they FAIL (they do not
skip): a hardened backend that is never exercised is not a hardened backend.
"""

from __future__ import annotations

import copy
import json
import pickle
import random
import subprocess
import sys
from pathlib import Path

import pytest

from cns_interop import crypto_backend as cb
from cns_interop import ed25519
from cns_interop.identity import Signer, algorithm_of, is_agent_id
from cns_interop.tests.test_ed25519 import RFC8032  # type: ignore[import-not-found]

ROOT = Path(__file__).resolve().parents[2]
PURE, OSSL = cb.PureBackend(), cb.CryptographyBackend()
L = ed25519._L


def corpus():
    """Valid signatures and every mutation that has ever mattered: bit flips, a non-canonical s (s + L), non-canonical
    and small-order keys and R, truncations, wrong lengths."""
    rnd = random.Random(8032)
    out = []
    for seed_hex, pub_hex, msg_hex, sig_hex in RFC8032:
        pub, msg, sig = bytes.fromhex(pub_hex), bytes.fromhex(msg_hex), bytes.fromhex(sig_hex)
        out += [(pub, msg, sig), (pub, msg + b"x", sig)]
        for i in range(0, 64, 3):
            bad = bytearray(sig)
            bad[i] ^= 1 << rnd.randrange(8)
            out.append((pub, msg, bytes(bad)))
        s = int.from_bytes(sig[32:], "little")
        out.append((pub, msg, sig[:32] + int.to_bytes(s + L, 32, "little")))     # non-canonical s
        out += [(pub[:31], msg, sig), (pub, msg, sig[:63]), (pub, msg, sig + b"\0"), (b"", msg, b"")]
    for _ in range(40):
        seed = bytes(rnd.randrange(256) for _ in range(32))
        msg = bytes(rnd.randrange(256) for _ in range(rnd.randrange(80)))
        out.append((ed25519.public_key(seed), msg, ed25519.sign(seed, msg)))
    vec = json.loads((ROOT / "contracts" / "uai-vectors.json").read_text(encoding="utf-8"))
    for key in ("alice", "bob", "authority"):
        seed = bytes.fromhex(vec["seeds"][key]["seed"])
        out.append((ed25519.public_key(seed), b"uai", ed25519.sign(seed, b"uai")))
    # the eight small-order points, as public keys and as R, with and without a valid-looking s
    smalls = ["00" * 32, "00" * 31 + "80", "01" + "00" * 31, "ecff" + "ff" * 29 + "7f", "ecff" + "ff" * 29 + "ff",
              "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
              "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"]
    for sm in smalls:
        out.append((bytes.fromhex(sm), b"m", bytes.fromhex(sm) + b"\x00" * 32))
        out.append((bytes.fromhex(sm), b"m", bytes.fromhex(sm) + int.to_bytes(1, 32, "little")))
    return out


def test_both_backends_agree_on_every_case_in_the_corpus_and_the_corpus_has_both_answers():
    cases = corpus()
    answers = [(PURE.verify(p, m, s), OSSL.verify(p, m, s)) for p, m, s in cases]
    disagreements = [i for i, (a, b) in enumerate(answers) if a != b]
    assert disagreements == [], f"backends disagree on corpus cases {disagreements}"
    assert any(a for a, _ in answers) and not all(a for a, _ in answers)   # the corpus is not trivially one-sided


@pytest.mark.parametrize("seed_hex,pub_hex,msg_hex,sig_hex", RFC8032)
def test_the_cryptography_backend_reproduces_the_rfc_8032_answer_key(seed_hex, pub_hex, msg_hex, sig_hex):
    seed, msg = bytes.fromhex(seed_hex), bytes.fromhex(msg_hex)
    assert OSSL.public_key(seed).hex() == pub_hex
    assert OSSL.sign(seed, msg).hex() == sig_hex
    assert PURE.verify(bytes.fromhex(pub_hex), msg, OSSL.sign(seed, msg))
    assert OSSL.verify(bytes.fromhex(pub_hex), msg, PURE.sign(seed, msg))


def test_a_signature_from_either_backend_verifies_under_both_for_random_keys():
    rnd = random.Random(1)
    for _ in range(25):
        seed = bytes(rnd.randrange(256) for _ in range(32))
        msg = bytes(rnd.randrange(256) for _ in range(rnd.randrange(200)))
        a, b = PURE.sign(seed, msg), OSSL.sign(seed, msg)
        assert a == b                                   # Ed25519 is deterministic: the wire format is unchanged
        pub = PURE.public_key(seed)
        assert OSSL.verify(pub, msg, a) and PURE.verify(pub, msg, b)


def test_openssl_alone_accepts_a_small_order_key_and_the_backend_still_refuses_it():
    """Measured, not assumed: this is why the strict checks run before the library's. Do not remove them as
    redundant. (Raw OpenSSL does refuse a non-canonical s; it accepts the identity as a public key.)"""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    ident = bytes.fromhex("01" + "00" * 31)
    forged = ident + b"\x00" * 32
    Ed25519PublicKey.from_public_bytes(ident).verify(forged, b"any message at all")   # raises if OpenSSL refused it
    assert not OSSL.verify(ident, b"any message at all", forged) and not PURE.verify(ident, b"any message at all",
                                                                                      forged)


def test_the_backend_choice_is_explicit_and_an_unknown_one_raises():
    with pytest.raises(ValueError):
        cb._select("openssl-ish")
    assert cb.ALGORITHMS == {"ed25519"}


def _run(code: str, **env: str) -> subprocess.CompletedProcess:
    import os
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=ROOT,
                          env={**os.environ, **env})


def test_a_missing_cryptography_package_when_it_is_required_fails_loudly_with_no_fallback():
    block = ("import sys; sys.modules['cryptography']=None\n"
             "from cns_interop.identity import Signer\n"
             "Signer.generate()\n")
    done = _run(block, UAI_CRYPTO_BACKEND="cryptography")
    assert done.returncode != 0 and "no fallback" in done.stderr


def test_the_production_profile_refuses_to_sign_with_the_pure_backend_and_signs_with_the_other():
    refuse = _run("from cns_interop.identity import Signer\nSigner.generate()", UAI_PROFILE="production")
    assert refuse.returncode != 0 and "production profile" in refuse.stderr
    ok = _run("from cns_interop.identity import Signer\nfrom cns_interop.envelope import seal, open_envelope\n"
              "s=Signer.generate(); e=seal(s,'request',{'a':1},ttl_ms=60000); open_envelope(e.to_wire()); print('ok')",
              UAI_PROFILE="production", UAI_CRYPTO_BACKEND="cryptography")
    assert ok.returncode == 0 and "ok" in ok.stdout, ok.stderr


def test_a_signer_cannot_be_pickled_copied_or_deep_copied_so_its_seed_does_not_travel():
    s = Signer(bytes([7] * 32))
    for fn in (pickle.dumps, copy.copy, copy.deepcopy, lambda o: pickle.dumps(o, protocol=0)):
        with pytest.raises(TypeError):
            fn(s)
    assert "07" * 8 not in repr(s) and str(s).startswith("Signer(uai:ed25519:")


def test_an_external_signer_backed_by_a_key_held_outside_it_works_and_is_checked_against_its_identity():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    key = Ed25519PrivateKey.generate()        # stands in for an HSM or OS keystore: the key never enters Signer
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    agent = "uai:ed25519:" + pub.hex()
    ext = Signer.external(agent, key.sign)
    assert ext._seed is None and ext.sign(b"hello") and PURE.verify(pub, b"hello", ext.sign(b"hello"))
    wrong = Signer.external("uai:ed25519:" + "11" * 32, key.sign)
    with pytest.raises(ValueError):
        wrong.sign(b"hello")


def test_only_ed25519_identities_are_defined_and_others_are_refused_not_mapped():
    good = "uai:ed25519:" + "ab" * 32
    assert algorithm_of(good) == "ed25519" and is_agent_id(good)
    for bad in ("uai:ed448:" + "ab" * 57, "uai:secp256k1:" + "ab" * 32, "uai:none:", "uai:ed25519:" + "AB" * 32,
                "uai:ed25519:" + "ab" * 31, "uai::" + "ab" * 32, "uai:ed25519", "ed25519:" + "ab" * 32):
        assert not is_agent_id(bad)
        with pytest.raises(ValueError):
            algorithm_of(bad)


def test_the_production_profile_is_frozen_at_start_so_neither_use_nor_the_environment_can_downgrade_it():
    base = ("from cns_interop import crypto_backend as cb\n"
            "import os\n")
    # the backend must be named: no default, and `pure` is not acceptable
    for backend in ({}, {"UAI_CRYPTO_BACKEND": "pure"}):
        done = _run(base + "cb.current()", UAI_PROFILE="production", **backend)
        assert done.returncode != 0 and "explicitly" in done.stderr
    prod = {"UAI_PROFILE": "production", "UAI_CRYPTO_BACKEND": "cryptography"}
    # a running process cannot be moved to another backend, by use() ...
    done = _run(base + "cb.current()\ntry:\n cb.use('pure')\nexcept RuntimeError as e:\n print('refused', e)", **prod)
    assert done.returncode == 0 and "refused" in done.stdout, done.stderr
    # ... or by editing the environment after start: the profile and backend were read once
    done = _run(base + "cb.current()\nos.environ['UAI_PROFILE']=''\nos.environ['UAI_CRYPTO_BACKEND']='pure'\n"
                "print(cb.production(), cb.current().name, cb.diagnostics())", **prod)
    assert done.returncode == 0 and done.stdout.startswith("True cryptography"), done.stderr
    assert "'frozen': True" in done.stdout and "'profile': 'production'" in done.stdout


def test_outside_production_the_backend_can_be_set_until_it_is_frozen_and_diagnostics_report_it():
    code = ("from cns_interop import crypto_backend as cb\n"
            "cb.use('pure'); print(cb.diagnostics()['frozen'])\n"
            "cb.freeze()\n"
            "try:\n cb.use('cryptography')\nexcept RuntimeError as e:\n print('refused')\n"
            "cb.use('pure'); print(cb.diagnostics())\n")
    done = _run(code)
    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()
    assert lines[0] == "False" and lines[1] == "refused"
    assert "'backend': 'pure'" in lines[2] and "'frozen': True" in lines[2] and "'constant_time_claimed': False" in lines[2]
