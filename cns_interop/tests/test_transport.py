"""The TLS 1.3 mutual-authentication profile, over REAL handshakes with a throwaway PKI (pki.py). Nothing is mocked.

Shown: a UAI exchange across a mutually authenticated TLS 1.3 channel, with the peer identity bound to the object signer;
refusal of a client with no certificate, with a certificate from another CA, with an expired one, with a revoked one (CRL),
of a server whose name or identity is not the one dialled, of TLS 1.2, of plain TCP in either direction, of an oversized
frame, and of an object signed by someone other than the authenticated peer; certificate rotation for new connections; and
what is and is not on the wire (TLS hides the object, the local-process profile does not). NOT shown: OCSP, hardware keys,
revocation freshness, or any property of a deployment beyond this one machine."""

from __future__ import annotations

import json
import socket
import ssl
import struct
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from pki import CA  # type: ignore[import-not-found]  # noqa: E402

from cns_interop import transport as T  # noqa: E402
from cns_interop import wire  # noqa: E402
from cns_interop.envelope import Refused, seal  # noqa: E402
from cns_interop.identity import Signer  # noqa: E402

ALICE, BOB, MALLORY = Signer(bytes([1] * 32)), Signer(bytes([2] * 32)), Signer(bytes([3] * 32))
MARKER = "TOP-SECRET-MARKER-7f3a"


def code(fn, *a, **k):
    try:
        fn(*a, **k)
    except Refused as exc:
        return exc.code
    return "ok"


@pytest.fixture()
def pki(tmp_path):
    ca = CA(tmp_path)
    return SimpleNs(ca=ca, dir=tmp_path, server=ca.leaf("bob", BOB.agent), client=ca.leaf("alice", ALICE.agent))


class SimpleNs:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def cfgs(p, **over):
    server = T.TlsConfig(cert=p.server["cert"], key=p.server["key"], peer_ca=p.ca.pem, expected_peer=ALICE.agent)
    client = T.TlsConfig(cert=p.client["cert"], key=p.client["key"], peer_ca=p.ca.pem, expected_peer=BOB.agent)
    return server, client


def echo_handler(frame, who):
    env = T.open_bound(wire.loads(frame.decode()), who)       # the object's signature AND the channel's identity
    return json.dumps({"ok": True, "from": env.sender, "kind": env.kind, "saw": env.body.get("note")}).encode()


def request(note=MARKER, signer=ALICE):
    return json.dumps(seal(signer, "request", {"note": note}, ttl_ms=60_000).to_wire()).encode()


def test_a_uai_object_crosses_a_mutually_authenticated_tls13_channel_and_both_identities_are_proved(pki):
    scfg, ccfg = cfgs(pki)
    srv = T.TlsServer(scfg, echo_handler)
    try:
        reply, server_identity = T.tls_exchange(ccfg, srv.address, "localhost", request())
        got = json.loads(reply)
        assert got == {"ok": True, "from": ALICE.agent, "kind": "request", "saw": MARKER}
        assert server_identity == BOB.agent                                   # the client learned who it reached, too
    finally:
        srv.close()


def test_an_object_signed_by_someone_else_is_refused_on_a_connection_that_authenticated_alice(pki):
    scfg, ccfg = cfgs(pki)
    srv = T.TlsServer(scfg, echo_handler)
    try:
        with pytest.raises(Refused):
            T.tls_exchange(ccfg, srv.address, "localhost", request(signer=MALLORY))   # valid signature, wrong speaker
        assert code(T.open_bound, wire.loads(request(signer=MALLORY).decode()), ALICE.agent) == "untrusted"
    finally:
        srv.close()


def test_no_client_certificate_another_ca_an_expired_and_a_revoked_certificate_never_reach_the_application(pki, tmp_path):
    scfg, ccfg = cfgs(pki)
    calls = []
    srv = T.TlsServer(scfg, lambda f, w: calls.append(w) or b"{}")
    try:
        # no client certificate at all
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_verify_locations(cafile=pki.ca.pem)
        with pytest.raises((ssl.SSLError, OSError)), socket.create_connection(srv.address, timeout=5) as raw, \
                ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            T.send_frame(tls, request())
            T.recv_frame(tls)                                   # TLS 1.3 reports the rejection on first read
        # a certificate from a CA the server does not trust
        other = CA(tmp_path / "x" if (tmp_path / "x").mkdir() is None else tmp_path, name="other-ca")
        stranger = other.leaf("alice-other", ALICE.agent)
        bad = T.TlsConfig(cert=stranger["cert"], key=stranger["key"], peer_ca=pki.ca.pem, expected_peer=BOB.agent)
        assert code(T.tls_exchange, bad, srv.address, "localhost", request()) in ("untrusted", "unavailable")
        # an expired certificate from the right CA
        old = pki.ca.leaf("alice-old", ALICE.agent, days_valid=0, not_before_days=3)
        exp = T.TlsConfig(cert=old["cert"], key=old["key"], peer_ca=pki.ca.pem, expected_peer=BOB.agent)
        assert code(T.tls_exchange, exp, srv.address, "localhost", request()) in ("untrusted", "unavailable")
        assert calls == []                                      # the handler was never called for any of them
    finally:
        srv.close()
    # revoked: the server loads a CRL listing the client's certificate
    crl = pki.ca.revoke(pki.client)
    rscfg = T.TlsConfig(cert=pki.server["cert"], key=pki.server["key"], peer_ca=pki.ca.pem, crl=crl, expected_peer=ALICE.agent)
    srv = T.TlsServer(rscfg, lambda f, w: calls.append(w) or b"{}")
    try:
        assert code(T.tls_exchange, ccfg, srv.address, "localhost", request()) in ("untrusted", "unavailable")
        assert calls == []
    finally:
        srv.close()


def test_a_crl_that_cannot_be_used_fails_closed_rather_than_skipping_the_check(pki):
    crl = pki.ca.crl()
    other = CA(pki.dir / "o" if (pki.dir / "o").mkdir() is None else pki.dir, name="foreign")
    foreign_crl = other.crl()                                   # a CRL from a CA that did not issue these certificates
    scfg = T.TlsConfig(cert=pki.server["cert"], key=pki.server["key"], peer_ca=pki.ca.pem, crl=foreign_crl, expected_peer=ALICE.agent)
    _, ccfg = cfgs(pki)
    srv = T.TlsServer(scfg, lambda f, w: b"{}")
    try:
        assert code(T.tls_exchange, ccfg, srv.address, "localhost", request()) in ("untrusted", "unavailable")
    finally:
        srv.close()
    assert crl                                                   # (a CRL from the right CA is accepted: see the revoked test)


def test_a_server_with_the_wrong_name_or_the_wrong_identity_is_refused_by_the_client(pki):
    scfg, ccfg = cfgs(pki)
    srv = T.TlsServer(scfg, echo_handler)
    try:
        assert code(T.tls_exchange, ccfg, srv.address, "not-the-endpoint.example", request()) == "untrusted"   # name mismatch
        wrong = T.TlsConfig(cert=ccfg.cert, key=ccfg.key, peer_ca=ccfg.peer_ca, expected_peer=MALLORY.agent)
        assert code(T.tls_exchange, wrong, srv.address, "localhost", request()) == "untrusted"                 # identity mismatch
    finally:
        srv.close()


def test_a_certificate_that_names_no_uai_identity_or_two_is_refused(pki):
    scfg, ccfg = cfgs(pki)
    calls = []
    srv = T.TlsServer(T.TlsConfig(cert=pki.server["cert"], key=pki.server["key"], peer_ca=pki.ca.pem),
                      lambda f, w: calls.append(w) or b"{}")
    try:
        none = pki.ca.leaf("anon", "https://not-a-uai-identity.example")
        cfg = T.TlsConfig(cert=none["cert"], key=none["key"], peer_ca=pki.ca.pem)
        assert code(T.tls_exchange, cfg, srv.address, "localhost", request()) in ("unavailable", "untrusted")
        import time
        time.sleep(0.3)
        assert calls == [] and srv.handshakes_refused >= 1           # never handed to the application
    finally:
        srv.close()


def test_downgrade_is_refused_tls12_only_clients_and_plain_tcp_in_both_directions(pki):
    scfg, ccfg = cfgs(pki)
    srv = T.TlsServer(scfg, echo_handler)
    try:
        legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        legacy.minimum_version = legacy.maximum_version = ssl.TLSVersion.TLSv1_2
        legacy.load_verify_locations(cafile=pki.ca.pem)
        legacy.load_cert_chain(pki.client["cert"], pki.client["key"])
        with pytest.raises(ssl.SSLError), socket.create_connection(srv.address, timeout=5) as raw, \
                legacy.wrap_socket(raw, server_hostname="localhost"):
            pass
        before = srv.handshakes_refused
        with socket.create_connection(srv.address, timeout=5) as raw:       # plain bytes at a TLS server
            raw.sendall(struct.pack(">I", 5) + b"hello")
            raw.settimeout(2)
            try:
                data = raw.recv(100)
            except (OSError, TimeoutError):
                data = b""
            assert b"hello" not in data and b"ok" not in data              # nothing answered in the clear
        import time
        time.sleep(0.3)
        assert srv.handshakes_refused > before
    finally:
        srv.close()
    # a TLS client aimed at a plaintext server gets no answer it accepts
    plain = socket.socket()
    plain.bind(("127.0.0.1", 0))
    plain.listen(1)
    threading.Thread(target=lambda: (plain.accept()[0].sendall(b"\x00\x00\x00\x02{}"), None), daemon=True).start()
    try:
        assert code(T.tls_exchange, ccfg, plain.getsockname(), "localhost", request(), timeout_s=2) in ("untrusted", "unavailable")
    finally:
        plain.close()


def test_an_oversized_frame_is_refused_before_it_is_read(pki):
    scfg, ccfg = cfgs(pki)
    srv = T.TlsServer(scfg, echo_handler)
    try:
        ctx = T.client_context(ccfg)
        with socket.create_connection(srv.address, timeout=5) as raw, ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            tls.sendall(struct.pack(">I", T.MAX_FRAME + 1))          # announces more than UAI-1 allows, sends none of it
            tls.settimeout(2)
            try:
                got = tls.recv(10)
            except (OSError, TimeoutError):
                got = b""
            assert got == b""                                        # closed, nothing answered
        assert code(T.send_frame, None, b"x" * (T.MAX_FRAME + 1)) == "malformed"
    finally:
        srv.close()


def test_rotation_reload_applies_to_new_connections_and_a_retired_ca_stops_working(pki, tmp_path):
    scfg, ccfg = cfgs(pki)
    srv = T.TlsServer(scfg, echo_handler)
    try:
        assert json.loads(T.tls_exchange(ccfg, srv.address, "localhost", request())[0])["ok"]
        new_ca = CA(tmp_path / "rot" if (tmp_path / "rot").mkdir() is None else tmp_path, name="ca-2")
        server2, client2 = new_ca.leaf("bob2", BOB.agent), new_ca.leaf("alice2", ALICE.agent)
        srv.reload(T.TlsConfig(cert=server2["cert"], key=server2["key"], peer_ca=new_ca.pem, expected_peer=ALICE.agent))
        # the old client (old CA) is refused on a NEW connection
        assert code(T.tls_exchange, ccfg, srv.address, "localhost", request()) in ("untrusted", "unavailable")
        # a client on the new CA works
        c2 = T.TlsConfig(cert=client2["cert"], key=client2["key"], peer_ca=new_ca.pem, expected_peer=BOB.agent)
        assert json.loads(T.tls_exchange(c2, srv.address, "localhost", request())[0])["ok"]
        # a reload with unusable files raises and changes nothing
        with pytest.raises((ssl.SSLError, OSError)):
            srv.reload(T.TlsConfig(cert=str(tmp_path / "missing.pem"), key=server2["key"], peer_ca=new_ca.pem))
        assert json.loads(T.tls_exchange(c2, srv.address, "localhost", request())[0])["ok"]
    finally:
        srv.close()


def relay(target, seen):
    """A TCP relay that records every byte in both directions: what a network eavesdropper would capture."""
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)

    def pump(a, b):
        try:
            while (d := a.recv(4096)):
                seen.append(d)
                b.sendall(d)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def run():
        c, _ = ls.accept()
        u = socket.create_connection(target)
        threading.Thread(target=pump, args=(u, c), daemon=True).start()
        pump(c, u)
    threading.Thread(target=run, daemon=True).start()
    return ls


def test_tls_hides_the_object_on_the_wire_and_the_local_process_profile_does_not(pki):
    scfg, ccfg = cfgs(pki)
    srv = T.TlsServer(scfg, echo_handler)
    seen: list = []
    ls = relay(srv.address, seen)
    try:
        reply, _ = T.tls_exchange(ccfg, ls.getsockname(), "localhost", request())
        assert json.loads(reply)["saw"] == MARKER
        captured = b"".join(seen)
        assert captured and MARKER.encode() not in captured and b"request" not in captured      # confidentiality: TLS 1.3
    finally:
        ls.close()
        srv.close()
    # the same object over the local-process profile (a plain pipe) is readable by anyone who can read the pipe
    assert MARKER.encode() in request()
    assert T.PROFILES["local-process"]["confidential"] is False and T.PROFILES["tls13-mutual"]["confidential"] is True
    # and a signature alone (no TLS) hides nothing: the object is signed, not encrypted
    assert json.loads(request())["sig"] and MARKER in json.loads(request())["body"]["note"]
