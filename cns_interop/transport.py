"""transport: UAI-1 security profiles, and one implemented network profile (TLS 1.3 with mutual authentication).

TRANSPORT SECURITY AND OBJECT SECURITY ARE DIFFERENT THINGS, AND THIS MODULE KEEPS THEM APART.
  * An envelope's signature (envelope.py) proves WHO made an object and that it was not changed. It is checked on every
    object whatever carried it, and it encrypts nothing.
  * A transport profile says what protects the CHANNEL: who is on the other end of the connection, and whether others can
    read or alter the bytes in flight. Neither one replaces the other. A signature is not confidentiality; TLS is not
    authorship of an object; neither is permission to act (grants.py is the receiver's permission).

THE PROFILES (named, so a deployment says which one it runs and a reader knows what it does and does not get)

  local-process   stdin/stdout pipes or a Unix socket between processes on ONE host. Protection is the operating system's
                  (file and process permissions). No encryption and no peer authentication at the channel; object signatures
                  still apply. Acceptable only for a host the operator controls. Confidentiality: the OS, nothing here.
  tls13-mutual    TCP with TLS 1.3 ONLY, both sides present certificates, each verifies the other against a CA the receiver
                  chose, and the certificate's identity is bound to a UAI identity (below). Gives peer authentication,
                  confidentiality and integrity in flight. Required for any traffic that leaves the host or a trusted
                  segment. Not provided: anything about the object (signatures), permission (grants), or the endpoints'
                  software. There is no weaker TLS profile: TLS 1.2 and below, and plain TCP, are refused, not negotiated.
  (anything else) Not defined. An implementation that offers an unlisted profile must say it is outside UAI-1.

IDENTITY BINDING. A certificate names a UAI identity in a subjectAltName URI exactly equal to the identity text
(`uai:ed25519:<64 hex>`). After the handshake the peer's identity is read from the verified certificate. The receiver passes
every object received on that connection through `open_bound`, which refuses an object whose signer is not the identity the
certificate proved: a peer cannot speak for another identity over its own channel. The pinned identity a peer is EXPECTED to
have is the receiver's own configuration (`expected_peer`), never something the peer says.

CERTIFICATES. The CA(s) are a file the receiver names. A peer certificate that does not chain to them, is expired or not yet
valid, or whose hostname does not match the endpoint (client side) fails the handshake. REVOCATION: give `crl` and OpenSSL
checks the peer's leaf against it; with `crl` set and no usable CRL the handshake fails (closed), and nothing here refreshes
the list: the operator replaces the file and calls `reload()`, which applies to NEW connections only (an open connection keeps
the certificate it was authenticated with until it closes). ROTATION is the same: new certificate files, `reload()`.

FAILURE. Every failure (handshake, certificate, identity, frame size, timeout, early close) is Refused: 'untrusted' when the
peer or its identity is not acceptable, 'unavailable' when no answer could be had. Nothing falls back to a weaker profile.

NOT CLAIMED. Revocation freshness (an out-of-date CRL file is only as good as its last replacement), OCSP, hardware-held
keys (a key file is read into this process), certificate transparency, post-quantum security, and any traffic analysis
resistance. TLS 1.3 session resumption and 0-RTT are left at the library's defaults (0-RTT is not enabled by this module).
"""

from __future__ import annotations

import socket
import ssl
import struct
import threading
from dataclasses import dataclass
from typing import Any, Callable, Optional, Tuple

from .envelope import Envelope, Refused, open_envelope
from .identity import is_agent_id

__all__ = ["PROFILES", "TlsConfig", "server_context", "client_context", "peer_identity", "open_bound", "TlsServer",
           "tls_exchange", "MAX_FRAME"]

PROFILES = {
    "local-process": {"channel_authenticated": False, "confidential": False, "network": False},
    "tls13-mutual": {"channel_authenticated": True, "confidential": True, "network": True},
}
MAX_FRAME = 1 << 20  # one UAI message is at most 1 MiB (wire.py); a longer frame is refused before it is read


@dataclass(frozen=True)
class TlsConfig:
    """Everything a TLS profile needs, from the RECEIVER's own configuration."""

    cert: str                         # this side's certificate chain (PEM file)
    key: str                          # its private key (PEM file)
    peer_ca: str                      # the CA file(s) the other side's certificate must chain to
    crl: Optional[str] = None         # a CRL (PEM) to check the peer's leaf against; None means no revocation check
    expected_peer: Optional[str] = None  # the UAI identity the peer must prove; None accepts any CA-signed identity


def _base(ctx: ssl.SSLContext, cfg: TlsConfig) -> ssl.SSLContext:
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3   # no negotiation downward, ever
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.load_cert_chain(cfg.cert, cfg.key)
    ctx.load_verify_locations(cafile=cfg.peer_ca)
    if cfg.crl:
        ctx.load_verify_locations(cafile=cfg.crl)
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    return ctx


def server_context(cfg: TlsConfig) -> ssl.SSLContext:
    """A server that REQUIRES a client certificate: an anonymous client never reaches the application."""
    return _base(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), cfg)


def client_context(cfg: TlsConfig) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True      # the server's certificate must also name the endpoint dialled
    return _base(ctx, cfg)


def peer_identity(tls: ssl.SSLSocket, expected: Optional[str] = None) -> str:
    """The UAI identity the peer's VERIFIED certificate names, or Refused('untrusted')."""
    cert = tls.getpeercert()
    if not cert:
        raise Refused("untrusted", "the peer presented no certificate")
    sans: Any = cert.get("subjectAltName", ())
    found = [str(v) for kind, v in sans if kind == "URI" and is_agent_id(v)]
    if len(found) != 1:
        raise Refused("untrusted", "the peer's certificate must name exactly one UAI identity in a subjectAltName URI")
    if expected is not None and found[0] != expected:
        raise Refused("untrusted", "the peer's certificate names a different UAI identity than the one expected")
    return found[0]


def open_bound(wire: Any, bound_identity: str, **kw: Any) -> Envelope:
    """Open an object received on a connection whose peer proved `bound_identity`. The object's own signature is verified
    as always, and its signer must be that identity: the channel's authentication and the object's are both required."""
    env = open_envelope(wire, **kw)
    if env.sender != bound_identity:
        raise Refused("untrusted", "the object is signed by an identity other than the one this connection authenticated")
    return env


def _read_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise Refused("unavailable", "the connection closed before a whole message arrived")
        buf += chunk
    return buf


def send_frame(sock: socket.socket, data: bytes) -> None:
    if len(data) > MAX_FRAME:
        raise Refused("malformed", "message larger than a UAI-1 frame")
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_frame(sock: socket.socket) -> bytes:
    (n,) = struct.unpack(">I", _read_exact(sock, 4))
    if n > MAX_FRAME:
        raise Refused("malformed", "the frame is larger than UAI-1 allows; it was not read")
    return _read_exact(sock, n)


class TlsServer:
    """A small mutual-TLS server. `handler(frame: bytes, bound_identity: str) -> bytes` answers each frame; whatever it
    raises, the connection is closed and nothing is sent. `reload()` applies new certificate files to new connections."""

    def __init__(self, cfg: TlsConfig, handler: Callable[[bytes, str], bytes], *, host: str = "127.0.0.1", port: int = 0,
                 timeout_s: float = 5.0) -> None:
        self._cfg, self._handler, self._timeout = cfg, handler, timeout_s
        self._ctx = server_context(cfg)
        self._lock = threading.Lock()
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(16)
        self.address: Tuple[str, int] = self._sock.getsockname()
        self.handshakes_refused = 0
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def reload(self, cfg: Optional[TlsConfig] = None) -> None:
        ctx = server_context(cfg or self._cfg)   # raises before anything changes if the new files are unusable
        with self._lock:
            self._ctx = ctx
            if cfg is not None:
                self._cfg = cfg

    def close(self) -> None:
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass

    def _serve(self) -> None:
        while not self._stop:
            try:
                raw, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(raw,), daemon=True).start()

    def _one(self, raw: socket.socket) -> None:
        raw.settimeout(self._timeout)
        with self._lock:
            ctx, expected = self._ctx, self._cfg.expected_peer
        try:
            with ctx.wrap_socket(raw, server_side=True) as tls:
                who = peer_identity(tls, expected)
                reply = self._handler(recv_frame(tls), who)
                send_frame(tls, reply)
        except (ssl.SSLError, OSError, Refused):
            self.handshakes_refused += 1
        except Exception:  # a handler error closes the connection and says nothing to the peer
            self.handshakes_refused += 1
        finally:
            try:
                raw.close()
            except OSError:
                pass


def tls_exchange(cfg: TlsConfig, address: Tuple[str, int], server_hostname: str, frame: bytes, *,
                 timeout_s: float = 5.0) -> Tuple[bytes, str]:
    """Send one frame and read one frame back. Returns (reply, the UAI identity the SERVER proved). Refused otherwise."""
    ctx = client_context(cfg)
    try:
        with socket.create_connection(address, timeout=timeout_s) as raw:
            with ctx.wrap_socket(raw, server_hostname=server_hostname) as tls:
                who = peer_identity(tls, cfg.expected_peer)
                send_frame(tls, frame)
                return recv_frame(tls), who
    except ssl.SSLCertVerificationError as exc:
        raise Refused("untrusted", f"the server's certificate was not accepted ({exc.verify_message})") from None
    except ssl.SSLError as exc:
        raise Refused("untrusted", f"the TLS 1.3 handshake failed ({type(exc).__name__})") from None
    except (OSError, TimeoutError) as exc:
        raise Refused("unavailable", f"the connection failed ({type(exc).__name__})") from None
