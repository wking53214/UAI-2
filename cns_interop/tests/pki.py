"""A throwaway PKI for the transport tests: a CA, leaf certificates that name a UAI identity, and a CRL. Test use only."""

from __future__ import annotations

import datetime as dt
import ipaddress
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

UTC = dt.timezone.utc


def _pem_key(key, path: Path) -> str:
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return str(path)


class CA:
    def __init__(self, directory: Path, name: str = "test-ca") -> None:
        self.dir, self.name = directory, name
        self.key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = dt.datetime.now(UTC)
        self.cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(self.key.public_key())
                     .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
                     .not_valid_after(now + dt.timedelta(days=30))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                     .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
                     .sign(self.key, hashes.SHA256()))
        self.pem = str(directory / f"{name}.pem")
        Path(self.pem).write_bytes(self.cert.public_bytes(serialization.Encoding.PEM))
        self.revoked: list = []

    def leaf(self, label: str, identity: str, *, hostname: Optional[str] = "localhost", days_valid: int = 10,
             not_before_days: int = 1) -> dict:
        key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(UTC)
        sans: list = [x509.UniformResourceIdentifier(identity)]
        if hostname:
            sans += [x509.DNSName(hostname), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)]))
                .issuer_name(self.cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(days=not_before_days)).not_valid_after(now + dt.timedelta(days=days_valid))
                .add_extension(x509.SubjectAlternativeName(sans), critical=False)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                                                      x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .sign(self.key, hashes.SHA256()))
        path = self.dir / f"{label}.pem"
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return {"cert": str(path), "key": _pem_key(key, self.dir / f"{label}.key"), "serial": cert.serial_number}

    def revoke(self, leaf: dict) -> str:
        self.revoked.append(leaf["serial"])
        return self.crl()

    def crl(self) -> str:
        now = dt.datetime.now(UTC)
        b = (x509.CertificateRevocationListBuilder().issuer_name(self.cert.subject).last_update(now - dt.timedelta(hours=1))
             .next_update(now + dt.timedelta(days=7)))
        for serial in self.revoked:
            b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(serial)
                                          .revocation_date(now - dt.timedelta(minutes=5)).build())
        path = self.dir / f"{self.name}.crl.pem"
        path.write_bytes(b.sign(self.key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
        return str(path)
