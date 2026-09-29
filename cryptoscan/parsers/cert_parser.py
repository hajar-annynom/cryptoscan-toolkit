"""
Pure certificate parsing: DER bytes in, CertInfo out. No sockets, so it is
unit-testable with certificates generated on the fly.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa


@dataclass(frozen=True, slots=True)
class CertInfo:
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    key_type: str            # "RSA", "EC", "DSA", "Ed25519", ...
    key_bits: int | None
    sig_hash: str | None     # "sha256", "sha1", "md5", None (EdDSA)
    self_signed: bool
    dns_names: tuple[str, ...]
    common_name: str | None

    @property
    def expired(self) -> bool:
        return self.not_after < datetime.now(timezone.utc)

    @property
    def days_left(self) -> int:
        return (self.not_after - datetime.now(timezone.utc)).days


def parse_certificate(der: bytes) -> CertInfo:
    cert = x509.load_der_x509_certificate(der)
    pub = cert.public_key()

    if isinstance(pub, rsa.RSAPublicKey):
        key_type, bits = "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_type, bits = "EC", pub.curve.key_size
    elif isinstance(pub, dsa.DSAPublicKey):
        key_type, bits = "DSA", pub.key_size
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        key_type, bits = "Ed25519", 256
    elif isinstance(pub, ed448.Ed448PublicKey):
        key_type, bits = "Ed448", 448
    else:
        key_type, bits = type(pub).__name__, None

    try:
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:  # noqa: BLE001 - unknown/unsupported signature OIDs
        sig_hash = None

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = tuple(san.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        dns_names = ()

    cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return CertInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        key_type=key_type,
        key_bits=bits,
        sig_hash=sig_hash,
        self_signed=cert.subject == cert.issuer,
        dns_names=dns_names,
        common_name=cn_attrs[0].value if cn_attrs else None,
    )


def hostname_matches(host: str, cert: CertInfo) -> bool | None:
    """True/False for DNS names; None when `host` is an IP (not checked)."""
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    names = cert.dns_names or ((cert.common_name,) if cert.common_name else ())
    host = host.lower().rstrip(".")
    for name in names:
        n = str(name).lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") == n.count(".") and host.endswith(n[1:]):
            return True
    return False
