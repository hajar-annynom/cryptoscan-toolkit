from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from cryptoscan.core.models import ScanTarget, Severity
from cryptoscan.parsers.cert_parser import hostname_matches, parse_certificate
from cryptoscan.scanners.tls_scanner import TLSScanner


def make_cert(bits=2048, days=90, cn="example.com", sans=("example.com",), ec_key=False, sha=hashes.SHA256()):
    key = ec.generate_private_key(ec.SECP256R1()) if ec_key else rsa.generate_private_key(65537, bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=100)).not_valid_after(now + timedelta(days=days)))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    return builder.sign(key, sha).public_bytes(serialization.Encoding.DER)


def ids(findings):
    return {f.id for f in findings}


T = ScanTarget(host="example.com", port=443)


def test_parse_rsa_fields():
    c = parse_certificate(make_cert(bits=2048))
    assert (c.key_type, c.key_bits, c.sig_hash, c.self_signed) == ("RSA", 2048, "sha256", True)


def test_short_rsa_key_flagged_high():
    found = TLSScanner._cert_findings(T, parse_certificate(make_cert(bits=1024)))
    assert "TLS-CERT-SHORT-KEY" in ids(found)
    assert next(f for f in found if f.id == "TLS-CERT-SHORT-KEY").severity == Severity.HIGH


def test_expired_certificate():
    found = TLSScanner._cert_findings(T, parse_certificate(make_cert(days=-1)))
    assert "TLS-CERT-EXPIRED" in ids(found)


def test_expiring_soon_is_low():
    found = TLSScanner._cert_findings(T, parse_certificate(make_cert(days=10)))
    assert next(f for f in found if f.id == "TLS-CERT-EXPIRING").severity == Severity.LOW


def test_hostname_mismatch():
    cert = parse_certificate(make_cert(sans=("other.org",), cn="other.org"))
    assert hostname_matches("example.com", cert) is False
    assert "TLS-CERT-HOSTNAME-MISMATCH" in ids(TLSScanner._cert_findings(T, cert))


def test_wildcard_matches_one_label_only():
    cert = parse_certificate(make_cert(sans=("*.example.com",)))
    assert hostname_matches("www.example.com", cert) is True
    assert hostname_matches("a.b.example.com", cert) is False


def test_ip_targets_skip_hostname_check():
    assert hostname_matches("10.0.0.1", parse_certificate(make_cert())) is None


def test_clean_ec_certificate_only_reports_self_signed():
    found = TLSScanner._cert_findings(T, parse_certificate(make_cert(ec_key=True)))
    assert ids(found) == {"TLS-CERT-SELF-SIGNED"}
