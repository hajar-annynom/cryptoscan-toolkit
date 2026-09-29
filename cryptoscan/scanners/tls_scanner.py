"""
TLSScanner: audits a TLS endpoint by *actively probing* it.

Why probing instead of "connect once and read what was negotiated":
a default client refuses TLS < 1.2 and weak ciphers (OpenSSL security level),
and a server picks its own preferred option anyway. A single connection would
therefore never reveal that the server *also accepts* TLS 1.0 or RC4. So this
scanner makes one deliberately-permissive handshake per protocol version and
one per weak cipher family, and reports what the server is willing to accept.

Certificate checks (expiry, self-signed, key size, signature hash, hostname)
run on the DER certificate via cryptoscan.parsers.cert_parser.

Limits (stated so nobody over-trusts the output):
  * SSLv2/SSLv3 cannot be probed: Python's ssl module cannot speak them.
  * EXPORT/RC4 probes are skipped when the local OpenSSL build was compiled
    without those ciphers; a skipped probe is not reported as "safe".
"""
from __future__ import annotations

import asyncio
import re
import ssl
import warnings
from dataclasses import dataclass

from cryptoscan.core.models import Protocol, ScanTarget, Severity, Vulnerability
from cryptoscan.parsers.cert_parser import CertInfo, hostname_matches, parse_certificate

_VERSIONS: tuple[tuple[str, ssl.TLSVersion], ...] = (
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
)
_DEPRECATED = {"TLSv1", "TLSv1.1"}

# family -> (OpenSSL cipher string, severity, remediation hint)
_WEAK_FAMILIES: dict[str, tuple[str, Severity]] = {
    "RC4": ("RC4:@SECLEVEL=0", Severity.HIGH),
    "3DES": ("3DES:@SECLEVEL=0", Severity.MEDIUM),      # Sweet32
    "EXPORT": ("EXPORT:@SECLEVEL=0", Severity.CRITICAL),  # FREAK / Logjam
    "NULL": ("eNULL:@SECLEVEL=0", Severity.CRITICAL),
    "ANON": ("aNULL:@SECLEVEL=0", Severity.CRITICAL),
}
_WEAK_NEGOTIATED = re.compile(r"(RC4|DES|EXPORT|NULL|ADH|AECDH|MD5)")


@dataclass(slots=True)
class _Probe:
    version: str
    cipher: str
    der_cert: bytes | None


def _context(min_v: ssl.TLSVersion, max_v: ssl.TLSVersion, ciphers: str | None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # we WANT to inspect bad certs, not reject them
    # Probing deprecated protocol versions is the whole point of this scanner, so the
    # DeprecationWarning Python emits for ssl.TLSVersion.TLSv1/TLSv1_1 is expected noise.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = min_v
        ctx.maximum_version = max_v
    if ciphers is not None:
        ctx.set_ciphers(ciphers)              # may raise ssl.SSLError if unsupported locally
    return ctx


async def _handshake(target: ScanTarget, ctx: ssl.SSLContext) -> _Probe | None:
    """One handshake. None = server refused this protocol/cipher (a normal answer).
    Network-level failures (refused, timeout, reset) propagate to the engine."""
    try:
        _r, writer = await asyncio.wait_for(
            asyncio.open_connection(target.host, target.port, ssl=ctx),
            timeout=target.timeout,
        )
    except ssl.SSLError:
        return None                           # handshake rejected / not a TLS service
    except (ConnectionResetError, asyncio.IncompleteReadError):
        return None                           # server slammed the door on this attempt
    try:
        obj = writer.get_extra_info("ssl_object")
        cipher = obj.cipher()[0] if obj.cipher() else "?"
        return _Probe(obj.version() or "?", cipher, obj.getpeercert(binary_form=True))
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ssl.SSLError, OSError):
            pass


class TLSScanner:
    name = "tls_scanner"
    protocol = Protocol.TLS

    async def scan(self, target: ScanTarget) -> list[Vulnerability]:
        # Fail fast (and cheaply) on closed/filtered ports: raises OSError,
        # which the engine records as a ModuleError instead of 9 slow timeouts.
        _r, w = await asyncio.wait_for(
            asyncio.open_connection(target.host, target.port), timeout=target.timeout
        )
        w.close()

        version_probes = await asyncio.gather(
            *(self._probe_version(target, name, v) for name, v in _VERSIONS)
        )
        accepted = {p.version: p for p in version_probes if p}
        if not accepted:
            return []                         # not speaking TLS: nothing to audit

        family_results = await asyncio.gather(
            *(self._probe_family(target, fam) for fam in _WEAK_FAMILIES)
        )

        findings: list[Vulnerability] = []
        findings += self._protocol_findings(target, accepted)
        findings += self._cipher_findings(target, family_results)
        findings += self._negotiated_findings(
            target, accepted, {c for _f, c, _s in family_results if c}
        )

        best = accepted.get("TLSv1.3") or accepted.get("TLSv1.2") or next(iter(accepted.values()))
        if best.der_cert:
            try:
                findings += self._cert_findings(target, parse_certificate(best.der_cert))
            except Exception as exc:  # noqa: BLE001 - malformed cert must not kill the scan
                findings.append(Vulnerability(
                    id="TLS-CERT-UNPARSEABLE", title="Certificate could not be parsed",
                    severity=Severity.MEDIUM, description=str(exc), target=target))
        return findings

    # -- probes -----------------------------------------------------------

    @staticmethod
    async def _probe_version(target: ScanTarget, name: str, version: ssl.TLSVersion) -> _Probe | None:
        ciphers = None if version is ssl.TLSVersion.TLSv1_3 else "ALL:!aNULL:!eNULL:@SECLEVEL=0"
        return await _handshake(target, _context(version, version, ciphers))

    @staticmethod
    async def _probe_family(target: ScanTarget, family: str) -> tuple[str, str | None, bool]:
        """Returns (family, negotiated_cipher or None, skipped).
        skipped=True means the LOCAL OpenSSL cannot even offer this family, so
        the result says nothing about the server (must never be read as "safe")."""
        cipher_string, _sev = _WEAK_FAMILIES[family]
        try:
            ctx = _context(ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_2, cipher_string)
        except ssl.SSLError:
            return family, None, True
        probe = await _handshake(target, ctx)
        return family, (probe.cipher if probe else None), False

    # -- findings ---------------------------------------------------------

    @staticmethod
    def _protocol_findings(target: ScanTarget, accepted: dict[str, _Probe]) -> list[Vulnerability]:
        old = sorted(v for v in accepted if v in _DEPRECATED)
        out: list[Vulnerability] = []
        if old:
            out.append(Vulnerability(
                id="TLS-DEPRECATED-PROTOCOL",
                title=f"Deprecated protocol(s) accepted: {', '.join(old)}",
                severity=Severity.HIGH,
                description="The server completes handshakes over TLS versions deprecated by RFC 8996.",
                target=target,
                remediation="Set the minimum protocol version to TLS 1.2 (TLS 1.3 preferred).",
                cve_refs=["RFC 8996"],
                evidence={"accepted_versions": sorted(accepted)},
            ))
        if "TLSv1.2" not in accepted and "TLSv1.3" not in accepted:
            out.append(Vulnerability(
                id="TLS-NO-MODERN-PROTOCOL",
                title="Server supports neither TLS 1.2 nor TLS 1.3",
                severity=Severity.CRITICAL,
                description="Only deprecated protocol versions are available to clients.",
                target=target,
                remediation="Enable TLS 1.2 and TLS 1.3.",
                evidence={"accepted_versions": sorted(accepted)},
            ))
        return out

    @staticmethod
    def _cipher_findings(
        target: ScanTarget, results: list[tuple[str, str | None, bool]]
    ) -> list[Vulnerability]:
        out = []
        skipped = [f for f, _c, sk in results if sk]
        for family, negotiated, _sk in results:
            if negotiated is None:
                continue
            out.append(Vulnerability(
                id=f"TLS-WEAK-CIPHER-{family}",
                title=f"Server accepts {family} cipher suites ({negotiated})",
                severity=_WEAK_FAMILIES[family][1],
                description=f"A client offering only {family} suites completed a handshake.",
                target=target,
                remediation="Restrict the cipher list to AEAD suites (AES-GCM, ChaCha20-Poly1305).",
                evidence={"negotiated_cipher": negotiated},
            ))
        if skipped:
            out.append(Vulnerability(
                id="TLS-PROBE-SKIPPED",
                title=f"Not tested (unsupported by local OpenSSL): {', '.join(skipped)}",
                severity=Severity.INFO,
                description="The scanning machine's OpenSSL build cannot offer these cipher families, "
                            "so the server's behaviour for them is UNKNOWN (not 'safe').",
                target=target,
                remediation="Re-run from a host whose OpenSSL supports legacy ciphers, or use "
                            "`nmap --script ssl-enum-ciphers` / testssl.sh for these families.",
                evidence={"skipped_families": skipped},
            ))
        return out

    @staticmethod
    def _negotiated_findings(
        target: ScanTarget, accepted: dict[str, _Probe], already_reported: set[str]
    ) -> list[Vulnerability]:
        """Weak suites the server *prefers*, that no family probe already reported."""
        weak = {p.cipher for p in accepted.values() if _WEAK_NEGOTIATED.search(p.cipher)}
        return [Vulnerability(
            id="TLS-WEAK-CIPHER-NEGOTIATED",
            title=f"Weak cipher suite negotiated: {c}",
            severity=Severity.MEDIUM,
            description=f"Handshake selected {c}, which is considered weak.",
            target=target,
            remediation="Remove weak suites from the server configuration.",
            evidence={"cipher": c},
        ) for c in sorted(weak - already_reported)]

    @staticmethod
    def _cert_findings(target: ScanTarget, c: CertInfo) -> list[Vulnerability]:
        out: list[Vulnerability] = []
        ev = {"subject": c.subject, "issuer": c.issuer, "not_after": c.not_after.isoformat(),
              "key": f"{c.key_type}-{c.key_bits}", "sig_hash": c.sig_hash}

        def add(id_: str, title: str, sev: Severity, desc: str, fix: str) -> None:
            out.append(Vulnerability(id=id_, title=title, severity=sev, description=desc,
                                     target=target, remediation=fix, evidence=ev))

        if c.expired:
            add("TLS-CERT-EXPIRED", "Certificate has expired", Severity.HIGH,
                f"Certificate expired on {c.not_after:%Y-%m-%d}.", "Renew the certificate.")
        elif c.days_left < 30:
            add("TLS-CERT-EXPIRING", f"Certificate expires in {c.days_left} days", Severity.LOW,
                f"Certificate expires on {c.not_after:%Y-%m-%d}.", "Renew/automate renewal.")
        if c.self_signed:
            add("TLS-CERT-SELF-SIGNED", "Self-signed certificate", Severity.MEDIUM,
                "Issuer equals subject; clients cannot validate the chain of trust.",
                "Use a certificate issued by a trusted CA.")
        if c.key_type == "RSA" and c.key_bits is not None and c.key_bits < 2048:
            sev = Severity.CRITICAL if c.key_bits < 1024 else Severity.HIGH
            add("TLS-CERT-SHORT-KEY", f"RSA key too short: {c.key_bits} bits", sev,
                "RSA keys under 2048 bits are within reach of well-resourced attackers.",
                "Reissue with RSA >= 2048 (3072 recommended) or ECDSA P-256.")
        if c.key_type == "EC" and c.key_bits is not None and c.key_bits < 224:
            add("TLS-CERT-SHORT-KEY", f"EC key too short: {c.key_bits} bits", Severity.HIGH,
                "Elliptic-curve keys under 224 bits are insufficient.", "Use P-256 or stronger.")
        if c.key_type == "DSA":
            add("TLS-CERT-DSA", "DSA certificate key", Severity.MEDIUM,
                "DSA is deprecated for TLS certificates.", "Use RSA >= 2048 or ECDSA.")
        if c.sig_hash in ("md5", "md2", "md4"):
            add("TLS-CERT-WEAK-SIG", f"Certificate signed with {c.sig_hash.upper()}", Severity.HIGH,
                "The signature hash is broken; certificates can be forged.", "Reissue using SHA-256+.")
        elif c.sig_hash == "sha1":
            add("TLS-CERT-WEAK-SIG", "Certificate signed with SHA-1", Severity.MEDIUM,
                "SHA-1 signatures are deprecated (practical collisions exist).", "Reissue using SHA-256+.")
        if hostname_matches(target.host, c) is False:
            add("TLS-CERT-HOSTNAME-MISMATCH", f"Certificate does not match host {target.host}",
                Severity.MEDIUM, f"Certificate names: {list(c.dns_names) or [c.common_name]}.",
                "Issue a certificate whose SAN covers the served hostname.")
        return out
