"""
SSHScanner: reads the server's SSH_MSG_KEXINIT to obtain the FULL list of
key-exchange, host-key, cipher and MAC algorithms it advertises, then flags
weak ones. Fully asyncio-native (no threads) and no credentials are ever sent:
we exchange version strings, read one packet, and disconnect.

Why not paramiko for this? A paramiko handshake only tells you the single
algorithm both sides agreed on, and it refuses to connect at all to servers
that only offer legacy algorithms - exactly the servers an auditor cares about.
(paramiko stays in requirements for the planned host-key-size check.)
"""
from __future__ import annotations

import asyncio
import re
import struct

from cryptoscan.core.models import Protocol, ScanTarget, Severity, Vulnerability
from cryptoscan.parsers.ssh_kex_parser import MAX_PACKET, KexInit, KexInitError, parse_kexinit_packet

CLIENT_BANNER = b"SSH-2.0-CryptoScan_0.1\r\n"
# A real SSH server sends its banner immediately. TLS/HTTP ports stay silent (the client
# speaks first), so waiting the full timeout there only wastes time in auto mode.
BANNER_TIMEOUT = 2.0

# algorithm -> (severity, short reason)
WEAK_KEX = {
    "diffie-hellman-group1-sha1": (Severity.HIGH, "1024-bit MODP group + SHA-1 (Logjam-class)"),
    "diffie-hellman-group14-sha1": (Severity.MEDIUM, "SHA-1 based key exchange"),
    "diffie-hellman-group-exchange-sha1": (Severity.MEDIUM, "SHA-1 based key exchange"),
}
WEAK_HOST_KEYS = {
    "ssh-dss": (Severity.HIGH, "DSA is limited to 1024 bits and deprecated"),
    "ssh-rsa": (Severity.MEDIUM, "RSA with SHA-1 signatures"),
}
WEAK_CIPHERS = {
    "none": (Severity.CRITICAL, "no encryption"),
    "arcfour": (Severity.HIGH, "RC4"), "arcfour128": (Severity.HIGH, "RC4"), "arcfour256": (Severity.HIGH, "RC4"),
    "blowfish-cbc": (Severity.HIGH, "64-bit block cipher"), "cast128-cbc": (Severity.HIGH, "64-bit block cipher"),
    "3des-cbc": (Severity.MEDIUM, "64-bit block (Sweet32)"),
    "aes128-cbc": (Severity.LOW, "CBC mode"), "aes192-cbc": (Severity.LOW, "CBC mode"),
    "aes256-cbc": (Severity.LOW, "CBC mode"),
}
WEAK_MACS = {
    "none": (Severity.CRITICAL, "no integrity protection"),
    "hmac-md5": (Severity.MEDIUM, "MD5"), "hmac-md5-96": (Severity.MEDIUM, "MD5, truncated"),
    "hmac-sha1-96": (Severity.MEDIUM, "SHA-1, truncated"),
    "hmac-sha1": (Severity.LOW, "SHA-1"),
}
_OPENSSH = re.compile(r"OpenSSH_(\d+)\.(\d+)")


async def read_kexinit(target: ScanTarget) -> tuple[str, KexInit] | None:
    """Returns (server_banner, KexInit) or None if the port is not an SSH server.
    Network errors propagate so the engine can record them as ModuleError."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(target.host, target.port), timeout=target.timeout
    )
    try:
        # Identification string (RFC 4253 4.2): servers may send free text lines first.
        banner = ""
        for _ in range(20):
            line = await asyncio.wait_for(reader.readline(), timeout=min(target.timeout, BANNER_TIMEOUT))
            if not line:
                return None
            if line.startswith(b"SSH-"):
                banner = line.decode("ascii", "replace").strip()
                break
        else:
            return None
        writer.write(CLIENT_BANNER)
        await writer.drain()

        (length,) = struct.unpack(">I", await asyncio.wait_for(reader.readexactly(4), target.timeout))
        if not 0 < length <= MAX_PACKET:
            return None
        packet = await asyncio.wait_for(reader.readexactly(length), target.timeout)
        try:
            return banner, parse_kexinit_packet(packet)
        except KexInitError:
            return None
    except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.TimeoutError):
        return None          # silent / non-SSH service (a *connect* timeout was raised earlier)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


class SSHScanner:
    name = "ssh_scanner"
    protocol = Protocol.SSH

    async def scan(self, target: ScanTarget) -> list[Vulnerability]:
        result = await read_kexinit(target)
        if result is None:
            return []                         # not an SSH server: nothing to audit
        banner, kex = result
        findings: list[Vulnerability] = []
        findings += self._check_banner(target, banner)
        findings += self._check_list(target, "KEX", "key-exchange", kex.kex, WEAK_KEX,
                                     "Remove them from sshd_config `KexAlgorithms` "
                                     "(keep curve25519-sha256, diffie-hellman-group16/18-sha512).")
        findings += self._check_host_keys(target, kex.host_keys)
        findings += self._check_list(target, "CIPHER", "cipher", kex.ciphers, WEAK_CIPHERS,
                                     "Restrict `Ciphers` to chacha20-poly1305@openssh.com, aes256-gcm@openssh.com, aes128-gcm@openssh.com.")
        findings += self._check_list(target, "MAC", "MAC", kex.macs, WEAK_MACS,
                                     "Restrict `MACs` to hmac-sha2-256-etm@openssh.com / hmac-sha2-512-etm@openssh.com.")
        return findings

    # -- checks: pure functions of (target, strings) -> findings ----------

    @staticmethod
    def _check_list(target: ScanTarget, tag: str, label: str, offered, table, fix: str) -> list[Vulnerability]:
        hits = [(a, *table[a]) for a in offered if a in table]
        if not hits:
            return []
        worst = max(sev for _a, sev, _r in hits)
        return [Vulnerability(
            id=f"SSH-WEAK-{tag}",
            title=f"Weak {label} algorithm(s) offered: {', '.join(a for a, _s, _r in hits)}",
            severity=worst,
            description="; ".join(f"{a}: {reason}" for a, _s, reason in hits),
            target=target,
            remediation=fix,
            evidence={"weak": [a for a, _s, _r in hits], "all_offered": list(offered)},
        )]

    @staticmethod
    def _check_host_keys(target: ScanTarget, offered) -> list[Vulnerability]:
        hits = [(a, *WEAK_HOST_KEYS[a]) for a in offered if a in WEAK_HOST_KEYS]
        if not hits:
            return []
        modern_rsa = any(a.startswith("rsa-sha2-") for a in offered)
        out = []
        for algo, sev, reason in hits:
            if algo == "ssh-rsa" and modern_rsa:
                sev = Severity.LOW  # legacy alias still offered next to rsa-sha2-*: hygiene issue only
            out.append((algo, sev, reason))
        return [Vulnerability(
            id="SSH-WEAK-HOSTKEY",
            title=f"Weak host key algorithm(s) offered: {', '.join(a for a, _s, _r in out)}",
            severity=max(s for _a, s, _r in out),
            description="; ".join(f"{a}: {r}" for a, _s, r in out),
            target=target,
            remediation="Use only ssh-ed25519 / rsa-sha2-512 / ecdsa host keys (`HostKeyAlgorithms`, remove DSA host keys).",
            evidence={"weak": [a for a, _s, _r in out], "all_offered": list(offered)},
        )]

    @staticmethod
    def _check_banner(target: ScanTarget, banner: str) -> list[Vulnerability]:
        m = _OPENSSH.search(banner)
        if m and (int(m.group(1)), int(m.group(2))) < (8, 0):
            return [Vulnerability(
                id="SSH-OUTDATED-VERSION",
                title=f"Outdated OpenSSH: {banner}",
                severity=Severity.MEDIUM,
                description="This OpenSSH release is end-of-life and lacks years of security fixes and "
                            "modern defaults. (Distros may backport fixes; verify the package version.)",
                target=target,
                remediation="Upgrade to a currently supported OpenSSH.",
                evidence={"banner": banner},
            )]
        return []
