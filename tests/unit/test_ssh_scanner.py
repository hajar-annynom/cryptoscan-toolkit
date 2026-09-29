from cryptoscan.core.models import ScanTarget, Severity
from cryptoscan.parsers.ssh_kex_parser import build_kexinit_packet, parse_kexinit_packet
from cryptoscan.scanners.ssh_scanner import WEAK_CIPHERS, WEAK_KEX, WEAK_MACS, SSHScanner

T = ScanTarget(host="127.0.0.1", port=22)


def test_kexinit_roundtrip():
    pkt = build_kexinit_packet(["curve25519-sha256"], ["ssh-ed25519"], ["aes256-gcm@openssh.com"], ["hmac-sha2-256"])
    parsed = parse_kexinit_packet(pkt[4:])          # strip the 4-byte length prefix
    assert parsed.kex == ("curve25519-sha256",)
    assert parsed.host_keys == ("ssh-ed25519",)
    assert parsed.ciphers == ("aes256-gcm@openssh.com",)
    assert parsed.macs == ("hmac-sha2-256",)


def test_weak_kex_is_grouped_and_takes_worst_severity():
    (f,) = SSHScanner._check_list(T, "KEX", "key-exchange",
                                  ["curve25519-sha256", "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"],
                                  WEAK_KEX, "fix")
    assert f.id == "SSH-WEAK-KEX"
    assert f.severity == Severity.HIGH
    assert f.evidence["weak"] == ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"]


def test_strong_algorithms_produce_no_findings():
    assert SSHScanner._check_list(T, "CIPHER", "cipher", ["chacha20-poly1305@openssh.com"], WEAK_CIPHERS, "") == []
    assert SSHScanner._check_list(T, "MAC", "MAC", ["hmac-sha2-512-etm@openssh.com"], WEAK_MACS, "") == []


def test_cbc_alone_is_only_low():
    (f,) = SSHScanner._check_list(T, "CIPHER", "cipher", ["aes128-cbc"], WEAK_CIPHERS, "")
    assert f.severity == Severity.LOW


def test_none_cipher_is_critical():
    (f,) = SSHScanner._check_list(T, "CIPHER", "cipher", ["none"], WEAK_CIPHERS, "")
    assert f.severity == Severity.CRITICAL


def test_ssh_rsa_is_downgraded_when_rsa_sha2_also_offered():
    (legacy,) = SSHScanner._check_host_keys(T, ["ssh-rsa"])
    (hygiene,) = SSHScanner._check_host_keys(T, ["ssh-rsa", "rsa-sha2-512"])
    assert legacy.severity == Severity.MEDIUM
    assert hygiene.severity == Severity.LOW


def test_dsa_host_key_is_high():
    (f,) = SSHScanner._check_host_keys(T, ["ssh-dss"])
    assert f.severity == Severity.HIGH


def test_banner_check():
    assert SSHScanner._check_banner(T, "SSH-2.0-OpenSSH_7.4p1 Debian-10")[0].id == "SSH-OUTDATED-VERSION"
    assert SSHScanner._check_banner(T, "SSH-2.0-OpenSSH_9.6") == []
    assert SSHScanner._check_banner(T, "SSH-2.0-dropbear_2022.83") == []
