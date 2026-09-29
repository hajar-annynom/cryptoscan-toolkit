"""
Runs the real TLS scanner against a real legacy `openssl s_server` (TLS 1.1 only,
NULL/anonymous suites, 1024-bit self-signed RSA). Skipped if the openssl CLI is missing.
"""
import asyncio
import shutil
import socket
import subprocess
import time
from contextlib import contextmanager

import pytest

from cryptoscan.core.models import ScanTarget
from cryptoscan.scanners.tls_scanner import TLSScanner

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not installed")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def legacy_tls_server(tmp_path):
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:1024", "-nodes", "-keyout", str(key),
                    "-out", str(crt), "-days", "2", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)
    port = free_port()
    proc = subprocess.Popen(
        ["openssl", "s_server", "-accept", str(port), "-cert", str(crt), "-key", str(key), "-tls1_1",
         "-cipher", "AES128-SHA:NULL-SHA:ADH-AES128-SHA:@SECLEVEL=0", "-quiet"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.skip("could not start openssl s_server with legacy options on this system")
        time.sleep(0.3)
        yield port
    finally:
        proc.terminate()
        proc.wait(5)


def test_legacy_tls_server_is_flagged(tmp_path):
    with legacy_tls_server(tmp_path) as port:
        found = asyncio.run(TLSScanner().scan(ScanTarget("127.0.0.1", port, timeout=4)))
    ids = {f.id for f in found}
    assert "TLS-DEPRECATED-PROTOCOL" in ids
    assert "TLS-NO-MODERN-PROTOCOL" in ids
    assert "TLS-CERT-SHORT-KEY" in ids
    assert "TLS-CERT-SELF-SIGNED" in ids


def test_closed_port_raises_so_the_engine_can_record_it():
    with pytest.raises(OSError):
        asyncio.run(TLSScanner().scan(ScanTarget("127.0.0.1", free_port(), timeout=1)))
