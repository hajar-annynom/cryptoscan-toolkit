"""Runs the real SSH scanner over real TCP against an in-process fake SSH server. No Docker needed."""
import asyncio

from cryptoscan.core.models import ScanTarget
from cryptoscan.scanners.ssh_scanner import SSHScanner
from tests.fixtures.fake_ssh import STRONG, WEAK, fake_ssh_server


def scan(port, timeout=3.0):
    return asyncio.run(SSHScanner().scan(ScanTarget("127.0.0.1", port, timeout=timeout)))


def test_weak_server_is_flagged():
    with fake_ssh_server(WEAK) as port:
        found = {f.id for f in scan(port)}
    assert {"SSH-WEAK-KEX", "SSH-WEAK-HOSTKEY", "SSH-WEAK-CIPHER", "SSH-WEAK-MAC", "SSH-OUTDATED-VERSION"} <= found


def test_strong_server_has_no_findings():
    with fake_ssh_server(STRONG) as port:
        assert scan(port) == []


def test_non_ssh_port_returns_nothing_instead_of_crashing():
    async def silent(reader, writer):        # accepts, never speaks (like a TLS port)
        await asyncio.sleep(5)
        writer.close()

    async def go():
        server = await asyncio.start_server(silent, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return await SSHScanner().scan(ScanTarget("127.0.0.1", port, timeout=3))
        finally:
            server.close()

    assert asyncio.run(go()) == []
