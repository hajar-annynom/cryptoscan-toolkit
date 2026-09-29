"""
Minimal fake SSH server for tests / manual demos - no Docker needed.

It speaks just enough of the protocol to be audited: it sends its version
string, waits for the client's, then sends a real wire-format SSH_MSG_KEXINIT
advertising whatever algorithms we configure, and closes. Nothing else.

Manual use:   python -m tests.fixtures.fake_ssh 2222 [weak|strong]
"""
from __future__ import annotations

import asyncio
import contextlib
import sys
import threading

from cryptoscan.parsers.ssh_kex_parser import build_kexinit_packet

WEAK = dict(
    banner=b"SSH-2.0-OpenSSH_7.4p1 Debian-10\r\n",
    kex=["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "curve25519-sha256"],
    host_keys=["ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256"],
    ciphers=["arcfour", "3des-cbc", "aes128-cbc", "aes256-ctr"],
    macs=["hmac-md5", "hmac-sha1", "hmac-sha2-256"],
)
STRONG = dict(
    banner=b"SSH-2.0-OpenSSH_9.6\r\n",
    kex=["curve25519-sha256", "diffie-hellman-group16-sha512"],
    host_keys=["ssh-ed25519", "rsa-sha2-512"],
    ciphers=["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
    macs=["hmac-sha2-512-etm@openssh.com"],
)


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, profile: dict) -> None:
    try:
        writer.write(profile["banner"])
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=5)   # client banner
        writer.write(build_kexinit_packet(profile["kex"], profile["host_keys"],
                                          profile["ciphers"], profile["macs"]))
        await writer.drain()
        await asyncio.wait_for(reader.read(1), timeout=5)       # until client hangs up
    except (asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        writer.close()


@contextlib.contextmanager
def fake_ssh_server(profile: dict = WEAK):
    """Runs the server in a background thread; yields the bound port."""
    ready = threading.Event()
    box: dict = {}

    def run() -> None:
        async def main() -> None:
            server = await asyncio.start_server(lambda r, w: _handle(r, w, profile), "127.0.0.1", 0)
            box["port"] = server.sockets[0].getsockname()[1]
            box["loop"] = asyncio.get_running_loop()
            box["stop"] = asyncio.Event()
            ready.set()
            await box["stop"].wait()
            server.close()
            await server.wait_closed()
        asyncio.run(main())

    t = threading.Thread(target=run, daemon=True)
    t.start()
    ready.wait(5)
    try:
        yield box["port"]
    finally:
        box["loop"].call_soon_threadsafe(box["stop"].set)
        t.join(5)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 2222
    profile = STRONG if len(sys.argv) > 2 and sys.argv[2] == "strong" else WEAK

    async def serve() -> None:
        server = await asyncio.start_server(lambda r, w: _handle(r, w, profile), "127.0.0.1", port)
        print(f"fake SSH ({'strong' if profile is STRONG else 'weak'}) on 127.0.0.1:{port} - Ctrl+C to stop")
        async with server:
            await server.serve_forever()

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(serve())
