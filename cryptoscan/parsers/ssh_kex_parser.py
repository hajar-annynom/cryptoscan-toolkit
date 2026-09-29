"""
Parser for the SSH_MSG_KEXINIT packet (RFC 4253 section 7.1).

The server sends KEXINIT *unencrypted*, right after the version exchange, and
it lists EVERY algorithm the server is willing to use. Reading it directly is
the correct way to audit a server: a full client handshake (paramiko) would
only reveal the single algorithm both sides agreed on, and would fail outright
against servers that only offer legacy algorithms the client refuses.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

SSH_MSG_KEXINIT = 20
MAX_PACKET = 35000  # RFC 4253 minimum supported packet size


class KexInitError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class KexInit:
    kex: tuple[str, ...]
    host_keys: tuple[str, ...]
    ciphers: tuple[str, ...]   # union of client->server and server->client
    macs: tuple[str, ...]      # union of both directions


def _name_list(buf: bytes, off: int) -> tuple[list[str], int]:
    if off + 4 > len(buf):
        raise KexInitError("truncated name-list length")
    (n,) = struct.unpack_from(">I", buf, off)
    off += 4
    if n > len(buf) - off:
        raise KexInitError("name-list overruns packet")
    raw = buf[off:off + n].decode("ascii", "replace")
    return ([x for x in raw.split(",") if x], off + n)


def parse_kexinit_packet(packet: bytes) -> KexInit:
    """`packet` = everything after the 4-byte length: padlen | payload | padding."""
    if len(packet) < 2:
        raise KexInitError("packet too short")
    pad = packet[0]
    payload = packet[1:len(packet) - pad] if pad else packet[1:]
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        raise KexInitError("first packet is not SSH_MSG_KEXINIT")
    off = 1 + 16  # message type + cookie
    lists: list[list[str]] = []
    for _ in range(10):
        lst, off = _name_list(payload, off)
        lists.append(lst)
    kex, hostkeys, enc_c2s, enc_s2c, mac_c2s, mac_s2c = lists[:6]
    return KexInit(
        kex=tuple(kex),
        host_keys=tuple(hostkeys),
        ciphers=tuple(dict.fromkeys(enc_c2s + enc_s2c)),
        macs=tuple(dict.fromkeys(mac_c2s + mac_s2c)),
    )


def build_kexinit_packet(kex, host_keys, ciphers, macs) -> bytes:
    """Builds a wire-format KEXINIT (used by the in-process test fixture)."""
    import os

    def nl(items) -> bytes:
        raw = ",".join(items).encode()
        return struct.pack(">I", len(raw)) + raw

    payload = bytes([SSH_MSG_KEXINIT]) + os.urandom(16)
    payload += nl(kex) + nl(host_keys) + nl(ciphers) + nl(ciphers) + nl(macs) + nl(macs)
    payload += nl(["none"]) + nl(["none"]) + nl([]) + nl([])
    payload += b"\x00" + struct.pack(">I", 0)
    pad = 8 - ((len(payload) + 5) % 8)
    pad = pad + 8 if pad < 4 else pad
    body = bytes([pad]) + payload + b"\x00" * pad
    return struct.pack(">I", len(body)) + body
