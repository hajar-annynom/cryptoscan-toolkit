"""Turns CLI strings ("10.0.0.0/30", "22,443,8000-8010") into concrete lists."""
from __future__ import annotations

import ipaddress

MAX_HOSTS = 65536


def parse_ports(spec: str) -> list[int]:
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                raise ValueError(f"Invalid port range: {part}")
            ports.extend(range(lo, hi + 1))
        else:
            ports.append(int(part))
    bad = [p for p in ports if not 0 < p < 65536]
    if bad or not ports:
        raise ValueError(f"Invalid port spec: {spec!r}")
    return list(dict.fromkeys(ports))


def expand_hosts(specs: list[str]) -> list[str]:
    hosts: list[str] = []
    for spec in specs:
        if "/" in spec:
            net = ipaddress.ip_network(spec, strict=False)
            if net.num_addresses > MAX_HOSTS:
                raise ValueError(f"{spec} expands to more than {MAX_HOSTS} hosts")
            hosts.extend(str(ip) for ip in (net.hosts() if net.num_addresses > 2 else net))
        else:
            hosts.append(spec)
    return list(dict.fromkeys(hosts))
