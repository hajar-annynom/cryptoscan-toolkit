"""
cryptoscan.core.models
=======================
Central data contracts for CryptoScan-Toolkit.

Every scanner module (TLS, SSH, cert-chain, cipher-suite) consumes a
ScanTarget and yields Vulnerability objects. The engine aggregates these
into a single AuditResult, which is the *only* object the report layer
(HTML/PDF/JSON) is allowed to touch. This keeps scanners, engine, and
reporting fully decoupled: none of them import from each other, they all
import from here.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Optional


class Severity(IntEnum):
    """Ordered so findings can be sorted / filtered numerically (e.g. --min-severity HIGH)."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # nicer default rendering in f-strings / rich tables
        return self.name


class Protocol(IntEnum):
    """Protocols a scanner module can be registered against."""
    TLS = 0
    SSH = 1
    UNKNOWN = 2


@dataclass(frozen=True, slots=True)
class ScanTarget:
    """
    Immutable unit of work. One ScanTarget = one (host, port) pair to probe.
    Frozen + slots: cheap to create thousands of these when expanding CIDR
    ranges / port lists, and safe to share across asyncio tasks.
    """
    host: str
    port: int
    protocol_hint: Protocol = Protocol.UNKNOWN
    timeout: float = 5.0

    def __post_init__(self) -> None:
        if not (0 < self.port < 65536):
            raise ValueError(f"Invalid port: {self.port}")
        # Fail fast on garbage input rather than letting a bad target
        # silently produce a meaningless "connection refused" finding.
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            if not self.host or " " in self.host:
                raise ValueError(f"Invalid host: {self.host!r}")

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass(slots=True)
class Vulnerability:
    """A single finding produced by a scanner module."""
    id: str                      # stable slug, e.g. "TLS-WEAK-CIPHER-RC4"
    title: str
    severity: Severity
    description: str
    target: ScanTarget
    remediation: str = ""
    cve_refs: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)   # raw bytes/handshake data for the report appendix

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": str(self.severity),
            "description": self.description,
            "target": self.target.address,
            "remediation": self.remediation,
            "cve_refs": self.cve_refs,
            "evidence": self.evidence,
        }


@dataclass(slots=True)
class ModuleError:
    """
    Non-fatal scan failure (timeout, RST, handshake refused, invalid cert
    chain that couldn't even be parsed). Kept distinct from Vulnerability
    so the report can show "3 hosts unreachable" separately from findings,
    instead of the CLI crashing or the failure being silently swallowed.
    """
    target: ScanTarget
    module: str
    message: str
    exception_type: str


@dataclass(slots=True)
class AuditResult:
    """
    Top-level aggregate handed to the report generator. This is the single
    seam between "engine + scanners" and "output formatting" — Jinja2
    templates only ever see this object (or its .as_dict()).
    """
    scan_id: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    targets: list[ScanTarget] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    errors: list[ModuleError] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        end = self.finished_at or datetime.now(timezone.utc)
        return (end - self.started_at).total_seconds()

    def by_severity(self, minimum: Severity = Severity.INFO) -> list[Vulnerability]:
        return sorted(
            (v for v in self.vulnerabilities if v.severity >= minimum),
            key=lambda v: v.severity,
            reverse=True,
        )

    def summary(self) -> dict[str, int]:
        counts = {s.name: 0 for s in Severity}
        for v in self.vulnerabilities:
            counts[v.severity.name] += 1
        return counts
