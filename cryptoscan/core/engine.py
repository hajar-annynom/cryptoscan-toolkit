"""
cryptoscan.core.engine
========================
The orchestrator. Knows nothing about TLS or SSH internals — it only knows
how to fan a list of ScanTarget objects out across a list of registered
ScannerModule plugins, bound concurrency with a semaphore, contain failures
per-task, and assemble the results into an AuditResult.

Design decisions:
  * Modules are discovered via a Protocol (structural typing), not
    inheritance from a base class -> scanner authors can write a plain
    class or even a set of functions wrapped in an object; the engine
    doesn't care, as long as `.protocol` and `.scan()` exist.
  * A bounded asyncio.Semaphore caps in-flight connections so scanning a
    /24 doesn't exhaust file descriptors or trip IDS/rate-limits on the
    target.
  * Every module invocation is wrapped in its own try/except *inside*
    the worker coroutine, so one bad handshake never cancels the rest of
    the scan (asyncio.gather would otherwise propagate the first
    exception and cancel sibling tasks).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol as TypingProtocol
from typing import runtime_checkable
from uuid import uuid4

from cryptoscan.core.models import (
    AuditResult,
    ModuleError,
    Protocol,
    ScanTarget,
    Vulnerability,
)

logger = logging.getLogger("cryptoscan.engine")


@runtime_checkable
class ScannerModule(TypingProtocol):
    """
    Structural contract every scanner module must satisfy.
    See cryptoscan/scanners/tls_scanner.py and ssh_scanner.py for
    concrete implementations.
    """
    name: str
    protocol: Protocol

    async def scan(self, target: ScanTarget) -> list[Vulnerability]:
        ...


@dataclass(slots=True)
class EngineConfig:
    max_concurrency: int = 100
    per_target_timeout: float = 8.0
    retries: int = 0


class CryptoScanEngine:
    """
    Usage:
        engine = CryptoScanEngine(config=EngineConfig(max_concurrency=200))
        engine.register(TLSScanner())
        engine.register(SSHScanner())
        result = await engine.run(targets)
    """

    def __init__(self, config: EngineConfig | None = None) -> None:
        self.config = config or EngineConfig()
        self._modules: list[ScannerModule] = []
        self._semaphore = asyncio.Semaphore(self.config.max_concurrency)

    def register(self, module: ScannerModule) -> None:
        if not isinstance(module, ScannerModule):
            raise TypeError(
                f"{module!r} does not satisfy the ScannerModule protocol "
                "(needs .name, .protocol, and async .scan(target))"
            )
        logger.debug("Registered scanner module: %s", module.name)
        self._modules.append(module)

    def _modules_for(self, target: ScanTarget) -> list[ScannerModule]:
        """Route a target only to modules that can handle its protocol hint,
        or to every module if the target didn't specify one (auto-detect mode)."""
        if target.protocol_hint is Protocol.UNKNOWN:
            return self._modules
        return [m for m in self._modules if m.protocol == target.protocol_hint] or self._modules

    async def _run_module(
        self,
        module: ScannerModule,
        target: ScanTarget,
        result: AuditResult,
    ) -> None:
        """One (module, target) unit of work. Never raises — all failure
        modes are captured as ModuleError so the CLI never crashes mid-scan."""
        async with self._semaphore:
            attempt = 0
            while True:
                try:
                    findings = await asyncio.wait_for(
                        module.scan(target), timeout=self.config.per_target_timeout
                    )
                    result.vulnerabilities.extend(findings)
                    return
                except asyncio.TimeoutError:
                    message = f"timed out after {self.config.per_target_timeout}s"
                    exc_name = "TimeoutError"
                except (ConnectionRefusedError, ConnectionResetError, OSError) as exc:
                    message = str(exc) or exc.__class__.__name__
                    exc_name = exc.__class__.__name__
                except Exception as exc:  # noqa: BLE001 - deliberate: contain *any* module bug
                    logger.exception("Unhandled error in module %s for %s", module.name, target.address)
                    message = str(exc)
                    exc_name = exc.__class__.__name__

                attempt += 1
                if attempt > self.config.retries:
                    result.errors.append(
                        ModuleError(
                            target=target,
                            module=module.name,
                            message=message,
                            exception_type=exc_name,
                        )
                    )
                    return
                # simple linear backoff between retries
                await asyncio.sleep(0.5 * attempt)

    async def run(self, targets: list[ScanTarget]) -> AuditResult:
        if not self._modules:
            raise RuntimeError("No scanner modules registered. Call engine.register(...) first.")

        result = AuditResult(scan_id=str(uuid4()), started_at=datetime.now(timezone.utc), targets=targets)

        tasks = [
            asyncio.create_task(self._run_module(module, target, result))
            for target in targets
            for module in self._modules_for(target)
        ]

        # return_exceptions=True is a defense-in-depth backstop; _run_module
        # already swallows everything, but this guarantees gather() itself
        # can never abort the batch.
        await asyncio.gather(*tasks, return_exceptions=True)

        result.finished_at = datetime.now(timezone.utc)
        logger.info(
            "Scan %s finished in %.2fs: %d findings, %d errors",
            result.scan_id, result.duration_seconds, len(result.vulnerabilities), len(result.errors),
        )
        return result


async def expand_targets(
    hosts: list[str], ports: list[int], protocol_hint: Protocol = Protocol.UNKNOWN, timeout: float = 5.0
) -> list[ScanTarget]:
    """Cartesian-expand hosts (plain names/IPs or CIDR blocks) x ports into ScanTargets.
    A free function (not an engine method) so target expansion is unit-testable
    without spinning up the engine."""
    from cryptoscan.parsers.target_parser import expand_hosts

    return [
        ScanTarget(host=h, port=p, protocol_hint=protocol_hint, timeout=timeout)
        for h in expand_hosts(hosts)
        for p in ports
    ]
