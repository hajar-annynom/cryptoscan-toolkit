"""Optional convenience base class. Not required (engine uses structural
typing via ScannerModule Protocol) but handy for shared boilerplate like
opening/closing raw sockets."""
from __future__ import annotations
import abc
from cryptoscan.core.models import Protocol, ScanTarget, Vulnerability


class BaseScanner(abc.ABC):
    name: str
    protocol: Protocol

    @abc.abstractmethod
    async def scan(self, target: ScanTarget) -> list[Vulnerability]:
        ...
