import asyncio

from cryptoscan.core.engine import CryptoScanEngine, EngineConfig
from cryptoscan.core.models import Protocol, ScanTarget, Severity, Vulnerability


class Good:
    name, protocol = "good", Protocol.TLS

    async def scan(self, target):
        return [Vulnerability("X", "t", Severity.LOW, "d", target)]


class Boom:
    name, protocol = "boom", Protocol.TLS

    async def scan(self, target):
        raise RuntimeError("module bug")


class Refused:
    name, protocol = "refused", Protocol.TLS

    async def scan(self, target):
        raise ConnectionRefusedError("nope")


class Hang:
    name, protocol = "hang", Protocol.TLS

    async def scan(self, target):
        await asyncio.sleep(60)


def run(*modules, timeout=0.3):
    engine = CryptoScanEngine(EngineConfig(max_concurrency=5, per_target_timeout=timeout))
    for m in modules:
        engine.register(m)
    return asyncio.run(engine.run([ScanTarget("127.0.0.1", 443), ScanTarget("127.0.0.1", 444)]))


def test_failures_are_contained_and_good_results_survive():
    r = run(Good(), Boom(), Refused(), Hang())
    assert len(r.vulnerabilities) == 2                       # Good ran on both targets
    kinds = sorted({e.exception_type for e in r.errors})
    assert kinds == ["ConnectionRefusedError", "RuntimeError", "TimeoutError"]
    assert len(r.errors) == 6                                # 3 failing modules x 2 targets


def test_protocol_hint_routes_only_matching_modules():
    class Ssh(Good):
        name, protocol = "ssh", Protocol.SSH

    engine = CryptoScanEngine()
    engine.register(Good())
    engine.register(Ssh())
    r = asyncio.run(engine.run([ScanTarget("127.0.0.1", 22, protocol_hint=Protocol.SSH)]))
    assert len(r.vulnerabilities) == 1


def test_register_rejects_non_modules():
    import pytest
    with pytest.raises(TypeError):
        CryptoScanEngine().register(object())
