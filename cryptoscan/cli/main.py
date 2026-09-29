"""
CLI entrypoint: parse args -> expand targets -> run engine -> render report.
Pure orchestration glue; no scanning logic lives here.
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from rich.console import Console
from rich.table import Table

from cryptoscan.core.engine import CryptoScanEngine, EngineConfig, expand_targets
from cryptoscan.core.models import AuditResult, Protocol, Severity
from cryptoscan.parsers.target_parser import parse_ports
from cryptoscan.report.render import render_report
from cryptoscan.scanners.ssh_scanner import SSHScanner
from cryptoscan.scanners.tls_scanner import TLSScanner

console = Console()

SEV_STYLE = {"INFO": "dim", "LOW": "blue", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold white on red"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cryptoscan",
        description="Audit TLS/SSH cryptographic configuration. Only scan systems you are authorized to test.",
    )
    p.add_argument("targets", nargs="+", help="Hosts, IPs or CIDR blocks (e.g. example.com 10.0.0.0/28)")
    p.add_argument("-p", "--ports", default="443", help='Ports: "443", "22,443", "8000-8010" (default: 443)')
    p.add_argument("--protocol", choices=["tls", "ssh", "auto"], default="auto",
                   help="Only run this module (default: auto = try both on every port)")
    p.add_argument("-c", "--concurrency", type=int, default=100, help="Max simultaneous probes (default: 100)")
    p.add_argument("--timeout", type=float, default=5.0, help="Per-connection timeout in seconds (default: 5)")
    p.add_argument("--min-severity", choices=[s.name for s in Severity], default="INFO")
    p.add_argument("-o", "--output", choices=["cli", "html", "json", "pdf"], default="cli")
    p.add_argument("--out-file", default=None, help="Output path for html/json/pdf reports")
    p.add_argument("--fail-on", choices=["none"] + [s.name for s in Severity if s > Severity.INFO], default="none",
                   help="Exit with status 1 if a finding of this severity or higher exists (for CI). Default: never")
    return p


async def _amain(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    try:
        ports = parse_ports(args.ports)
        hint = {"tls": Protocol.TLS, "ssh": Protocol.SSH, "auto": Protocol.UNKNOWN}[args.protocol]
        targets = await expand_targets(args.targets, ports, hint, args.timeout)
    except ValueError as exc:
        console.print(f"[red]Invalid input:[/red] {exc}")
        return 2

    engine = CryptoScanEngine(EngineConfig(max_concurrency=args.concurrency,
                                           per_target_timeout=args.timeout * 3))
    engine.register(TLSScanner())
    engine.register(SSHScanner())

    with console.status(f"[bold cyan]Scanning {len(targets)} target(s)..."):
        result = await engine.run(targets)

    if args.output == "cli":
        _print_cli_report(result, Severity[args.min_severity])
    else:
        path = render_report(result, fmt=args.output, out_file=args.out_file)
        console.print(f"Report written to [bold]{path}[/bold]  ({_summary_line(result)})")

    if args.fail_on != "none" and any(v.severity >= Severity[args.fail_on] for v in result.vulnerabilities):
        return 1
    return 0


def _summary_line(result: AuditResult) -> str:
    counts = {k: v for k, v in result.summary().items() if v}
    return ", ".join(f"{k}: {v}" for k, v in counts.items()) or "no findings"


def _print_cli_report(result: AuditResult, min_severity: Severity) -> None:
    findings = result.by_severity(min_severity)
    if findings:
        table = Table(title="CryptoScan-Toolkit - Findings")
        table.add_column("Severity")
        table.add_column("Target")
        table.add_column("ID")
        table.add_column("Finding")
        for v in findings:
            table.add_row(f"[{SEV_STYLE[v.severity.name]}]{v.severity}[/]", v.target.address, v.id, v.title)
        console.print(table)
    else:
        console.print("[green]No findings at or above the requested severity.[/green]")
    if result.errors:
        console.print(f"\n[yellow]{len(result.errors)} probe(s) could not complete:[/yellow]")
        for e in result.errors:
            console.print(f"  {e.target.address}  {e.module}: {e.exception_type} {e.message}")
    console.print(f"\n{len(result.targets)} target(s) in {result.duration_seconds:.1f}s - {_summary_line(result)}")


def main() -> None:
    sys.exit(asyncio.run(_amain(sys.argv[1:])))


if __name__ == "__main__":
    main()
