import json
from datetime import datetime, timezone

from cryptoscan.core.models import AuditResult, ScanTarget, Severity, Vulnerability
from cryptoscan.report.render import render_report


def _sample_result() -> AuditResult:
    target = ScanTarget(host="127.0.0.1", port=4433)
    result = AuditResult(scan_id="test-scan", started_at=datetime.now(timezone.utc))
    result.targets.append(target)
    result.vulnerabilities.append(
        Vulnerability(
            id="TLS-WEAK-CIPHER",
            title="Weak cipher suite negotiated: RC4-SHA",
            severity=Severity.HIGH,
            description="RC4 is broken.",
            target=target,
            remediation="Disable RC4.",
        )
    )
    result.finished_at = datetime.now(timezone.utc)
    return result


def test_json_report_roundtrip(tmp_path):
    result = _sample_result()
    out = render_report(result, fmt="json", out_file=str(tmp_path / "report.json"))
    data = json.loads(out.read_text())
    assert data["scan_id"] == "test-scan"
    assert data["summary"]["HIGH"] == 1
    assert data["vulnerabilities"][0]["id"] == "TLS-WEAK-CIPHER"


def test_html_report_contains_finding(tmp_path):
    result = _sample_result()
    out = render_report(result, fmt="html", out_file=str(tmp_path / "report.html"))
    html = out.read_text()
    assert "RC4-SHA" in html
    assert "HIGH" in html
