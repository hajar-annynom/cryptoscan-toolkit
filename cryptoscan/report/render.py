"""
Report rendering: Jinja2 -> HTML, optional HTML -> PDF via weasyprint, and a
plain JSON dump. Kept isolated from the engine/scanners: this module only
ever imports from cryptoscan.core.models, never the other way around, so
scanners stay reusable as a library even if you rip the reporting layer out
entirely (e.g. to pipe AuditResult into your own SIEM ingester instead).

PDF is an optional extra (see requirements.txt: `weasyprint ; extra == "pdf"`)
because it drags in system-level dependencies (Pango/Cairo). Importing it
lazily, only when `fmt == "pdf"`, means `cryptoscan ... --output html` keeps
working on a minimal install without weasyprint present.
"""
from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cryptoscan.core.models import AuditResult

TEMPLATE_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "j2"]),
)


def render_report(result: AuditResult, fmt: str, out_file: str | None) -> Path:
    """Render `result` in the requested format and return the path written to."""
    if fmt == "json":
        return _render_json(result, out_file)
    if fmt == "html":
        return _render_html(result, out_file)
    if fmt == "pdf":
        return _render_pdf(result, out_file)
    raise ValueError(f"Unknown report format: {fmt!r}")


def _render_json(result: AuditResult, out_file: str | None) -> Path:
    payload = {
        "scan_id": result.scan_id,
        "started_at": result.started_at.isoformat(),
        "finished_at": result.finished_at.isoformat() if result.finished_at else None,
        "duration_seconds": result.duration_seconds,
        "targets": [t.address for t in result.targets],
        "summary": result.summary(),
        "vulnerabilities": [v.as_dict() for v in result.vulnerabilities],
        "errors": [
            {
                "target": e.target.address,
                "module": e.module,
                "message": e.message,
                "exception_type": e.exception_type,
            }
            for e in result.errors
        ],
    }
    path = Path(out_file or f"cryptoscan-report-{result.scan_id}.json")
    path.write_text(json.dumps(payload, indent=2))
    return path


def _render_html_string(result: AuditResult) -> str:
    template = _env.get_template("report.html.j2")
    return template.render(result=result)


def _render_html(result: AuditResult, out_file: str | None) -> Path:
    html = _render_html_string(result)
    path = Path(out_file or f"cryptoscan-report-{result.scan_id}.html")
    path.write_text(html, encoding="utf-8")
    return path


def _render_pdf(result: AuditResult, out_file: str | None) -> Path:
    try:
        from weasyprint import HTML  # imported lazily — see module docstring
    except ImportError as exc:
        raise RuntimeError(
            "PDF output requires the optional 'pdf' extra: pip install 'cryptoscan-toolkit[pdf]'"
        ) from exc

    html = _render_html_string(result)
    path = Path(out_file or f"cryptoscan-report-{result.scan_id}.pdf")
    HTML(string=html).write_pdf(str(path))
    return path
