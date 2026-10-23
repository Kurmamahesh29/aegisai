"""Self-contained HTML report. Every value is HTML-escaped; no scripts are embedded."""

from __future__ import annotations

from html import escape
from pathlib import Path

from aegisai.models.finding import Finding, Severity
from aegisai.models.scan import ScanResult

_CSS = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1f2933;background:#fff}
h1{margin-bottom:0}.muted{color:#52606d}table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{border:1px solid #d9e2ec;padding:.4rem .6rem;text-align:left;vertical-align:top;font-size:.92rem}
th{background:#f0f4f8}.sev{font-weight:600;text-transform:uppercase;font-size:.8rem;padding:.1rem .4rem;border-radius:4px}
.sev-critical{background:#7f1d1d;color:#fff}.sev-high{background:#b91c1c;color:#fff}.sev-medium{background:#d97706;color:#fff}
.sev-low{background:#2563eb;color:#fff}.sev-informational{background:#64748b;color:#fff}
code{background:#f0f4f8;padding:.1rem .3rem;border-radius:3px;font-size:.85rem}
.status-success{color:#15803d}.status-incomplete,.status-failed,.status-cancelled{color:#b91c1c}
.status-success_with_warnings{color:#d97706}details{margin:.4rem 0}summary{cursor:pointer}
"""


def render_html(result: ScanResult) -> str:
    summary = result.summary
    rows = "\n".join(_finding_row(f) for f in result.findings)
    analyzers = "\n".join(
        f"<tr><td>{escape(a.name)}</td><td>{escape(a.status.value)}</td><td>{escape(a.message or '')}</td><td>{a.findings_count}</td></tr>"
        for a in result.analyzers
    )
    warnings = "\n".join(
        f"<li><code>{escape(w.code)}</code> {escape(w.message)}</li>" for w in result.warnings
    )
    errors = "\n".join(
        f"<li><code>{escape(e.rule_id)}</code> {escape(e.file_path)}: {escape(e.error)}</li>"
        for e in result.errors
    )
    severity_counts = " ".join(
        f'<span class="sev sev-{sev.value}">{sev.value}: {summary.by_severity.get(sev, 0)}</span>'
        for sev in Severity
    )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>AegisAI report</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><style>{_CSS}</style></head>
<body>
<h1>AegisAI security report</h1>
<p class="muted">{escape(result.metadata.tool_name)} {escape(result.metadata.tool_version)} &middot; {escape(result.metadata.root)} &middot; {escape(result.metadata.finished_at.isoformat())}</p>
<p>Status: <strong class="status-{escape(result.status.value)}">{escape(result.status.value)}</strong>{(" - " + escape(result.status_reason)) if result.status_reason else ""}</p>
<p>{severity_counts}</p>
<p>Files scanned: {summary.files_scanned} / {summary.files_discovered} &middot; Rules executed: {summary.rules_executed} &middot; Active findings: {summary.active_findings} &middot; Suppressed: {summary.suppressed_findings} &middot; Exit code: {summary.exit_code}</p>
<h2>Findings ({len(result.findings)})</h2>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Title</th><th>Confidence</th><th>Status</th><th>Details</th></tr></thead>
<tbody>{rows or '<tr><td colspan="7">No findings.</td></tr>'}</tbody></table>
<h2>Analyzers</h2>
<table><thead><tr><th>Name</th><th>Status</th><th>Message</th><th>Findings</th></tr></thead><tbody>{analyzers or '<tr><td colspan="4">None</td></tr>'}</tbody></table>
<h2>Warnings ({len(result.warnings)})</h2><ul>{warnings or "<li>None</li>"}</ul>
<h2>Rule errors ({len(result.errors)})</h2><ul>{errors or "<li>None</li>"}</ul>
</body></html>
"""


def _finding_row(finding: Finding) -> str:
    evidence = "".join(
        f"<li>{escape(e.kind)}: {escape(e.description)}"
        + (f" <code>{escape(e.snippet)}</code>" if e.snippet else "")
        + "</li>"
        for e in finding.evidence
    )
    refs = "".join(
        f'<li><a href="{escape(r, quote=True)}" rel="noopener noreferrer">{escape(r)}</a></li>'
        for r in finding.references
        if r.startswith("https://")
    )
    suppression = ""
    if finding.suppression:
        suppression = f"<p><strong>Suppressed:</strong> {escape(finding.suppression.reason)} ({escape(finding.suppression.source)})</p>"
    return (
        f'<tr><td><span class="sev sev-{finding.severity.value}">{finding.severity.value}</span></td>'
        f"<td><code>{escape(finding.rule_id)}</code></td>"
        f"<td><code>{escape(finding.location.file_path)}:{finding.location.start_line}</code></td>"
        f"<td>{escape(finding.title)}{' <em>(review required)</em>' if finding.review_required else ''}</td>"
        f"<td>{escape(finding.confidence.value)}</td><td>{escape(finding.status.value)}</td>"
        f"<td><details><summary>{escape(finding.evidence_summary)}</summary>"
        f"<p>{escape(finding.description)}</p><p><strong>Impact:</strong> {escape(finding.impact)}</p>"
        f"<p><strong>Remediation:</strong> {escape(finding.remediation)}</p>{suppression}"
        f'<ul>{evidence}</ul><ul>{refs}</ul><p class="muted">fingerprint <code>{escape(finding.fingerprint)}</code></p></details></td></tr>'
    )


def write_html(result: ScanResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(result), encoding="utf-8")
