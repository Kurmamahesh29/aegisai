"""Human-readable terminal report using Rich."""

from __future__ import annotations

from typing import IO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from aegisai.models.finding import Finding, FindingStatus, Severity
from aegisai.models.scan import AnalyzerStatus, ScanResult, ScanStatus

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFORMATIONAL: "dim",
}

_STATUS_STYLE: dict[ScanStatus, str] = {
    ScanStatus.SUCCESS: "bold green",
    ScanStatus.SUCCESS_WITH_WARNINGS: "bold yellow",
    ScanStatus.INCOMPLETE: "bold red",
    ScanStatus.FAILED: "bold red",
    ScanStatus.CANCELLED: "bold red",
}


def render_terminal(
    result: ScanResult,
    *,
    stream: IO[str],
    color: bool = True,
    quiet: bool = False,
    verbose: bool = False,
    max_findings: int = 200,
) -> None:
    console = Console(
        file=stream, force_terminal=color, no_color=not color, highlight=False, soft_wrap=True
    )
    summary = result.summary
    if quiet:
        console.print(_summary_line(result))
        return

    console.print()
    console.print(
        Text(f"AegisAI {result.metadata.tool_version}", style="bold"),
        Text(f"- {result.metadata.root}", style="dim"),
    )
    console.print(
        f"profiles: {', '.join(result.metadata.profiles)} | files: {summary.files_scanned}/{summary.files_discovered} | "
        f"rules: {summary.rules_executed} executed, {summary.rules_skipped} skipped | "
        f"frameworks: {', '.join(result.metadata.frameworks) or 'none detected'}"
    )
    console.print()

    findings = [f for f in result.findings if f.status is not FindingStatus.SUPPRESSED]
    suppressed = [f for f in result.findings if f.status is FindingStatus.SUPPRESSED]
    if findings:
        table = Table(show_lines=False, pad_edge=False, expand=False)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Rule", no_wrap=True)
        table.add_column("Location", overflow="fold")
        table.add_column("Finding", overflow="fold")
        table.add_column("Conf.", no_wrap=True)
        for finding in sorted(findings, key=_sort_key)[:max_findings]:
            table.add_row(
                Text(finding.severity.value, style=_SEVERITY_STYLE[finding.severity]),
                finding.rule_id,
                f"{finding.location.file_path}:{finding.location.start_line}",
                _finding_text(finding, verbose),
                finding.confidence.value,
            )
        console.print(table)
        if len(findings) > max_findings:
            console.print(
                f"... {len(findings) - max_findings} more findings omitted; use --format json for the full list.",
                style="dim",
            )
    else:
        console.print("No findings.", style="green")

    if suppressed:
        console.print(
            f"{len(suppressed)} suppressed finding(s) not shown (listed in JSON/SARIF reports).",
            style="dim",
        )

    if result.baseline is not None:
        b = result.baseline
        console.print(
            f"baseline: {b.new} new, {b.existing} existing, {b.resolved} resolved", style="cyan"
        )

    problem_analyzers = [
        a
        for a in result.analyzers
        if a.status not in (AnalyzerStatus.COMPLETED, AnalyzerStatus.DISABLED)
    ]
    if result.analyzers:
        console.print()
        console.print("Analyzers:", style="bold")
        for analyzer in result.analyzers:
            style = (
                "green"
                if analyzer.status is AnalyzerStatus.COMPLETED
                else ("dim" if analyzer.status is AnalyzerStatus.DISABLED else "yellow")
            )
            if analyzer.status in (AnalyzerStatus.FAILED, AnalyzerStatus.TIMED_OUT) or (
                analyzer.required and analyzer in problem_analyzers
            ):
                style = "red"
            suffix = f" - {analyzer.message}" if analyzer.message else ""
            required = " (required)" if analyzer.required else ""
            console.print(
                f"  {analyzer.name}: [{style}]{analyzer.status.value}[/{style}]{required}{suffix}"
            )

    if result.warnings:
        console.print()
        console.print(f"Warnings ({len(result.warnings)}):", style="bold yellow")
        for warning in result.warnings[: 20 if not verbose else len(result.warnings)]:
            location = f" [{warning.file_path}]" if warning.file_path else ""
            console.print(f"  {warning.code}: {warning.message}{location}")
        if not verbose and len(result.warnings) > 20:
            console.print(f"  ... {len(result.warnings) - 20} more (use --verbose)", style="dim")
    if result.errors:
        console.print()
        console.print(f"Rule errors ({len(result.errors)}):", style="bold red")
        for error in result.errors[:20]:
            console.print(f"  {error.rule_id} on {error.file_path}: {error.error}")
    if verbose and result.skipped_rules:
        console.print()
        console.print("Skipped rules:", style="bold")
        for skipped in result.skipped_rules:
            console.print(f"  {skipped.rule_id}: {skipped.reason}")

    console.print()
    console.print(_summary_line(result))


def _summary_line(result: ScanResult) -> Text:
    summary = result.summary
    counts = ", ".join(
        f"{sev.value}={summary.by_severity.get(sev, 0)}"
        for sev in Severity
        if summary.by_severity.get(sev, 0)
    )
    text = Text()
    text.append(f"status: {result.status.value}", style=_STATUS_STYLE[result.status])
    if result.status_reason:
        text.append(f" ({result.status_reason})", style="dim")
    text.append(f" | findings: {summary.active_findings}")
    if counts:
        text.append(f" [{counts}]")
    if summary.suppressed_findings:
        text.append(f" | suppressed: {summary.suppressed_findings}")
    if summary.filtered_below_threshold:
        text.append(f" | hidden below --severity: {summary.filtered_below_threshold}")
    threshold = summary.fail_on.value if summary.fail_on else "none"
    text.append(f" | fail-on: {threshold}")
    text.append(f" | exit code: {summary.exit_code}", style="bold")
    return text


def _finding_text(finding: Finding, verbose: bool) -> Text:
    text = Text()
    text.append(finding.title, style="bold")
    if finding.review_required:
        text.append(" (review required)", style="dim")
    text.append("\n")
    text.append(finding.evidence_summary, style="dim")
    if verbose:
        text.append("\n")
        text.append(f"remediation: {finding.remediation}", style="italic")
        text.append(f"\nfingerprint: {finding.fingerprint}", style="dim")
    return text


def _sort_key(finding: Finding) -> tuple[int, int, str, int]:
    return (
        -finding.severity.rank,
        -finding.confidence.rank,
        finding.location.file_path,
        finding.location.start_line,
    )
