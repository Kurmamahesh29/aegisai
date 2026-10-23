"""Scan orchestration: discovery -> rules -> integrations -> normalisation -> result."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from aegisai import __version__
from aegisai.discovery.project import build_project_context
from aegisai.engine.baseline import apply_baseline, load_baseline
from aegisai.engine.context import apply_context_adjustments
from aegisai.engine.deduplication import apply_precedence, deduplicate
from aegisai.engine.execution import Deadline, execute_rules
from aegisai.engine.filtering import (
    apply_overrides,
    filter_by_confidence,
    select_rules,
    split_by_severity,
    threshold_reached,
)
from aegisai.engine.registry import RuleRegistry, default_registry
from aegisai.engine.suppression import apply_suppressions
from aegisai.exceptions import ScanCancelledError
from aegisai.integrations import ALL_INTEGRATIONS
from aegisai.integrations.base import IntegrationOutcome
from aegisai.models.configuration import IntegrationSettings, Profile, ScanConfiguration
from aegisai.models.finding import Finding, FindingStatus, Severity
from aegisai.models.scan import (
    AnalyzerResult,
    AnalyzerStatus,
    ExitCode,
    ScanMetadata,
    ScanResult,
    ScanStatus,
    ScanSummary,
    ScanWarning,
    SkippedRule,
)
from aegisai.rules import RULE_PRECEDENCE
from aegisai.utils.logging import get_logger
from aegisai.utils.paths import PathMatcher, resolve_root

log = get_logger("runner")

ProgressCallback = Callable[[str, int, int], None]


@dataclass(slots=True)
class ScanOptions:
    """Fully resolved options for one scan (configuration + CLI overrides)."""

    root: Path
    config: ScanConfiguration
    config_path: Path | None = None
    profiles: list[Profile] | None = None
    min_severity: Severity | None = None
    fail_on: Severity | None = None
    fail_on_overridden: bool = False
    baseline_path: Path | None = None
    extra_excludes: list[str] = field(default_factory=list)
    disabled_rules: list[str] = field(default_factory=list)
    timeout_seconds: int | None = None
    max_file_size_kb: int | None = None
    no_integrations: bool = False
    strict_integrations: bool | None = None
    command_line: list[str] = field(default_factory=list)
    should_cancel: Callable[[], bool] | None = None
    progress: ProgressCallback | None = None
    registry: RuleRegistry | None = None


def run_scan(options: ScanOptions) -> ScanResult:
    """Run a complete scan and return a :class:`ScanResult`.

    Raises :class:`ProjectRootError`, :class:`ConfigurationError`, :class:`BaselineError` or
    :class:`ScanCancelledError`; the CLI maps these to exit codes. Analyzer failures never
    raise: they are recorded in the result and reflected in the scan status.
    """
    started = datetime.now(UTC)
    clock = time.monotonic()
    config = options.config
    root = resolve_root(options.root)
    registry = options.registry or default_registry()

    scan_section = config.scan.model_copy()
    if options.profiles:
        scan_section.profiles = list(options.profiles)
    if options.max_file_size_kb:
        scan_section.max_file_size_kb = options.max_file_size_kb
    if options.timeout_seconds:
        scan_section.timeout_seconds = options.timeout_seconds
    effective = config.model_copy(update={"scan": scan_section})
    strict = (
        options.strict_integrations
        if options.strict_integrations is not None
        else config.ci.strict_integrations
    )
    fail_on = options.fail_on if options.fail_on_overridden else config.ci.fail_on
    min_severity = options.min_severity or config.report.min_severity

    baseline = load_baseline(options.baseline_path) if options.baseline_path else None

    deadline = Deadline(scan_section.timeout_seconds)
    _notify(options, "discovering files", 0, 0)
    project = build_project_context(
        root,
        scan_section,
        extra_excludes=options.extra_excludes,
        should_cancel=options.should_cancel,
    )
    warnings: list[ScanWarning] = [
        ScanWarning(code="discovery", message=w) for w in project.stats.warnings
    ]

    integration_enabled = {
        name: (not options.no_integrations) and getattr(config.integrations, name).enabled
        for name in ALL_INTEGRATIONS
    }
    selection = select_rules(
        registry,
        effective,
        extra_disabled=options.disabled_rules,
        available_integrations=integration_enabled,
    )

    def progress(index: int, total: int, path: str) -> None:
        _notify(options, path, index, total)

    outcome = execute_rules(
        project,
        selection.rules,
        deadline=deadline,
        should_cancel=options.should_cancel,
        progress=progress if options.progress else None,
    )
    warnings.extend(outcome.warnings)

    analyzers: list[AnalyzerResult] = [
        AnalyzerResult(
            name="builtin",
            status=AnalyzerStatus.COMPLETED if not outcome.timed_out else AnalyzerStatus.TIMED_OUT,
            required=True,
            findings_count=len(outcome.findings),
            files_processed=outcome.files_scanned,
            duration_ms=int((time.monotonic() - clock) * 1000),
            version=__version__,
        )
    ]
    all_findings: list[Finding] = list(outcome.findings)
    # External scanners walk the root themselves; apply the same exclusions to their findings.
    exclusion_matcher = PathMatcher(
        list(scan_section.exclude) + list(options.extra_excludes), scan_section.include
    )
    skipped_rules: list[SkippedRule] = list(selection.skipped)

    for name, analyzer_cls in ALL_INTEGRATIONS.items():
        if options.should_cancel is not None and options.should_cancel():
            raise ScanCancelledError("scan cancelled")
        settings: IntegrationSettings = getattr(config.integrations, name)
        analyzer = analyzer_cls()
        if not integration_enabled[name]:
            result = analyzer.disabled()
        elif deadline.expired():
            result = IntegrationOutcome(
                AnalyzerResult(
                    name=name,
                    status=AnalyzerStatus.SKIPPED,
                    required=settings.required,
                    message="scan timeout reached before the analyzer could run",
                )
            )
        else:
            _notify(options, f"running {name}", 0, 0)
            timeout = max(1, min(settings.timeout_seconds, int(deadline.remaining()) or 1))
            result = analyzer.run(project, settings, timeout)
        analyzers.append(result.result)
        warnings.extend(result.warnings)
        kept = [
            f
            for f in result.findings
            if not exclusion_matcher.is_excluded(f.location.file_path)
            and exclusion_matcher.is_included(f.location.file_path)
        ]
        if len(kept) != len(result.findings):
            log.debug(
                "%s: dropped %d finding(s) in excluded paths",
                name,
                len(result.findings) - len(kept),
            )
            result.result.findings_count = len(kept)
        all_findings.extend(kept)
        if result.result.status is not AnalyzerStatus.COMPLETED:
            for rule in registry:
                if rule.metadata.requires_integration == name and rule in selection.rules:
                    skipped_rules.append(
                        SkippedRule(
                            rule_id=rule.rule_id,
                            reason=f"integration '{name}' {result.result.status.value}: {result.result.message or ''}".strip(),
                        )
                    )

    # Normalisation pipeline.
    all_findings = apply_overrides(all_findings, effective)
    all_findings = apply_context_adjustments(all_findings, scan_section)
    all_findings = filter_by_confidence(all_findings, scan_section.min_confidence)
    all_findings = apply_precedence(all_findings, RULE_PRECEDENCE)
    all_findings = deduplicate(all_findings)
    all_findings, suppression_warnings = apply_suppressions(
        all_findings, configured=config.suppressions, inline_lookup=dict(outcome.contexts)
    )
    warnings.extend(suppression_warnings)
    baseline_summary = None
    if baseline is not None and options.baseline_path is not None:
        all_findings, baseline_summary = apply_baseline(
            all_findings, baseline, str(options.baseline_path)
        )
    reported, filtered = split_by_severity(all_findings, min_severity)
    reported.sort(
        key=lambda f: (-f.severity.rank, f.location.file_path, f.location.start_line, f.rule_id)
    )

    # Status.
    status = ScanStatus.SUCCESS
    reason: str | None = None
    problem = [
        a
        for a in analyzers
        if a.status in (AnalyzerStatus.UNAVAILABLE, AnalyzerStatus.FAILED, AnalyzerStatus.TIMED_OUT)
    ]
    blocking = [a for a in problem if a.required or strict]
    limit_hit = project.stats.skipped_limit > 0
    if outcome.timed_out:
        status, reason = (
            ScanStatus.INCOMPLETE,
            "scan timeout reached before all files were analysed",
        )
    elif blocking:
        names = ", ".join(f"{a.name} ({a.status.value})" for a in blocking)
        status, reason = ScanStatus.INCOMPLETE, f"required analyzer(s) did not complete: {names}"
    elif limit_hit:
        status, reason = (
            ScanStatus.INCOMPLETE,
            "file or size limits reached; not all files were scanned",
        )
    elif problem or warnings or outcome.errors:
        status = ScanStatus.SUCCESS_WITH_WARNINGS
        if problem:
            reason = "optional analyzer(s) unavailable or failed: " + ", ".join(
                a.name for a in problem
            )
        elif outcome.errors:
            reason = f"{len(outcome.errors)} rule execution error(s)"

    # Summary and exit code.
    active = [f for f in reported if f.status is not FindingStatus.SUPPRESSED]
    summary = ScanSummary(
        total_findings=len(reported),
        active_findings=len(active),
        suppressed_findings=len(reported) - len(active),
        filtered_below_threshold=filtered,
        by_severity={
            sev: sum(1 for f in active if f.severity is sev)
            for sev in Severity
            if any(f.severity is sev for f in active)
        },
        by_category=_count(f.category.value for f in active),
        by_rule=_count(f.rule_id for f in active),
        files_discovered=project.stats.files_selected,
        files_scanned=outcome.files_scanned,
        files_skipped=project.stats.skipped_too_large
        + project.stats.skipped_symlink
        + project.stats.skipped_limit
        + outcome.files_skipped,
        rules_executed=len(selection.rules),
        rules_skipped=len(skipped_rules),
        fail_on=fail_on,
    )
    summary.threshold_reached = threshold_reached(active, fail_on, new_only=baseline is not None)
    if summary.threshold_reached:
        summary.exit_code = ExitCode.FINDINGS_AT_THRESHOLD
    elif status is ScanStatus.INCOMPLETE:
        summary.exit_code = ExitCode.INCOMPLETE
    else:
        summary.exit_code = ExitCode.SUCCESS

    finished = datetime.now(UTC)
    metadata = ScanMetadata(
        tool_version=__version__,
        started_at=started,
        finished_at=finished,
        duration_ms=int((time.monotonic() - clock) * 1000),
        root=str(root),
        profiles=[p.value for p in scan_section.profiles],
        languages=sorted(project.languages),
        frameworks=project.frameworks.sorted_names(),
        config_path=str(options.config_path) if options.config_path else None,
        baseline_path=str(options.baseline_path) if options.baseline_path else None,
        command_line=list(options.command_line),
    )
    return ScanResult(
        status=status,
        status_reason=reason,
        metadata=metadata,
        summary=summary,
        findings=reported,
        analyzers=analyzers,
        skipped_rules=skipped_rules,
        warnings=warnings,
        errors=outcome.errors,
        baseline=baseline_summary,
    )


def _count(values: object) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:  # type: ignore[attr-defined]
        counts[str(value)] = counts.get(str(value), 0) + 1
    return dict(sorted(counts.items()))


def _notify(options: ScanOptions, message: str, index: int, total: int) -> None:
    if options.progress is not None:
        options.progress(message, index, total)
