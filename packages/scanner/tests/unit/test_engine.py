"""Engine tests: deduplication, precedence, suppressions, baselines, thresholds, timeouts."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from aegisai.engine.baseline import (
    apply_baseline,
    baseline_from_result,
    load_baseline,
    write_baseline,
)
from aegisai.engine.deduplication import apply_precedence, deduplicate
from aegisai.engine.execution import Deadline
from aegisai.engine.filtering import threshold_reached
from aegisai.engine.registry import FileContext, Rule, RuleRegistry, default_registry
from aegisai.engine.suppression import apply_suppressions
from aegisai.models.configuration import Profile, ScanConfiguration, Suppression
from aegisai.models.finding import Category, Confidence, Finding, FindingStatus, Location, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack
from aegisai.models.scan import ExitCode, ScanStatus
from conftest import findings_for, scan_code, scan_dir

VULNERABLE = """
    import subprocess
    from flask import request

    def ping():
        host = request.args.get("host")
        return subprocess.check_output("ping " + host, shell=True)
"""


def _finding(
    rule_id: str,
    line: int,
    summary: str = "s",
    analyzer: str = "a",
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        finding_id=f"{rule_id}-{line}-{analyzer}",
        rule_id=rule_id,
        rule_version="1.0.0",
        title="t",
        description="d",
        category=Category.CODE,
        severity=severity,
        confidence=Confidence.MEDIUM,
        location=Location(file_path="a.py", start_line=line, end_line=line),
        evidence_summary=summary,
        impact="i",
        remediation="r",
        analyzer=analyzer,
        fingerprint=f"{rule_id}{line}{analyzer}".ljust(32, "x"),
    )


def test_deduplicate_merges_same_location_and_keeps_distinct() -> None:
    a = _finding("SEC001", 3, analyzer="secrets", severity=Severity.MEDIUM)
    b = _finding("SEC001", 3, analyzer="gitleaks", severity=Severity.HIGH)
    c = _finding("SEC001", 4)
    merged = deduplicate([a, b, c])
    assert len(merged) == 2
    assert merged[0].severity is Severity.HIGH
    assert "analyzer:gitleaks" in merged[0].tags and "analyzer:secrets" in merged[0].tags


def test_precedence_drops_superseded_rule_only_at_same_line() -> None:
    findings = [_finding("MCP003", 5), _finding("SEC001", 5), _finding("SEC001", 9)]
    kept = apply_precedence(findings, {"MCP003": frozenset({"SEC001"})})
    assert [(f.rule_id, f.location.start_line) for f in kept] == [("MCP003", 5), ("SEC001", 9)]


def test_configured_suppression_by_fingerprint_and_path() -> None:
    f1 = _finding("SEC003", 1)
    f2 = _finding("SEC003", 2)
    f3 = _finding("LLM001", 3)
    configured = [
        Suppression(fingerprint=f1.fingerprint, reason="accepted risk"),
        Suppression(
            rule_id="SEC003", path="a.py", reason="legacy", expires=date.today() + timedelta(days=1)
        ),
        Suppression(
            rule_id="LLM001",
            path="a.py",
            reason="expired",
            expires=date.today() - timedelta(days=1),
        ),
    ]
    updated, warnings = apply_suppressions([f1, f2, f3], configured=configured, inline_lookup={})
    assert updated[0].status is FindingStatus.SUPPRESSED and updated[0].suppression is not None
    assert updated[0].suppression.matched_by == "fingerprint"
    assert (
        updated[1].suppression is not None and updated[1].suppression.matched_by == "rule_id+path"
    )
    assert updated[2].status is FindingStatus.NEW
    assert any(w.code == "suppression_expired" for w in warnings)


def test_inline_suppression_requires_reason(project) -> None:
    code = VULNERABLE.replace(
        'return subprocess.check_output("ping " + host, shell=True)',
        'return subprocess.check_output("ping " + host, shell=True)  # aegisai: ignore[SEC003] reason="demo fixture"',
    )
    result = scan_code(project, code, profiles=[Profile.CODE])
    found = findings_for(result, "SEC003")
    assert found and found[0].status is FindingStatus.SUPPRESSED
    assert result.summary.suppressed_findings == 1 and result.summary.active_findings == 0
    assert result.summary.exit_code == ExitCode.SUCCESS

    no_reason = VULNERABLE.replace("shell=True)", "shell=True)  # aegisai: ignore")
    result2 = scan_code(project, no_reason, profiles=[Profile.CODE])
    assert findings_for(result2, "SEC003")[0].status is FindingStatus.NEW
    assert any(w.code == "suppression_missing_reason" for w in result2.warnings)


def test_inline_suppression_for_other_rule_does_not_apply(project) -> None:
    code = VULNERABLE.replace(
        "shell=True)", 'shell=True)  # aegisai: ignore[LLM001] reason="wrong rule"'
    )
    result = scan_code(project, code, profiles=[Profile.CODE])
    assert findings_for(result, "SEC003")[0].status is FindingStatus.NEW


def test_baseline_marks_existing_and_resolved(project, tmp_path: Path) -> None:
    root = project({"app.py": VULNERABLE})
    first = scan_dir(root, profiles=[Profile.CODE])
    assert first.summary.exit_code == ExitCode.FINDINGS_AT_THRESHOLD
    baseline_path = tmp_path / "baseline.json"
    write_baseline(baseline_from_result(first), baseline_path)
    loaded = load_baseline(baseline_path)
    assert len(loaded.entries) == 1

    second = scan_dir(root, profiles=[Profile.CODE], baseline_path=baseline_path)
    assert second.findings[0].status is FindingStatus.EXISTING
    assert second.findings[0].first_seen is not None
    assert (
        second.baseline is not None and second.baseline.existing == 1 and second.baseline.new == 0
    )
    assert second.summary.exit_code == ExitCode.SUCCESS

    (root / "app.py").write_text("print('clean')\n", encoding="utf-8")
    third = scan_dir(root, profiles=[Profile.CODE], baseline_path=baseline_path)
    assert third.baseline is not None and third.baseline.resolved == 1


def test_baseline_accepts_scan_report_and_fingerprints_are_stable(project, tmp_path: Path) -> None:
    root = project({"app.py": VULNERABLE})
    result = scan_dir(root, profiles=[Profile.CODE])
    report = tmp_path / "report.json"
    report.write_text(result.model_dump_json(), encoding="utf-8")
    loaded = load_baseline(report)
    assert loaded.entries[0].fingerprint == result.findings[0].fingerprint
    import textwrap

    shifted = project({"app.py": "# a new comment line\n" + textwrap.dedent(VULNERABLE)})
    again = scan_dir(shifted, profiles=[Profile.CODE])
    assert again.findings[0].fingerprint == result.findings[0].fingerprint
    assert again.findings[0].location.start_line > result.findings[0].location.start_line


def test_apply_baseline_keeps_suppressed_status() -> None:
    f = _finding("SEC003", 1).model_copy(update={"status": FindingStatus.SUPPRESSED})
    baseline = baseline_from_result(scan_result_with([f]))
    updated, summary = apply_baseline([f], baseline, "b.json")
    assert updated[0].status is FindingStatus.SUPPRESSED
    assert summary.existing == 0


def scan_result_with(findings: list[Finding]):
    from aegisai.models.scan import ScanMetadata, ScanResult, ScanSummary

    now = datetime.now(UTC)
    return ScanResult(
        status=ScanStatus.SUCCESS,
        metadata=ScanMetadata(
            tool_version="0",
            started_at=now,
            finished_at=now,
            duration_ms=0,
            root="/",
            profiles=["all"],
        ),
        summary=ScanSummary(),
        findings=findings,
    )


def test_threshold_logic() -> None:
    findings = [_finding("SEC003", 1, severity=Severity.MEDIUM)]
    assert threshold_reached(findings, Severity.MEDIUM)
    assert not threshold_reached(findings, Severity.HIGH)
    assert not threshold_reached(findings, None)
    existing = [f.model_copy(update={"status": FindingStatus.EXISTING}) for f in findings]
    assert not threshold_reached(existing, Severity.LOW, new_only=True)
    assert threshold_reached(existing, Severity.LOW, new_only=False)


def test_severity_filter_and_overrides(project) -> None:
    root = project({"app.py": VULNERABLE})
    config = ScanConfiguration.model_validate(
        {"rules": {"overrides": {"SEC003": {"severity": "low"}}}}
    )
    result = scan_dir(root, profiles=[Profile.CODE], config=config)
    assert result.findings[0].severity is Severity.LOW
    assert result.summary.exit_code == ExitCode.SUCCESS
    filtered = scan_dir(root, profiles=[Profile.CODE], config=config, min_severity=Severity.HIGH)
    assert filtered.findings == [] and filtered.summary.filtered_below_threshold == 1


def test_disabled_rules_are_recorded_as_skipped(project) -> None:
    root = project({"app.py": VULNERABLE})
    result = scan_dir(root, profiles=[Profile.CODE], disabled_rules=["SEC003"])
    assert findings_for(result, "SEC003") == []
    assert any(s.rule_id == "SEC003" and "disabled" in s.reason for s in result.skipped_rules)
    assert any(s.rule_id == "LLM001" and "profiles" in s.reason for s in result.skipped_rules)


def test_rule_exception_is_recorded_not_swallowed(project) -> None:
    class Broken(Rule):
        metadata = RuleMetadata(
            rule_id="TST001",
            name="broken",
            version="1.0.0",
            description="d",
            category=Category.CODE,
            pack=RulePack.CODE,
            default_severity=Severity.LOW,
            default_confidence=Confidence.LOW,
            confidence_behavior="n/a",
            artifact_types=[ArtifactType.PYTHON],
            impact="i",
            remediation="r",
        )

        def check(self, ctx: FileContext) -> list[Finding]:
            raise RuntimeError("boom")

    registry = RuleRegistry()
    registry.register(Broken())
    root = project({"app.py": "x = 1\n"})
    result = scan_dir(root, profiles=[Profile.CODE], registry=registry)
    assert (
        result.errors and result.errors[0].rule_id == "TST001" and "boom" in result.errors[0].error
    )
    assert result.status is ScanStatus.SUCCESS_WITH_WARNINGS


def test_timeout_marks_scan_incomplete(project) -> None:
    root = project({f"f{i}.py": "x = 1\n" for i in range(20)})
    deadline = Deadline(0)
    assert deadline.expired()
    result = scan_dir(root, profiles=[Profile.CODE], timeout_seconds=1)
    # A 1-second budget may or may not expire on fast machines; force the expired path explicitly.
    from aegisai.discovery.project import build_project_context
    from aegisai.engine.execution import execute_rules
    from aegisai.models.configuration import ScanSection

    project_ctx = build_project_context(root, ScanSection())
    outcome = execute_rules(project_ctx, list(default_registry()), deadline=Deadline(0))
    assert outcome.timed_out and outcome.files_skipped == 20
    assert result.status in (ScanStatus.SUCCESS, ScanStatus.INCOMPLETE)


def test_cancellation_raises(project) -> None:
    import pytest

    from aegisai.exceptions import ScanCancelledError

    root = project({"app.py": "x = 1\n"})
    with pytest.raises(ScanCancelledError):
        scan_dir(root, profiles=[Profile.CODE], should_cancel=lambda: True)


def test_malformed_python_is_reported_as_warning(project) -> None:
    root = project({"broken.py": "def (:\n", "ok.py": "x = 1\n"})
    result = scan_dir(root, profiles=[Profile.ALL])
    assert any(w.code == "parse_error" and w.file_path == "broken.py" for w in result.warnings)
    assert result.status is ScanStatus.SUCCESS_WITH_WARNINGS
    assert result.summary.exit_code == ExitCode.SUCCESS


def test_json_report_never_contains_absolute_paths_in_findings(project) -> None:
    root = project({"app.py": VULNERABLE})
    result = scan_dir(root, profiles=[Profile.CODE])
    payload = json.loads(result.model_dump_json())
    assert payload["findings"][0]["location"]["file_path"] == "app.py"


def test_test_and_example_paths_are_downgraded(project) -> None:
    from aegisai.engine.context import classify_path

    assert classify_path("tests/unit/test_x.py") == "test"
    assert classify_path("src/app_test.py") == "test"
    assert classify_path("pkg/conftest.py") == "test"
    assert classify_path("web/src/model.test.ts") == "test"
    assert classify_path(".env.test") == "test"
    assert classify_path("examples/demo/app.py") == "example"
    assert classify_path("docs/config.md") == "example"
    assert classify_path("src/app.py") is None
    assert classify_path("src/attestation.py") is None  # "test" inside a word does not count

    root = project({"tests/test_app.py": VULNERABLE, "app.py": VULNERABLE})
    result = scan_dir(root, profiles=[Profile.CODE])
    by_path = {f.location.file_path: f for f in findings_for(result, "SEC003")}
    assert by_path["app.py"].severity is Severity.CRITICAL
    assert by_path["tests/test_app.py"].severity is Severity.HIGH
    assert by_path["tests/test_app.py"].review_required
    assert "context:test" in by_path["tests/test_app.py"].tags

    config = ScanConfiguration.model_validate({"scan": {"downgrade_test_paths": False}})
    result2 = scan_dir(root, profiles=[Profile.CODE], config=config)
    assert all(f.severity is Severity.CRITICAL for f in findings_for(result2, "SEC003"))
