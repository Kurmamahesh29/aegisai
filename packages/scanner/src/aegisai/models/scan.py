"""Scan result, analyzer result and summary models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from aegisai.models.finding import Finding, Severity

SCAN_SCHEMA_VERSION = "1.0.0"


class AnalyzerStatus(StrEnum):
    """Outcome of a single analyzer (built-in or external)."""

    COMPLETED = "completed"
    DISABLED = "disabled"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class ScanStatus(StrEnum):
    """Overall scan outcome. Findings are reported separately in the summary."""

    SUCCESS = "success"
    SUCCESS_WITH_WARNINGS = "success_with_warnings"
    INCOMPLETE = "incomplete"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ExitCode:
    """Documented exit-code contract for the CLI."""

    SUCCESS = 0
    FINDINGS_AT_THRESHOLD = 1
    FAILED = 2
    INCOMPLETE = 3
    CANCELLED = 130


class AnalyzerResult(BaseModel):
    """Status record for each analyzer that was configured for the scan."""

    model_config = ConfigDict(extra="forbid")

    name: str
    status: AnalyzerStatus
    required: bool = Field(
        default=False, description="If True, a non-completed status makes the scan incomplete."
    )
    message: str | None = None
    version: str | None = None
    findings_count: int = 0
    duration_ms: int = 0
    files_processed: int = 0


class SkippedRule(BaseModel):
    """A rule that did not run, with the reason."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    reason: str


class ScanWarning(BaseModel):
    """A non-fatal problem encountered while scanning."""

    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    file_path: str | None = None


class RuleExecutionError(BaseModel):
    """An exception raised by a rule for a specific file (recorded, never swallowed)."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    file_path: str
    error: str


class BaselineSummary(BaseModel):
    """Comparison against a baseline file."""

    model_config = ConfigDict(extra="forbid")

    baseline_path: str
    new: int = 0
    existing: int = 0
    resolved: int = 0
    resolved_fingerprints: list[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    """Counts used by reporters and for the CI exit code."""

    model_config = ConfigDict(extra="forbid")

    total_findings: int = 0
    active_findings: int = Field(default=0, description="Findings not suppressed.")
    suppressed_findings: int = 0
    filtered_below_threshold: int = Field(
        default=0, description="Findings hidden by the --severity reporting filter."
    )
    by_severity: dict[Severity, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_rule: dict[str, int] = Field(default_factory=dict)
    files_discovered: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    rules_executed: int = 0
    rules_skipped: int = 0
    fail_on: Severity | None = None
    threshold_reached: bool = False
    exit_code: int = ExitCode.SUCCESS


class ScanMetadata(BaseModel):
    """Information about the scan invocation."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str = "AegisAI"
    tool_version: str
    started_at: datetime
    finished_at: datetime
    duration_ms: int
    root: str = Field(description="Absolute path of the scanned project root.")
    profiles: list[str]
    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    config_path: str | None = None
    baseline_path: str | None = None
    command_line: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Top-level scan output. Serialized as-is for the JSON report."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCAN_SCHEMA_VERSION
    status: ScanStatus
    status_reason: str | None = Field(
        default=None, description="Why the status is not SUCCESS, when applicable."
    )
    metadata: ScanMetadata
    summary: ScanSummary
    findings: list[Finding] = Field(default_factory=list)
    analyzers: list[AnalyzerResult] = Field(default_factory=list)
    skipped_rules: list[SkippedRule] = Field(default_factory=list)
    warnings: list[ScanWarning] = Field(default_factory=list)
    errors: list[RuleExecutionError] = Field(default_factory=list)
    baseline: BaselineSummary | None = None

    @property
    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.is_active]

    @property
    def is_clean(self) -> bool:
        """True only when the scan completed and no active findings were reported."""
        return self.status in (ScanStatus.SUCCESS, ScanStatus.SUCCESS_WITH_WARNINGS) and not any(
            f.is_active for f in self.findings
        )
