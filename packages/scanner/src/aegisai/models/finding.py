"""Finding model shared by every analyzer, reporter and integration."""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

FINDING_SCHEMA_VERSION = "1.0.0"


class Severity(StrEnum):
    """Documented severity taxonomy, ordered from most to least severe."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def rank(self) -> int:
        """Numeric rank where a higher number means more severe."""
        return _SEVERITY_RANK[self]

    def at_least(self, threshold: Severity) -> bool:
        """Return True when this severity is equal to or more severe than ``threshold``."""
        return self.rank >= threshold.rank


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 1,
}


class Confidence(StrEnum):
    """How confident the analyzer is that the finding is a true positive."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}[self]


class FindingStatus(StrEnum):
    """Lifecycle status relative to a baseline and suppressions."""

    NEW = "new"
    EXISTING = "existing"
    SUPPRESSED = "suppressed"


class Category(StrEnum):
    """High-level finding categories used for grouping and profiles."""

    CODE = "code"
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"
    CONFIGURATION = "configuration"
    LLM = "llm"
    AGENTS = "agents"
    RAG = "rag"
    MCP = "mcp"


class Location(BaseModel):
    """Source location. Lines and columns are 1-based; ``end_*`` are inclusive."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    file_path: str = Field(description="Path relative to the scan root, POSIX separators.")
    start_line: int = Field(ge=1)
    start_column: int = Field(default=1, ge=1)
    end_line: int = Field(ge=1)
    end_column: int = Field(default=1, ge=1)

    @field_validator("file_path")
    @classmethod
    def _posix(cls, value: str) -> str:
        return value.replace("\\", "/")


class Evidence(BaseModel):
    """A single piece of evidence supporting a finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str = Field(description="Evidence kind, e.g. 'source', 'sink', 'line', 'config_key'.")
    description: str
    snippet: str | None = Field(default=None, description="Redacted code or config excerpt.")
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)


class SuppressionInfo(BaseModel):
    """Why and by which mechanism a finding was suppressed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str = Field(description="'inline' or 'config'.")
    reason: str
    expires: date | None = None
    expired: bool = False
    matched_by: str = Field(description="What matched: 'fingerprint', 'rule_id+path', or 'inline'.")


class Finding(BaseModel):
    """Normalized security finding."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    schema_version: str = FINDING_SCHEMA_VERSION
    finding_id: str = Field(description="Unique id within a scan result.")
    rule_id: str = Field(pattern=r"^[A-Z]{3,4}[0-9]{3}$")
    rule_version: str
    title: str
    description: str
    category: Category
    severity: Severity
    confidence: Confidence
    status: FindingStatus = FindingStatus.NEW
    location: Location
    evidence: list[Evidence] = Field(default_factory=list)
    evidence_summary: str = Field(description="One-line, redacted description of the evidence.")
    impact: str
    remediation: str
    references: list[str] = Field(default_factory=list)
    analyzer: str = Field(description="Analyzer that produced the finding (e.g. 'python_ast').")
    first_seen: datetime | None = Field(
        default=None, description="Set from the baseline when the finding already existed."
    )
    fingerprint: str = Field(min_length=16, description="Stable identity across scans.")
    cwe_ids: list[str] = Field(default_factory=list)
    owasp_references: list[str] = Field(default_factory=list)
    suppression: SuppressionInfo | None = None
    review_required: bool = Field(
        default=False,
        description="True for heuristic findings that need human confirmation.",
    )
    tags: list[str] = Field(default_factory=list)

    @field_validator("cwe_ids")
    @classmethod
    def _cwe_format(cls, values: list[str]) -> list[str]:
        for value in values:
            if not value.startswith("CWE-") or not value[4:].isdigit():
                raise ValueError(f"invalid CWE identifier: {value!r}")
        return values

    @property
    def is_active(self) -> bool:
        """True when the finding counts towards thresholds (i.e. not suppressed)."""
        return self.status is not FindingStatus.SUPPRESSED

    def short_location(self) -> str:
        return f"{self.location.file_path}:{self.location.start_line}"
