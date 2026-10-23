"""Strictly validated configuration model for ``.aegisai.yaml`` and CLI overrides."""

from __future__ import annotations

from datetime import date
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegisai.models.finding import Confidence, Severity
from aegisai.models.rule import RulePack

CONFIG_VERSION = 1
DEFAULT_CONFIG_FILENAME = ".aegisai.yaml"


class Profile(StrEnum):
    """Scan profiles map to sets of rule packs."""

    ALL = "all"
    AI = "ai"
    LLM = "llm"
    AGENTS = "agents"
    RAG = "rag"
    MCP = "mcp"
    CODE = "code"
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"


PROFILE_PACKS: dict[Profile, frozenset[RulePack]] = {
    Profile.ALL: frozenset(RulePack),
    Profile.AI: frozenset({RulePack.LLM, RulePack.AGENTS, RulePack.RAG, RulePack.MCP}),
    Profile.LLM: frozenset({RulePack.LLM}),
    Profile.AGENTS: frozenset({RulePack.AGENTS}),
    Profile.RAG: frozenset({RulePack.RAG}),
    Profile.MCP: frozenset({RulePack.MCP}),
    Profile.CODE: frozenset({RulePack.CODE, RulePack.SECRETS, RulePack.DEPENDENCIES}),
    Profile.SECRETS: frozenset({RulePack.SECRETS}),
    Profile.DEPENDENCIES: frozenset({RulePack.DEPENDENCIES}),
}


def packs_for_profiles(profiles: list[Profile]) -> frozenset[RulePack]:
    packs: set[RulePack] = set()
    for profile in profiles:
        packs |= PROFILE_PACKS[profile]
    return frozenset(packs)


class ReportFormat(StrEnum):
    TERMINAL = "terminal"
    JSON = "json"
    SARIF = "sarif"
    HTML = "html"


DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".git/**",
    ".hg/**",
    ".svn/**",
    ".venv/**",
    "venv/**",
    "env/**",
    "node_modules/**",
    "dist/**",
    "build/**",
    "__pycache__/**",
    ".mypy_cache/**",
    ".pytest_cache/**",
    ".ruff_cache/**",
    ".tox/**",
    ".idea/**",
    "*.min.js",
    "*.egg-info/**",
)


class ScanSection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profiles: list[Profile] = Field(default_factory=lambda: [Profile.ALL])
    exclude: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    include: list[str] = Field(
        default_factory=list,
        description="Optional allow-list of glob patterns; empty means everything.",
    )
    max_file_size_kb: int = Field(default=1024, ge=1, le=1024 * 100)
    max_files: int = Field(default=50_000, ge=1)
    max_total_size_mb: int = Field(default=512, ge=1)
    timeout_seconds: int = Field(default=300, ge=1)
    follow_symlinks: bool = Field(
        default=False,
        description="Symlinks are never followed outside the root. Inside the root, only if True.",
    )
    min_confidence: Confidence = Field(
        default=Confidence.LOW, description="Discard findings below this confidence."
    )
    downgrade_test_paths: bool = Field(
        default=True,
        description=(
            "Lower severity by one step and mark findings in test, fixture, example and docs "
            "paths as review-required (they are usually dummy data)."
        ),
    )
    test_path_patterns: list[str] = Field(
        default_factory=list,
        description="Extra globs treated as test/example paths in addition to the built-in set.",
    )

    @field_validator("profiles")
    @classmethod
    def _non_empty(cls, value: list[Profile]) -> list[Profile]:
        if not value:
            raise ValueError("at least one profile is required")
        return value


class RuleOverride(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Severity | None = None
    enabled: bool = True


class RulesSection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    disabled: list[str] = Field(default_factory=list)
    overrides: dict[str, RuleOverride] = Field(default_factory=dict)

    @field_validator("disabled")
    @classmethod
    def _rule_ids(cls, values: list[str]) -> list[str]:
        for value in values:
            if not value.isupper() or not value[-3:].isdigit():
                raise ValueError(f"invalid rule id: {value!r}")
        return values


class ReportSection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    formats: list[ReportFormat] = Field(default_factory=lambda: [ReportFormat.TERMINAL])
    output_dir: str | None = None
    min_severity: Severity = Field(
        default=Severity.INFORMATIONAL, description="Only report findings at/above this level."
    )


class CISection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fail_on: Severity | None = Field(
        default=Severity.HIGH, description="Exit 1 when an active finding reaches this severity."
    )
    strict_integrations: bool = Field(
        default=False,
        description="Treat enabled-but-unavailable integrations as a scan failure (exit 3).",
    )


class IntegrationSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    required: bool = Field(
        default=False, description="If True and unavailable, the scan is marked incomplete."
    )
    executable: str | None = Field(
        default=None, description="Explicit executable path; defaults to PATH lookup."
    )
    timeout_seconds: int = Field(default=180, ge=1)
    extra_args: list[str] = Field(default_factory=list)


class SemgrepSettings(IntegrationSettings):
    enabled: bool = False
    config: list[str] = Field(
        default_factory=list,
        description="Explicit rule files or directories. Remote registry refs are refused.",
    )


class IntegrationsSection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    gitleaks: IntegrationSettings = Field(default_factory=IntegrationSettings)
    osv_scanner: IntegrationSettings = Field(default_factory=IntegrationSettings)
    semgrep: SemgrepSettings = Field(default_factory=SemgrepSettings)


class AIReviewSection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    provider: str | None = None
    model: str | None = None
    require_explicit_consent: bool = True
    redact_secrets: bool = True
    send_source_code: bool = Field(
        default=False, description="Source snippets are never transmitted unless True."
    )

    @model_validator(mode="after")
    def _consistent(self) -> AIReviewSection:
        if self.enabled and not self.provider:
            raise ValueError("ai_review.provider is required when ai_review.enabled is true")
        return self


class Suppression(BaseModel):
    """A single configured suppression. Must target a fingerprint or rule_id + path."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=3)
    fingerprint: str | None = None
    rule_id: str | None = None
    path: str | None = Field(default=None, description="Glob relative to the scan root.")
    expires: date | None = None
    created_by: str | None = None

    @model_validator(mode="after")
    def _target(self) -> Suppression:
        if self.fingerprint:
            return self
        if self.rule_id and self.path:
            return self
        raise ValueError("a suppression needs either 'fingerprint' or both 'rule_id' and 'path'")


class ScanConfiguration(BaseModel):
    """Root configuration object."""

    model_config = ConfigDict(extra="forbid")

    version: int = CONFIG_VERSION
    scan: ScanSection = Field(default_factory=ScanSection)
    rules: RulesSection = Field(default_factory=RulesSection)
    report: ReportSection = Field(default_factory=ReportSection)
    ci: CISection = Field(default_factory=CISection)
    integrations: IntegrationsSection = Field(default_factory=IntegrationsSection)
    ai_review: AIReviewSection = Field(default_factory=AIReviewSection)
    suppressions: list[Suppression] = Field(default_factory=list)

    @field_validator("version")
    @classmethod
    def _version(cls, value: int) -> int:
        if value != CONFIG_VERSION:
            raise ValueError(
                f"unsupported configuration version {value}; expected {CONFIG_VERSION}"
            )
        return value

    @property
    def selected_packs(self) -> frozenset[RulePack]:
        return packs_for_profiles(self.scan.profiles)
