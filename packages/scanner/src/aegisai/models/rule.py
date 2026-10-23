"""Rule metadata model."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegisai.models.finding import Category, Confidence, Severity


class ArtifactType(StrEnum):
    """Kinds of input artifacts a rule can analyze."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JSON = "json"
    YAML = "yaml"
    TOML = "toml"
    ENV = "env"
    TEXT = "text"
    MANIFEST = "manifest"
    ANY = "any"


class RulePack(StrEnum):
    """Versioned rule packs; profiles select one or more packs."""

    CODE = "code"
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"
    LLM = "llm"
    AGENTS = "agents"
    RAG = "rag"
    MCP = "mcp"


class RuleMetadata(BaseModel):
    """Static description of a rule, used by reports, SARIF and ``aegisai rules``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(pattern=r"^[A-Z]{3,4}[0-9]{3}$")
    name: str
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    description: str
    category: Category
    pack: RulePack
    default_severity: Severity
    default_confidence: Confidence
    confidence_behavior: str = Field(
        description="Human-readable explanation of how confidence is derived."
    )
    artifact_types: list[ArtifactType]
    impact: str
    remediation: str
    references: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    owasp_references: list[str] = Field(default_factory=list)
    heuristic: bool = Field(
        default=False, description="True when findings generally require human review."
    )
    requires_integration: str | None = Field(
        default=None, description="External analyzer name required for this rule."
    )
    tags: list[str] = Field(default_factory=list)

    @field_validator("cwe_ids")
    @classmethod
    def _cwe_format(cls, values: list[str]) -> list[str]:
        for value in values:
            if not value.startswith("CWE-") or not value[4:].isdigit():
                raise ValueError(f"invalid CWE identifier: {value!r}")
        return values
