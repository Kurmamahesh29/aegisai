"""Shared interface and helpers for external scanner integrations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from aegisai.discovery.project import ProjectContext
from aegisai.models.configuration import IntegrationSettings
from aegisai.models.finding import Confidence, Evidence, Finding, Location, Severity
from aegisai.models.rule import RuleMetadata
from aegisai.models.scan import AnalyzerResult, AnalyzerStatus, ScanWarning
from aegisai.utils.hashing import fingerprint, short_id
from aegisai.utils.paths import to_posix_relative
from aegisai.utils.redaction import redact_text


@dataclass(slots=True)
class IntegrationOutcome:
    result: AnalyzerResult
    findings: list[Finding] = field(default_factory=list)
    warnings: list[ScanWarning] = field(default_factory=list)


class ExternalAnalyzer(ABC):
    """An optional external scanner (Gitleaks, OSV-Scanner, Semgrep)."""

    name: str
    executable_name: str

    @abstractmethod
    def run(
        self, project: ProjectContext, settings: IntegrationSettings, timeout_seconds: int
    ) -> IntegrationOutcome:
        """Execute the scanner and normalise its output. Must not raise for tool failures."""

    def disabled(self) -> IntegrationOutcome:
        return IntegrationOutcome(
            AnalyzerResult(
                name=self.name, status=AnalyzerStatus.DISABLED, message="disabled by configuration"
            )
        )


def normalize_path(root: Path, raw: str) -> str:
    """Convert a scanner-reported path into a POSIX path relative to ``root``."""
    candidate = Path(raw)
    if candidate.is_absolute():
        try:
            return to_posix_relative(root, candidate.resolve())
        except OSError:
            return candidate.as_posix()
    return candidate.as_posix().lstrip("./")


class FingerprintCounter:
    """Disambiguates identical (rule, path, snippet) tuples produced by one integration."""

    def __init__(self) -> None:
        self._seen: dict[tuple[str, str, str], int] = {}

    def next(self, rule_id: str, rel_path: str, material: str) -> int:
        key = (rule_id, rel_path, material)
        value = self._seen.get(key, 0)
        self._seen[key] = value + 1
        return value


def build_finding(
    meta: RuleMetadata,
    *,
    rel_path: str,
    line: int,
    column: int = 1,
    end_line: int | None = None,
    end_column: int | None = None,
    evidence_summary: str,
    analyzer: str,
    counter: FingerprintCounter,
    severity: Severity | None = None,
    confidence: Confidence | None = None,
    title: str | None = None,
    description: str | None = None,
    remediation: str | None = None,
    references: Iterable[str] = (),
    evidence: Iterable[Evidence] = (),
    tags: Iterable[str] = (),
    cwe_ids: Iterable[str] = (),
    fingerprint_material: str | None = None,
    review_required: bool | None = None,
) -> Finding:
    """Create a redacted finding for an external analyzer result."""
    summary = redact_text(evidence_summary).strip()
    material = fingerprint_material if fingerprint_material is not None else summary
    occurrence = counter.next(meta.rule_id, rel_path, material)
    fp = fingerprint(meta.rule_id, rel_path, material, occurrence)
    refs = list(dict.fromkeys([*meta.references, *references]))
    return Finding(
        finding_id=short_id(fp, rel_path, str(line)),
        rule_id=meta.rule_id,
        rule_version=meta.version,
        title=title or meta.name,
        description=redact_text(description or meta.description),
        category=meta.category,
        severity=severity or meta.default_severity,
        confidence=confidence or meta.default_confidence,
        location=Location(
            file_path=rel_path,
            start_line=max(1, line),
            start_column=max(1, column),
            end_line=max(1, end_line or line),
            end_column=max(1, end_column or column),
        ),
        evidence=[
            Evidence(
                kind=e.kind,
                description=redact_text(e.description),
                snippet=redact_text(e.snippet) if e.snippet else None,
                line=e.line,
                column=e.column,
            )
            for e in evidence
        ],
        evidence_summary=summary[:500],
        impact=meta.impact,
        remediation=remediation or meta.remediation,
        references=refs,
        analyzer=analyzer,
        fingerprint=fp,
        cwe_ids=list(dict.fromkeys([*meta.cwe_ids, *cwe_ids])),
        owasp_references=list(meta.owasp_references),
        review_required=meta.heuristic if review_required is None else review_required,
        tags=list(tags) or list(meta.tags),
    )
