"""DEP001: known vulnerable dependency versions (via OSV-Scanner)."""

from __future__ import annotations

from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack


class VulnerableDependencyRule(Rule):
    """Metadata holder; findings are produced by the OSV-Scanner integration."""

    metadata = RuleMetadata(
        rule_id="DEP001",
        name="Known vulnerable dependency",
        version="1.0.0",
        description=(
            "A dependency version listed in a manifest or lockfile has a published vulnerability "
            "in the OSV database. Severity is derived from the advisory's CVSS score when present."
        ),
        category=Category.DEPENDENCIES,
        pack=RulePack.DEPENDENCIES,
        default_severity=Severity.HIGH,
        default_confidence=Confidence.HIGH,
        confidence_behavior="High when the advisory carries a severity score; medium when it does not.",
        artifact_types=[ArtifactType.MANIFEST],
        impact="The application inherits the vulnerability; exploitability depends on how the package is used.",
        remediation="Upgrade to a fixed version listed in the advisory, or document why the vulnerable code path is unreachable.",
        references=["https://osv.dev/", "https://cwe.mitre.org/data/definitions/1395.html"],
        cwe_ids=["CWE-1395"],
        owasp_references=["OWASP Top 10 2021 A06"],
        requires_integration="osv_scanner",
        tags=["dependencies"],
    )

    def applies_to(self, ctx: FileContext) -> bool:
        return False

    def check(self, ctx: FileContext) -> list[Finding]:
        return []
