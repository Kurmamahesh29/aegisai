"""SMG001: findings reported by an explicitly configured local Semgrep ruleset."""

from __future__ import annotations

from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack


class SemgrepFindingRule(Rule):
    """Metadata holder; findings are produced by the Semgrep integration."""

    metadata = RuleMetadata(
        rule_id="SMG001",
        name="Semgrep rule match",
        version="1.0.0",
        description=(
            "A locally configured Semgrep rule matched. The upstream check id, message and "
            "severity are preserved. AegisAI does not independently verify Semgrep findings."
        ),
        category=Category.CODE,
        pack=RulePack.CODE,
        default_severity=Severity.MEDIUM,
        default_confidence=Confidence.MEDIUM,
        confidence_behavior="Medium: inherits the upstream rule quality; review each match.",
        artifact_types=[ArtifactType.ANY],
        impact="Depends on the matched rule.",
        remediation="Follow the remediation guidance of the matched Semgrep rule.",
        references=["https://semgrep.dev/docs/"],
        heuristic=True,
        requires_integration="semgrep",
        tags=["semgrep"],
    )

    def applies_to(self, ctx: FileContext) -> bool:
        return False

    def check(self, ctx: FileContext) -> list[Finding]:
        return []
