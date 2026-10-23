"""SEC002: sensitive values written to logs or stdout."""

from __future__ import annotations

from aegisai.analyzers.dataflow import SinkKind, SourceKind
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack
from aegisai.rules.common import adjusted_confidence, finding_from_flow


class SensitiveLoggingRule(Rule):
    metadata = RuleMetadata(
        rule_id="SEC002",
        name="Sensitive value exposed in logs",
        version="1.0.0",
        description=(
            "A value read from a secret source (environment variable, secrets manager, or a "
            "variable whose name indicates a credential) is passed to a logging or print call. "
            "Logs are widely replicated and rarely protected like secrets."
        ),
        category=Category.CODE,
        pack=RulePack.CODE,
        default_severity=Severity.MEDIUM,
        default_confidence=Confidence.HIGH,
        confidence_behavior=(
            "High when the value comes from an explicit secret source such as os.environ; medium "
            "when only the variable name suggests a secret."
        ),
        artifact_types=[ArtifactType.PYTHON],
        impact="Credentials may be exposed to anyone with log access, including third-party log platforms.",
        remediation="Remove the value from the log call or log a redacted/hashed form; configure a redaction filter.",
        references=[
            "https://cwe.mitre.org/data/definitions/532.html",
        ],
        cwe_ids=["CWE-532"],
        owasp_references=["OWASP Top 10 2021 A09"],
        tags=["logging", "secrets"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        dataflow = ctx.dataflow
        if dataflow is None:
            return []
        findings: list[Finding] = []
        for flow in dataflow.flows_matching({SourceKind.SECRET_VALUE}, {SinkKind.LOGGING}):
            confidence, review = adjusted_confidence(flow, Confidence.HIGH)
            severity = Severity.MEDIUM if flow.source.name_based else Severity.HIGH
            findings.append(
                finding_from_flow(
                    ctx,
                    self,
                    flow,
                    severity=severity,
                    confidence=confidence,
                    review_required=review,
                    title="Secret value passed to a logging call",
                )
            )
        return findings
