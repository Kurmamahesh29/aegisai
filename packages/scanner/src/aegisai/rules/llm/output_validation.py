"""LLM004: LLM output rendered or acted on at a recognised web boundary without validation."""

from __future__ import annotations

from aegisai.analyzers.dataflow import SinkKind, SourceKind
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack
from aegisai.rules.common import (
    SINK_LABEL,
    adjusted_confidence,
    finding_from_flow,
    has_strong_guard,
)


class MissingOutputValidationRule(Rule):
    metadata = RuleMetadata(
        rule_id="LLM004",
        name="LLM output reaches a web boundary without validation",
        version="1.0.0",
        description=(
            "Model output is rendered as HTML (render_template_string, Markup, mark_safe, "
            "HTMLResponse, unsafe_allow_html) or used as a redirect target. These sinks are "
            "framework boundaries where encoding or validation is expected; model output that "
            "contains markup or URLs chosen by an attacker leads to XSS or open redirects."
        ),
        category=Category.LLM,
        pack=RulePack.LLM,
        default_severity=Severity.HIGH,
        default_confidence=Confidence.HIGH,
        confidence_behavior=(
            "High for a direct path into a recognised HTML or redirect sink; medium when an "
            "escaping or validation call is referenced. Only reported when framework-specific "
            "sinks are present, so plain return values are not flagged."
        ),
        artifact_types=[ArtifactType.PYTHON],
        impact="Cross-site scripting or open redirect driven by prompt injection.",
        remediation=(
            "Render model output as text (auto-escaped templates, Markdown with HTML disabled) and "
            "validate redirect targets against an allow-list of hosts."
        ),
        references=[
            "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://cwe.mitre.org/data/definitions/601.html",
        ],
        cwe_ids=["CWE-79", "CWE-601"],
        owasp_references=["OWASP Top 10 for LLM Applications 2025 LLM05"],
        tags=["llm", "output-handling", "web"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        dataflow = ctx.dataflow
        if dataflow is None:
            return []
        findings: list[Finding] = []
        for flow in dataflow.flows_matching(
            {SourceKind.LLM_OUTPUT}, {SinkKind.HTML_RENDER, SinkKind.REDIRECT}
        ):
            if has_strong_guard(flow):
                continue
            confidence, review = adjusted_confidence(flow, Confidence.HIGH)
            severity = Severity.HIGH if flow.sink.kind is SinkKind.HTML_RENDER else Severity.MEDIUM
            findings.append(
                finding_from_flow(
                    ctx,
                    self,
                    flow,
                    severity=severity,
                    confidence=confidence,
                    review_required=review,
                    title=f"LLM output reaches {SINK_LABEL[flow.sink.kind]} without validation",
                )
            )
        return findings
