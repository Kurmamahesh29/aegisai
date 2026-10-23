"""LLM001: untrusted LLM output reaches a sensitive operation."""

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
    severity_for_sink,
)

SENSITIVE_SINKS = {
    SinkKind.SHELL_EXEC,
    SinkKind.CODE_EXEC,
    SinkKind.SQL_EXEC,
    SinkKind.FILE_PATH,
    SinkKind.NETWORK_REQUEST,
    SinkKind.DESERIALIZATION,
    SinkKind.DYNAMIC_DISPATCH,
}


class LLMOutputToSensitiveOperationRule(Rule):
    metadata = RuleMetadata(
        rule_id="LLM001",
        name="LLM output reaches a sensitive operation",
        version="1.0.0",
        description=(
            "Text or structured output returned by a language model flows into a command, code "
            "evaluation, SQL statement, file path, outbound request or dynamic attribute lookup "
            "without a recognised validation step. Model output is attacker-influenced whenever "
            "any untrusted content (user messages, documents, web pages) reaches the prompt."
        ),
        category=Category.LLM,
        pack=RulePack.LLM,
        default_severity=Severity.HIGH,
        default_confidence=Confidence.HIGH,
        confidence_behavior=(
            "High for a direct path from a recognised LLM API call to the sink. Medium when a "
            "validation-looking check references the value. Dictionary-based dispatch on a fixed "
            "tool table is not reported."
        ),
        artifact_types=[ArtifactType.PYTHON],
        impact="Prompt injection becomes command injection, SQL injection, SSRF or path traversal.",
        remediation=(
            "Treat model output as untrusted input: parse it into a typed schema, validate each "
            "field against an allow-list, and execute privileged actions only through constrained "
            "tool wrappers that do not accept free-form commands."
        ),
        references=[
            "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
            "https://cwe.mitre.org/data/definitions/74.html",
        ],
        cwe_ids=["CWE-74"],
        owasp_references=["OWASP Top 10 for LLM Applications 2025 LLM05"],
        tags=["llm", "output-handling"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        dataflow = ctx.dataflow
        if dataflow is None:
            return []
        findings: list[Finding] = []
        for flow in dataflow.flows_matching({SourceKind.LLM_OUTPUT}, SENSITIVE_SINKS):
            if (
                flow.sink.kind is SinkKind.DYNAMIC_DISPATCH
                and flow.sink.argument == "subscript key"
            ):
                continue
            if has_strong_guard(flow):
                continue
            confidence, review = adjusted_confidence(flow, Confidence.HIGH)
            severity = severity_for_sink(flow.sink.kind)
            if flow.sink.kind is SinkKind.DYNAMIC_DISPATCH:
                severity = Severity.MEDIUM
            findings.append(
                finding_from_flow(
                    ctx,
                    self,
                    flow,
                    severity=severity,
                    confidence=confidence,
                    review_required=review,
                    title=f"LLM output reaches {SINK_LABEL[flow.sink.kind]}",
                )
            )
        return findings
