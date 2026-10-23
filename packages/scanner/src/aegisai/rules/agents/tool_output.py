"""AGT004: untrusted tool output reaches a privileged decision or execution path."""

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

SINKS = {
    SinkKind.SHELL_EXEC,
    SinkKind.CODE_EXEC,
    SinkKind.SQL_EXEC,
    SinkKind.FILE_PATH,
    SinkKind.NETWORK_REQUEST,
    SinkKind.DESERIALIZATION,
    SinkKind.DYNAMIC_DISPATCH,
    SinkKind.TOOL_INVOCATION,
}


class UntrustedToolOutputRule(Rule):
    metadata = RuleMetadata(
        rule_id="AGT004",
        name="Tool output reaches a privileged path without handling",
        version="1.0.0",
        description=(
            "The result of a tool call (web search, page fetch, MCP tool, retrieval helper) is "
            "passed into command execution, code evaluation, SQL, filesystem, network, dynamic "
            "dispatch or another tool without a recognised validation step. Tool results come "
            "from third-party systems and can carry injected instructions or payloads."
        ),
        category=Category.AGENTS,
        pack=RulePack.AGENTS,
        default_severity=Severity.HIGH,
        default_confidence=Confidence.MEDIUM,
        confidence_behavior=(
            "Medium by default because tool receivers are recognised by naming convention; "
            "lowered to low when a validation-looking check references the value."
        ),
        artifact_types=[ArtifactType.PYTHON],
        impact="A malicious web page or tool response can escalate into actions on the host or downstream systems.",
        remediation=(
            "Validate and type tool results before use; never execute content returned by a tool; "
            "pass results to the model as data and let privileged actions go through constrained tools."
        ),
        references=[
            "https://genai.owasp.org/llmrisk/llm012025-prompt-injection/",
            "https://cwe.mitre.org/data/definitions/20.html",
        ],
        cwe_ids=["CWE-20"],
        owasp_references=["OWASP Top 10 for LLM Applications 2025 LLM01"],
        heuristic=True,
        tags=["agents", "tools"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        dataflow = ctx.dataflow
        if dataflow is None:
            return []
        findings: list[Finding] = []
        for flow in dataflow.flows_matching({SourceKind.TOOL_OUTPUT}, SINKS):
            if (
                flow.sink.kind is SinkKind.DYNAMIC_DISPATCH
                and flow.sink.argument == "subscript key"
            ):
                continue
            if has_strong_guard(flow):
                continue
            confidence, _ = adjusted_confidence(flow, Confidence.MEDIUM)
            severity = severity_for_sink(flow.sink.kind)
            if flow.sink.kind in (SinkKind.TOOL_INVOCATION, SinkKind.DYNAMIC_DISPATCH):
                severity = Severity.MEDIUM
            findings.append(
                finding_from_flow(
                    ctx,
                    self,
                    flow,
                    severity=severity,
                    confidence=confidence,
                    review_required=True,
                    title=f"Tool output reaches {SINK_LABEL[flow.sink.kind]}",
                )
            )
        return findings
