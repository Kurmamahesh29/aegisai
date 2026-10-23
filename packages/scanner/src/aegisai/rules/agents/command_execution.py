"""AGT001: agent-controlled tool input reaches command or code execution."""

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
}


class AgentToolCommandExecutionRule(Rule):
    metadata = RuleMetadata(
        rule_id="AGT001",
        name="Agent tool parameter reaches command execution",
        version="1.0.0",
        description=(
            "A parameter of a function registered as an agent tool (``@tool``, "
            "``@function_tool``, ``Tool(func=...)``, ``tools=[...]``) flows into shell, code, SQL, "
            "filesystem, network or deserialization calls without a recognised validation step. "
            "Tool arguments are chosen by the model, which can be steered by prompt injection."
        ),
        category=Category.AGENTS,
        pack=RulePack.AGENTS,
        default_severity=Severity.CRITICAL,
        default_confidence=Confidence.HIGH,
        confidence_behavior=(
            "High for a direct path from a tool parameter to the sink; medium when a "
            "validation-looking check references the parameter."
        ),
        artifact_types=[ArtifactType.PYTHON],
        impact="An attacker who influences the agent's context can execute commands or queries with the agent's privileges.",
        remediation=(
            "Constrain tool inputs to typed, enumerated values; implement specific operations "
            "instead of generic command runners; run unavoidable execution in a sandbox with "
            "least privilege and require human approval for high-impact actions."
        ),
        references=[
            "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
        cwe_ids=["CWE-78", "CWE-94"],
        owasp_references=["OWASP Top 10 for LLM Applications 2025 LLM06"],
        tags=["agents", "tools"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        dataflow = ctx.dataflow
        if dataflow is None:
            return []
        findings: list[Finding] = []
        for flow in dataflow.flows_matching({SourceKind.TOOL_PARAM}, SINKS):
            if has_strong_guard(flow):
                continue
            confidence, review = adjusted_confidence(flow, Confidence.HIGH)
            severity = severity_for_sink(flow.sink.kind)
            if (
                flow.sink.kind is SinkKind.SHELL_EXEC
                and flow.sink.arg_form == "list_other"
                and not flow.sink.shell
            ):
                severity = Severity.HIGH
            findings.append(
                finding_from_flow(
                    ctx,
                    self,
                    flow,
                    severity=severity,
                    confidence=confidence,
                    review_required=review,
                    title=f"Agent tool parameter reaches {SINK_LABEL[flow.sink.kind]}",
                )
            )
        return findings
