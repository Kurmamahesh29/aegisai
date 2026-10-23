"""RAG003: retrieved content enters a privileged action path."""

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
    SinkKind.HTML_RENDER,
}


class RetrievedContentToPrivilegedActionRule(Rule):
    metadata = RuleMetadata(
        rule_id="RAG003",
        name="Retrieved content reaches a privileged action",
        version="1.0.0",
        description=(
            "Content returned by a vector store, retriever or search index flows into command "
            "execution, code evaluation, SQL, filesystem, network, deserialization, dynamic "
            "dispatch or HTML rendering without a recognised trust boundary. Indexed documents "
            "are frequently attacker-writable (uploads, web pages, tickets), so they must be "
            "treated as untrusted input."
        ),
        category=Category.RAG,
        pack=RulePack.RAG,
        default_severity=Severity.HIGH,
        default_confidence=Confidence.HIGH,
        confidence_behavior="High for a direct path; medium when a validation-looking check references the value.",
        artifact_types=[ArtifactType.PYTHON],
        impact="Indirect prompt injection or poisoned documents escalate to code execution or data access.",
        remediation="Treat retrieved text as data only: never execute, query or render it; validate extracted fields against strict schemas.",
        references=[
            "https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/",
            "https://cwe.mitre.org/data/definitions/74.html",
        ],
        cwe_ids=["CWE-74"],
        owasp_references=["OWASP Top 10 for LLM Applications 2025 LLM08"],
        tags=["rag", "injection"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        dataflow = ctx.dataflow
        if dataflow is None:
            return []
        findings: list[Finding] = []
        for flow in dataflow.flows_matching({SourceKind.RETRIEVED_CONTENT}, SINKS):
            if (
                flow.sink.kind is SinkKind.DYNAMIC_DISPATCH
                and flow.sink.argument == "subscript key"
            ):
                continue
            if has_strong_guard(flow):
                continue
            confidence, review = adjusted_confidence(flow, Confidence.HIGH)
            findings.append(
                finding_from_flow(
                    ctx,
                    self,
                    flow,
                    severity=severity_for_sink(flow.sink.kind),
                    confidence=confidence,
                    review_required=review,
                    title=f"Retrieved content reaches {SINK_LABEL[flow.sink.kind]}",
                )
            )
        return findings
