"""LLM002: untrusted user or retrieved content reaches a tool execution path."""

from __future__ import annotations

import re

from aegisai.analyzers.dataflow import SinkKind, SourceKind
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack
from aegisai.rules.common import adjusted_confidence, finding_from_flow, has_strong_guard

DANGEROUS_TOOL_RECEIVER = re.compile(
    r"(?i)(shell|bash|terminal|python|repl|code|exec|sql|file|filesystem|requests|http|browser)"
)


class UntrustedContentToToolRule(Rule):
    metadata = RuleMetadata(
        rule_id="LLM002",
        name="Untrusted content reaches tool execution",
        version="1.0.0",
        description=(
            "User-supplied text or content retrieved from a document store is passed directly into "
            "a tool invocation (``tool.run(...)``, ``tool.invoke(...)``, ``execute_tool(...)``). "
            "Tools typically perform side effects; feeding them unvalidated content lets prompt "
            "injection or poisoned documents trigger those side effects."
        ),
        category=Category.LLM,
        pack=RulePack.LLM,
        default_severity=Severity.HIGH,
        default_confidence=Confidence.MEDIUM,
        confidence_behavior=(
            "High when the tool receiver is a recognised dangerous tool (shell, Python REPL, SQL, "
            "filesystem, HTTP). Medium otherwise because the tool's capabilities are unknown."
        ),
        artifact_types=[ArtifactType.PYTHON],
        impact="Attacker-controlled content drives privileged tool actions.",
        remediation=(
            "Route tool calls through the model's structured tool-calling interface with typed, "
            "validated arguments; never pass raw user or document text as a tool input."
        ),
        references=[
            "https://genai.owasp.org/llmrisk/llm012025-prompt-injection/",
            "https://cwe.mitre.org/data/definitions/20.html",
        ],
        cwe_ids=["CWE-20"],
        owasp_references=["OWASP Top 10 for LLM Applications 2025 LLM01"],
        heuristic=True,
        tags=["llm", "tools"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        dataflow = ctx.dataflow
        if dataflow is None:
            return []
        findings: list[Finding] = []
        for flow in dataflow.flows_matching(
            {SourceKind.USER_INPUT, SourceKind.RETRIEVED_CONTENT}, {SinkKind.TOOL_INVOCATION}
        ):
            if has_strong_guard(flow):
                continue
            dangerous = DANGEROUS_TOOL_RECEIVER.search(flow.sink.callee) is not None
            base = Confidence.HIGH if dangerous else Confidence.MEDIUM
            confidence, review = adjusted_confidence(flow, base)
            findings.append(
                finding_from_flow(
                    ctx,
                    self,
                    flow,
                    severity=Severity.HIGH if dangerous else Severity.MEDIUM,
                    confidence=confidence,
                    review_required=review or not dangerous,
                    title="Untrusted content passed directly to a tool",
                )
            )
        return findings
