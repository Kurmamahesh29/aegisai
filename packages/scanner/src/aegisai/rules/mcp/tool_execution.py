"""MCP001: MCP tool input reaches dangerous execution without validation."""

from __future__ import annotations

from aegisai.analyzers.dataflow import SinkKind, SourceKind
from aegisai.analyzers.javascript import find_dangerous_exec, imports_mcp_sdk
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Evidence, Finding, Severity
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


class MCPToolExecutionRule(Rule):
    metadata = RuleMetadata(
        rule_id="MCP001",
        name="MCP tool input reaches dangerous execution",
        version="1.0.0",
        description=(
            "An argument of an MCP tool handler (``@mcp.tool()``, ``@server.call_tool()``) flows "
            "into shell, code, SQL, filesystem, network or deserialization calls without a "
            "recognised validation step. MCP clients forward model-chosen arguments, so any "
            "prompt injection in the client reaches the server with the server's privileges. "
            "For TypeScript/JavaScript servers a regex heuristic flags exec/spawn/eval inside "
            "files that import the MCP SDK."
        ),
        category=Category.MCP,
        pack=RulePack.MCP,
        default_severity=Severity.CRITICAL,
        default_confidence=Confidence.HIGH,
        confidence_behavior=(
            "High for a direct Python taint path; medium when a validation-looking check "
            "references the value; medium for JavaScript/TypeScript heuristic matches."
        ),
        artifact_types=[ArtifactType.PYTHON, ArtifactType.JAVASCRIPT, ArtifactType.TYPESCRIPT],
        impact="Remote command/code execution on the MCP server host by any connected client.",
        remediation=(
            "Validate tool arguments with a strict schema and allow-lists, avoid shell "
            "interpolation, use argument arrays, and restrict filesystem and network scope."
        ),
        references=[
            "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
        cwe_ids=["CWE-78", "CWE-94"],
        owasp_references=["OWASP Top 10 for LLM Applications 2025 LLM06"],
        tags=["mcp", "tools"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        if ctx.artifact_type is ArtifactType.PYTHON:
            return self._check_python(ctx)
        return self._check_javascript(ctx)

    def _check_python(self, ctx: FileContext) -> list[Finding]:
        dataflow = ctx.dataflow
        if dataflow is None:
            return []
        findings: list[Finding] = []
        for flow in dataflow.flows_matching({SourceKind.MCP_TOOL_PARAM}, SINKS):
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
                    title=f"MCP tool argument reaches {SINK_LABEL[flow.sink.kind]}",
                )
            )
        return findings

    def _check_javascript(self, ctx: FileContext) -> list[Finding]:
        text = ctx.text
        if not imports_mcp_sdk(text):
            return []
        findings: list[Finding] = []
        for match in find_dangerous_exec(text):
            severity = Severity.CRITICAL if (match.shell or match.interpolated) else Severity.HIGH
            findings.append(
                ctx.new_finding(
                    self,
                    line=match.line,
                    column=match.column,
                    end_line=match.line,
                    end_column=match.column + len(match.call),
                    evidence=[
                        Evidence(
                            kind="sink",
                            description=f"{match.call}() in an MCP SDK server module"
                            + (" with shell: true" if match.shell else "")
                            + (" using string interpolation" if match.interpolated else ""),
                            snippet=match.snippet,
                            line=match.line,
                            column=match.column,
                        ),
                    ],
                    evidence_summary=f"{match.call}() called in MCP server module"
                    + (" with interpolated input" if match.interpolated else ""),
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    title=f"Dangerous {match.call}() in MCP server (heuristic)",
                    review_required=True,
                    analyzer="javascript_heuristics",
                    fingerprint_material=f"js:{match.call}:{match.snippet}",
                )
            )
        return findings
