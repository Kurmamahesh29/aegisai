"""AGT003: tool definitions that expose unnecessarily broad capabilities."""

from __future__ import annotations

import ast
import re

from aegisai.analyzers.dataflow import FunctionRole
from aegisai.analyzers.python_ast import get_keyword, is_truthy_constant, node_end
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Evidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack

DANGEROUS_TOOL_CLASSES: dict[str, str] = {
    "ShellTool": "executes arbitrary shell commands",
    "BashProcess": "executes arbitrary shell commands",
    "TerminalTool": "executes arbitrary shell commands",
    "PythonREPLTool": "executes arbitrary Python code",
    "PythonAstREPLTool": "executes arbitrary Python code",
    "PythonREPL": "executes arbitrary Python code",
    "CodeInterpreterTool": "executes arbitrary code",
    "LocalPythonExecutor": "executes arbitrary Python code",
    "FileManagementToolkit": "grants filesystem access (restrict with root_dir)",
    "RequestsToolkit": "performs arbitrary HTTP requests",
    "RequestsPostTool": "performs arbitrary HTTP POST requests",
    "RequestsDeleteTool": "performs arbitrary HTTP DELETE requests",
    "SQLDatabaseToolkit": "executes arbitrary SQL",
    "QuerySQLDataBaseTool": "executes arbitrary SQL",
    "QuerySQLDatabaseTool": "executes arbitrary SQL",
}
DANGEROUS_LOAD_TOOLS = {
    "terminal",
    "python_repl",
    "requests_all",
    "requests_post",
    "requests_delete",
    "requests_put",
    "requests_patch",
}
DANGEROUS_FLAGS = {
    "allow_dangerous_code",
    "allow_dangerous_requests",
    "allow_dangerous_deserialization",
    "allow_dangerous_tools",
    "dangerously_allow_browser",
}
BROAD_DESCRIPTION = re.compile(
    r"(?i)\b(any|arbitrary|anything|unrestricted|full access|all files|entire|whatever)\b.{0,60}\b"
    r"(command|commands|shell|bash|python|code|sql|query|file|files|filesystem|system|url|request|script)\b"
    r"|\b(command|commands|shell|bash|python|code|sql|query|file|files|filesystem|system|url|request|script)\b.{0,60}\b(any|arbitrary|anything|unrestricted|full access|all files|entire|whatever)\b"
)


class OverlyBroadToolRule(Rule):
    metadata = RuleMetadata(
        rule_id="AGT003",
        name="Tool exposes unnecessarily broad capabilities",
        version="1.0.0",
        description=(
            "The agent is given a general-purpose execution tool (shell, Python REPL, raw SQL, "
            "unrestricted HTTP or filesystem toolkit), a dangerous-mode flag is enabled, or a tool "
            "description advertises arbitrary command/code/file access. Broad tools turn any "
            "prompt injection into full control of the host."
        ),
        category=Category.AGENTS,
        pack=RulePack.AGENTS,
        default_severity=Severity.HIGH,
        default_confidence=Confidence.HIGH,
        confidence_behavior=(
            "High for known dangerous tool classes and explicit dangerous-mode flags; medium for "
            "description-based matches. Smolagents authorized_imports=['*'] is reported as high."
        ),
        artifact_types=[ArtifactType.PYTHON],
        impact="The model can perform actions far beyond the task, including data exfiltration and host compromise.",
        remediation=(
            "Replace generic tools with narrowly scoped functions that accept validated parameters; "
            "if execution is necessary, sandbox it, restrict the filesystem root and network, and "
            "require approval."
        ),
        references=[
            "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
            "https://cwe.mitre.org/data/definitions/250.html",
        ],
        cwe_ids=["CWE-250"],
        owasp_references=["OWASP Top 10 for LLM Applications 2025 LLM06"],
        tags=["agents", "tools"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        module = ctx.python_module
        dataflow = ctx.dataflow
        if module is None or dataflow is None:
            return []
        findings: list[Finding] = []

        def report(
            node: ast.AST,
            what: str,
            *,
            severity: Severity,
            confidence: Confidence,
            review: bool,
            material: str,
        ) -> None:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                # Anchor function-level findings to the signature, not the whole body.
                end_line = node.lineno
                end_col = node.col_offset + len("def ") + len(node.name) + 1
            else:
                end_line, end_col = node_end(node)
            findings.append(
                ctx.new_finding(
                    self,
                    line=int(getattr(node, "lineno", 1)),
                    column=int(getattr(node, "col_offset", 0)) + 1,
                    end_line=end_line,
                    end_column=end_col,
                    evidence=[
                        Evidence(
                            kind="tool",
                            description=what,
                            snippet=module.snippet(node),
                            line=int(getattr(node, "lineno", 1)),
                        )
                    ],
                    evidence_summary=what,
                    severity=severity,
                    confidence=confidence,
                    review_required=review,
                    analyzer="python_ast",
                    fingerprint_material=material,
                )
            )

        for call in dataflow.calls:
            node = call.node
            class_name = call.name.rsplit(".", 1)[-1]
            if class_name in DANGEROUS_TOOL_CLASSES:
                if (
                    class_name == "FileManagementToolkit"
                    and get_keyword(node, "root_dir") is not None
                ):
                    continue
                report(
                    node,
                    f"{class_name} {DANGEROUS_TOOL_CLASSES[class_name]}",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    review=False,
                    material=f"class:{class_name}",
                )
                continue
            if class_name == "load_tools" and node.args:
                first = node.args[0]
                if isinstance(first, ast.List | ast.Tuple):
                    names = [
                        e.value
                        for e in first.elts
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)
                    ]
                    bad = sorted(set(names) & DANGEROUS_LOAD_TOOLS)
                    if bad:
                        report(
                            node,
                            f"load_tools() includes dangerous tools: {', '.join(bad)}",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            review=False,
                            material=f"load_tools:{','.join(bad)}",
                        )
            for keyword in node.keywords:
                if keyword.arg in DANGEROUS_FLAGS and is_truthy_constant(keyword.value):
                    report(
                        node,
                        f"{keyword.arg}=True enables dangerous behaviour in {class_name}()",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        review=False,
                        material=f"flag:{keyword.arg}:{class_name}",
                    )
                if keyword.arg == "additional_authorized_imports" and _contains_star(keyword.value):
                    report(
                        node,
                        "additional_authorized_imports=['*'] allows any import in the code agent",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        review=False,
                        material=f"flag:authorized_imports:{class_name}",
                    )

        for info in dataflow.functions_with_role(FunctionRole.TOOL, FunctionRole.MCP_TOOL):
            text = f"{info.tool_name or ''}: {info.tool_description}"
            match = BROAD_DESCRIPTION.search(text)
            if match and info.node is not None:
                report(
                    info.node,
                    f"tool '{info.tool_name or info.name}' description advertises broad capability: \"{match.group(0).strip()}\"",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    review=True,
                    material=f"description:{info.name}",
                )
        return findings


def _contains_star(node: ast.AST) -> bool:
    return isinstance(node, ast.List | ast.Tuple | ast.Set) and any(
        isinstance(e, ast.Constant) and e.value == "*" for e in node.elts
    )
