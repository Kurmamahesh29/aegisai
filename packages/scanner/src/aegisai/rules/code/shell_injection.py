"""SEC003: untrusted input reaches shell or subprocess execution."""

from __future__ import annotations

import ast

from aegisai.analyzers.dataflow import SANITIZER_NAMES, SinkKind, SourceKind
from aegisai.analyzers.python_ast import get_keyword, is_dynamic, is_truthy_constant, node_end
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Evidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack
from aegisai.rules.common import adjusted_confidence, finding_from_flow, has_strong_guard


class ShellInjectionRule(Rule):
    metadata = RuleMetadata(
        rule_id="SEC003",
        name="Untrusted input reaches shell execution",
        version="1.0.0",
        description=(
            "User-controlled data (HTTP request data, stdin, CLI input) flows into a subprocess "
            "or shell execution call. With shell=True or string commands this allows command "
            "injection; with argument lists it can still inject arguments."
        ),
        category=Category.CODE,
        pack=RulePack.CODE,
        default_severity=Severity.HIGH,
        default_confidence=Confidence.HIGH,
        confidence_behavior=(
            "High for a direct taint path. Medium when a validation-looking check references the "
            "value. A shell=True call with a dynamic but untainted command is reported as a "
            "low-confidence potential issue."
        ),
        artifact_types=[ArtifactType.PYTHON],
        impact="Remote command execution on the host running the application.",
        remediation=(
            "Never pass untrusted input to a shell. Use argument lists without shell=True, validate "
            "against a strict allow-list, and prefer library APIs over spawning processes."
        ),
        references=[
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://owasp.org/Top10/A03_2021-Injection/",
        ],
        cwe_ids=["CWE-78"],
        owasp_references=["OWASP Top 10 2021 A03"],
        tags=["injection"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        dataflow = ctx.dataflow
        if dataflow is None:
            return []
        findings: list[Finding] = []
        # Any taint flow into a shell sink is reported by a specific rule; skip the generic check.
        reported_lines: set[int] = {
            f.sink.line for f in dataflow.flows if f.sink.kind is SinkKind.SHELL_EXEC
        }
        for flow in dataflow.flows_matching({SourceKind.USER_INPUT}, {SinkKind.SHELL_EXEC}):
            if has_strong_guard(flow):
                continue
            confidence, review = adjusted_confidence(flow, Confidence.HIGH)
            severity = (
                Severity.CRITICAL
                if flow.sink.shell
                or flow.sink.arg_form in {"string", "string_concat", "list_first"}
                else Severity.HIGH
            )
            if flow.sink.arg_form == "list_other" and not flow.sink.shell:
                severity = Severity.MEDIUM
            reported_lines.add(flow.sink.line)
            findings.append(
                finding_from_flow(
                    ctx,
                    self,
                    flow,
                    severity=severity,
                    confidence=confidence,
                    review_required=review,
                    title="Untrusted input reaches shell execution"
                    if flow.sink.shell
                    else "Untrusted input reaches subprocess execution",
                )
            )
        # Potential: shell=True with a dynamic command and no recognised taint.
        for call in dataflow.calls:
            if call.name not in {
                "subprocess.run",
                "subprocess.call",
                "subprocess.check_call",
                "subprocess.check_output",
                "subprocess.Popen",
            }:
                continue
            node = call.node
            if node.lineno in reported_lines or not is_truthy_constant(get_keyword(node, "shell")):
                continue
            command = node.args[0] if node.args else get_keyword(node, "args")
            if command is None or not is_dynamic(command) or _uses_sanitizer(command, ctx):
                continue
            end_line, end_col = node_end(node)
            findings.append(
                ctx.new_finding(
                    self,
                    line=node.lineno,
                    column=node.col_offset + 1,
                    end_line=end_line,
                    end_column=end_col,
                    evidence=[
                        Evidence(
                            kind="sink",
                            description="shell=True with a dynamically built command",
                            snippet=ctx.python_module.snippet(node) if ctx.python_module else None,
                            line=node.lineno,
                        )
                    ],
                    evidence_summary=f"shell=True with dynamic command in {call.function.name}()",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    title="Potential command injection: shell=True with dynamic command",
                    review_required=True,
                    analyzer="python_ast",
                )
            )
        return findings


def _uses_sanitizer(command: ast.AST, ctx: FileContext) -> bool:
    """True when the command expression wraps values in a recognised sanitizer (e.g. shlex.quote)."""
    module = ctx.python_module
    if module is None:
        return False
    for node in ast.walk(command):
        if isinstance(node, ast.Call):
            name = module.call_name(node) or ""
            if name in SANITIZER_NAMES or name.rsplit(".", 1)[-1] in {"quote", "escape"}:
                return True
    return False
