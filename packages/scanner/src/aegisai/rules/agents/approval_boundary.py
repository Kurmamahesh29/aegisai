"""AGT002: high-impact tools without a recognised authorization or approval boundary."""

from __future__ import annotations

from aegisai.analyzers.dataflow import FunctionRole, function_is_high_impact
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Evidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack


class MissingApprovalBoundaryRule(Rule):
    metadata = RuleMetadata(
        rule_id="AGT002",
        name="High-impact tool lacks a recognised approval boundary",
        version="1.0.0",
        description=(
            "A tool exposed to an agent performs a high-impact action (command execution, SQL, "
            "file or network side effects, or a destructive operation suggested by its name), "
            "and neither the tool body, its decorators, nor the module show a recognised "
            "authorization or human-approval mechanism. This is a heuristic: a custom "
            "authorization helper may not be recognised."
        ),
        category=Category.AGENTS,
        pack=RulePack.AGENTS,
        default_severity=Severity.MEDIUM,
        default_confidence=Confidence.LOW,
        confidence_behavior=(
            "Medium when the tool body contains a dangerous sink; low when only the tool name or "
            "description suggests a destructive action. Always marked review-required."
        ),
        artifact_types=[ArtifactType.PYTHON],
        impact="The model can trigger irreversible actions without a human or policy check.",
        remediation=(
            "Gate high-impact tools behind an explicit approval step (framework interrupts, "
            "confirmation callbacks, policy checks) and enforce authorization server-side."
        ),
        references=[
            "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
            "https://cwe.mitre.org/data/definitions/862.html",
        ],
        cwe_ids=["CWE-862"],
        owasp_references=["OWASP Top 10 for LLM Applications 2025 LLM06"],
        heuristic=True,
        tags=["agents", "authorization"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        dataflow = ctx.dataflow
        if dataflow is None:
            return []
        if dataflow.module_markers:
            return []
        findings: list[Finding] = []
        for info in dataflow.functions_with_role(FunctionRole.TOOL):
            high_impact, reason = function_is_high_impact(info)
            if not high_impact:
                continue
            if info.approval_guards or info.auth_guards:
                continue
            sink_based = reason.startswith("performs") or reason.startswith("calls")
            node = info.node
            assert node is not None
            findings.append(
                ctx.new_finding(
                    self,
                    line=node.lineno,
                    column=node.col_offset + 1,
                    end_line=node.lineno,
                    end_column=node.col_offset + len("def ") + len(node.name) + 1,
                    evidence=[
                        Evidence(
                            kind="tool",
                            description=f"tool '{info.tool_name or info.name}' {reason}",
                            line=node.lineno,
                        ),
                        Evidence(
                            kind="missing",
                            description="no approval/authorization call, decorator or module-level marker recognised",
                            line=node.lineno,
                        ),
                    ],
                    evidence_summary=f"tool '{info.tool_name or info.name}' {reason} without a recognised approval boundary",
                    severity=Severity.MEDIUM if sink_based else Severity.LOW,
                    confidence=Confidence.MEDIUM if sink_based else Confidence.LOW,
                    review_required=True,
                    analyzer="dataflow",
                    fingerprint_material=f"tool:{info.name}:{reason}",
                )
            )
        return findings
