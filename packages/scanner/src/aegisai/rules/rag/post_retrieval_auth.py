"""RAG002: authorization applied after retrieval instead of inside the query."""

from __future__ import annotations

import ast
import re

from aegisai.analyzers.dataflow import FunctionRole, _FunctionAnalyzer
from aegisai.analyzers.python_ast import attribute_tail, node_end, receiver_name
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Evidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack

AUTH_TERM = re.compile(
    r"(?i)(tenant|user_id|userid|owner|permission|has_access|can_view|can_read|allowed|authorized|"
    r"authorised|acl|role|org_id|organization|account_id|customer_id|group_id|visible_to|access_list)"
)


class AuthorizationAfterRetrievalRule(Rule):
    metadata = RuleMetadata(
        rule_id="RAG002",
        name="Authorization applied after retrieval",
        version="1.0.0",
        description=(
            "Documents are retrieved without a filter and then filtered in application code by "
            "tenant, owner or permission (list comprehension or if-statement over the results). "
            "Post-filtering wastes the top-k budget, leaks document existence through counts and "
            "timing, and silently fails when the filter condition does not match the metadata."
        ),
        category=Category.RAG,
        pack=RulePack.RAG,
        default_severity=Severity.MEDIUM,
        default_confidence=Confidence.MEDIUM,
        confidence_behavior="Medium: the pattern is syntactic; the store may not support pre-filtering.",
        artifact_types=[ArtifactType.PYTHON],
        impact="Unauthorized documents are loaded into memory and may leak via errors, logs or incomplete filtering.",
        remediation="Push the authorization predicate into the retrieval query (metadata filter, namespace or per-tenant index).",
        references=[
            "https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/",
            "https://cwe.mitre.org/data/definitions/285.html",
        ],
        cwe_ids=["CWE-285"],
        owasp_references=["OWASP Top 10 for LLM Applications 2025 LLM08"],
        heuristic=True,
        tags=["rag", "authorization"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        dataflow = ctx.dataflow
        module = ctx.python_module
        if dataflow is None or module is None:
            return []
        findings: list[Finding] = []
        for info in dataflow.functions:
            if info.role is FunctionRole.MODULE or info.node is None:
                continue
            result_names: set[str] = set()
            unfiltered_calls: dict[str, ast.Call] = {}
            for stmt in ast.walk(info.node):
                if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call | ast.Await):
                    call = stmt.value.value if isinstance(stmt.value, ast.Await) else stmt.value
                    if not isinstance(call, ast.Call):
                        continue
                    name = module.call_name(call) or ""
                    tail = attribute_tail(call.func) or ""
                    receiver = receiver_name(call.func)
                    if tail not in {"get", "fetch"} and _FunctionAnalyzer._is_retrieval_call(
                        name, tail, module.resolve(receiver) if receiver else None
                    ):
                        if any(
                            k.arg
                            in {
                                "filter",
                                "filters",
                                "where",
                                "namespace",
                                "search_kwargs",
                                "metadata_filter",
                                "pre_filter",
                            }
                            for k in call.keywords
                        ):
                            continue
                        for target in stmt.targets:
                            if isinstance(target, ast.Name):
                                result_names.add(target.id)
                                unfiltered_calls[target.id] = call
                elif (
                    isinstance(stmt, ast.For)
                    and isinstance(stmt.iter, ast.Name)
                    and stmt.iter.id in result_names
                    and isinstance(stmt.target, ast.Name)
                ):
                    result_names.add(stmt.target.id)
            if not result_names:
                continue
            for node in ast.walk(info.node):
                tests: list[ast.expr] = []
                iter_names: set[str] = set()
                if isinstance(node, ast.ListComp | ast.GeneratorExp | ast.SetComp):
                    for gen in node.generators:
                        if _references(gen.iter, result_names):
                            tests.extend(gen.ifs)
                            if isinstance(gen.target, ast.Name):
                                iter_names.add(gen.target.id)
                elif isinstance(node, ast.If):
                    tests.append(node.test)
                for test in tests:
                    if _references(test, result_names | iter_names) and _auth_identifier_in(test):
                        end_line, end_col = node_end(node)
                        node_line = int(getattr(node, "lineno", 1))
                        node_col = int(getattr(node, "col_offset", 0)) + 1
                        findings.append(
                            ctx.new_finding(
                                self,
                                line=node_line,
                                column=node_col,
                                end_line=end_line,
                                end_column=end_col,
                                evidence=[
                                    Evidence(
                                        kind="retrieval",
                                        description="unfiltered retrieval result",
                                        snippet=module.snippet(
                                            next(iter(unfiltered_calls.values()))
                                        ),
                                        line=next(iter(unfiltered_calls.values())).lineno,
                                    ),
                                    Evidence(
                                        kind="post_filter",
                                        description="authorization-like filtering applied to retrieved results",
                                        snippet=module.snippet(test),
                                        line=node_line,
                                    ),
                                ],
                                evidence_summary=f"results of unfiltered retrieval in {info.name}() are filtered by an authorization condition afterwards",
                                review_required=True,
                                analyzer="python_ast",
                                fingerprint_material=f"{info.name}:{module.snippet(test)}",
                            )
                        )
                        break
        return findings


def _references(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(child, ast.Name) and child.id in names for child in ast.walk(node))


def _auth_identifier_in(node: ast.AST) -> bool:
    """True when a variable or attribute *name* in the test looks authorization-related.

    String constants are ignored on purpose: ``"user_id" in payload`` is a key check, not an
    authorization comparison against the caller's identity.
    """
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and AUTH_TERM.search(child.id):
            return True
        if isinstance(child, ast.Attribute) and AUTH_TERM.search(child.attr):
            return True
    return False
