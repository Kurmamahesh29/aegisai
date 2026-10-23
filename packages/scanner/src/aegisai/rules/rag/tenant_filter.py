"""RAG001: tenant/user filtering not evident in a multi-tenant retrieval path."""

from __future__ import annotations

import ast
import re

from aegisai.analyzers.dataflow import FunctionInfo, FunctionRole, _FunctionAnalyzer
from aegisai.analyzers.python_ast import node_end
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Evidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack

TENANT_IDENTIFIER = re.compile(
    r"(?i)(tenant|user_id|userid|org_id|organization|organisation|account_id|customer_id|"
    r"workspace|current_user|owner_id|group_id|team_id|principal)"
)
FILTER_KEYWORDS = {
    "filter",
    "filters",
    "where",
    "where_document",
    "namespace",
    "metadata_filter",
    "search_kwargs",
    "pre_filter",
    "filter_expr",
    "expr",
    "query_filter",
    "tenant",
    "partition",
    "partition_names",
    "tenant_id",
    "user_id",
    "collection_name",
    "index_name",
    "metadata",
    "doc_ids",
    "node_ids",
}


class MissingTenantFilterRule(Rule):
    metadata = RuleMetadata(
        rule_id="RAG001",
        name="Tenant filtering not evident in retrieval",
        version="1.0.0",
        description=(
            "A vector/document retrieval call runs inside a function that has a tenant, user, "
            "organization or account identifier in scope, but the call passes no filter, "
            "namespace, partition or search_kwargs argument and the identifier is not referenced "
            "in the call. Multi-tenant RAG systems must scope retrieval server-side; relying on "
            "the model or post-filtering leaks other tenants' documents into the context window."
        ),
        category=Category.RAG,
        pack=RulePack.RAG,
        default_severity=Severity.HIGH,
        default_confidence=Confidence.MEDIUM,
        confidence_behavior=(
            "Medium: the identifier in scope is strong evidence of multi-tenancy but the "
            "collection itself may already be tenant-scoped. Always review-required."
        ),
        artifact_types=[ArtifactType.PYTHON],
        impact="Cross-tenant data disclosure through retrieved context.",
        remediation=(
            "Pass a tenant/user filter (metadata filter, namespace, partition or per-tenant "
            "collection) to every retrieval call, derived from the authenticated principal."
        ),
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
            identifiers = _tenant_identifiers(info)
            if not identifiers:
                continue
            for call in info.calls:
                is_retrieval = _FunctionAnalyzer._is_retrieval_call(
                    call.name, call.tail, call.receiver
                )
                is_as_retriever = call.tail == "as_retriever"
                if not (is_retrieval or is_as_retriever):
                    continue
                node = call.node
                if any(k.arg in FILTER_KEYWORDS for k in node.keywords):
                    continue
                if _mentions(node, identifiers):
                    continue
                if is_as_retriever and not node.keywords:
                    pass
                end_line, end_col = node_end(node)
                ids = ", ".join(sorted(identifiers))
                findings.append(
                    ctx.new_finding(
                        self,
                        line=node.lineno,
                        column=node.col_offset + 1,
                        end_line=end_line,
                        end_column=end_col,
                        evidence=[
                            Evidence(
                                kind="retrieval",
                                description=f"retrieval call {call.name or call.tail}() without filter/namespace arguments",
                                snippet=module.snippet(node),
                                line=node.lineno,
                            ),
                            Evidence(
                                kind="context",
                                description=f"tenant/user identifier(s) in scope of {info.name}(): {ids}",
                                line=info.lineno,
                            ),
                        ],
                        evidence_summary=f"{call.name or call.tail}() in {info.name}() has no tenant filter although {ids} is in scope",
                        review_required=True,
                        analyzer="dataflow",
                        fingerprint_material=f"{info.name}:{module.snippet(node)}",
                    )
                )
        return findings


def _tenant_identifiers(info: FunctionInfo) -> set[str]:
    names: set[str] = set()
    for param in info.params:
        if TENANT_IDENTIFIER.search(param):
            names.add(param)
    node = info.node
    if node is not None:
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and TENANT_IDENTIFIER.search(child.id):
                names.add(child.id)
            elif isinstance(child, ast.Attribute) and TENANT_IDENTIFIER.search(child.attr):
                names.add(child.attr)
    return names


def _mentions(node: ast.AST, identifiers: set[str]) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in identifiers:
            return True
        if isinstance(child, ast.Attribute) and child.attr in identifiers:
            return True
        if (
            isinstance(child, ast.Constant)
            and isinstance(child.value, str)
            and TENANT_IDENTIFIER.search(child.value)
        ):
            return True
    return False
