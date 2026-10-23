"""RAG004: potential sensitive document or embedding metadata exposure."""

from __future__ import annotations

import ast
import re

from aegisai.analyzers.dataflow import SinkKind, SourceKind
from aegisai.analyzers.python_ast import get_keyword, node_end
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Evidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack
from aegisai.rules.common import adjusted_confidence, finding_from_flow

SENSITIVE_METADATA_KEY = re.compile(
    r"(?i)^(ssn|social_security|national_id|passport|password|passwd|secret|api_key|token|"
    r"credit_card|card_number|cvv|iban|account_number|salary|dob|date_of_birth|birthdate|"
    r"email|phone|phone_number|address|home_address|medical|diagnosis|health|ethnicity|religion|"
    r"private_key|access_token)$"
)
INGEST_TAILS = {
    "add_texts",
    "add_documents",
    "aadd_documents",
    "aadd_texts",
    "upsert",
    "add",
    "insert",
    "from_documents",
    "from_texts",
    "upload_documents",
    "ingest",
}
DOCUMENT_CLASSES = {
    "Document",
    "TextNode",
    "Node",
    "langchain_core.documents.Document",
    "langchain.schema.Document",
}


class MetadataExposureRule(Rule):
    metadata = RuleMetadata(
        rule_id="RAG004",
        name="Potential sensitive metadata exposure",
        version="1.0.0",
        description=(
            "Either documents are ingested into a vector store with metadata keys that denote "
            "sensitive personal or secret data (which is then returned with every retrieval), or "
            "retrieved documents are returned in an HTTP response or written to logs without "
            "evidence of metadata scrubbing."
        ),
        category=Category.RAG,
        pack=RulePack.RAG,
        default_severity=Severity.MEDIUM,
        default_confidence=Confidence.MEDIUM,
        confidence_behavior=(
            "High when a literal metadata key is in the sensitive list; medium for retrieved "
            "documents returned from a route handler; low for logging of retrieved documents."
        ),
        artifact_types=[ArtifactType.PYTHON],
        impact="Personal data or secrets stored alongside embeddings leak to clients, logs or the model context.",
        remediation=(
            "Store only the metadata needed for filtering and citation; keep sensitive attributes "
            "in the system of record and return sanitised document views to clients."
        ),
        references=[
            "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
        cwe_ids=["CWE-200"],
        owasp_references=["OWASP Top 10 for LLM Applications 2025 LLM02"],
        heuristic=True,
        tags=["rag", "privacy"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        dataflow = ctx.dataflow
        module = ctx.python_module
        if dataflow is None or module is None:
            return []
        findings: list[Finding] = []

        for call in dataflow.calls:
            node = call.node
            class_name = call.name.rsplit(".", 1)[-1]
            if call.tail not in INGEST_TAILS and class_name not in DOCUMENT_CLASSES:
                continue
            metadata_node = (
                get_keyword(node, "metadata")
                or get_keyword(node, "metadatas")
                or get_keyword(node, "extra_info")
            )
            if metadata_node is None:
                continue
            keys = _sensitive_keys(metadata_node)
            if not keys:
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
                            kind="metadata",
                            description=f"sensitive metadata keys: {', '.join(keys)}",
                            snippet=module.snippet(node),
                            line=node.lineno,
                        )
                    ],
                    evidence_summary=f"{call.name or call.tail}() stores sensitive metadata keys: {', '.join(keys)}",
                    confidence=Confidence.HIGH,
                    title="Sensitive metadata stored with embeddings",
                    review_required=True,
                    analyzer="python_ast",
                    fingerprint_material=f"ingest:{call.tail}:{','.join(keys)}",
                )
            )

        for flow in dataflow.flows_matching(
            {SourceKind.RETRIEVED_CONTENT}, {SinkKind.HTTP_RESPONSE, SinkKind.LOGGING}
        ):
            if _narrowed_to_safe_fields(flow.source.via):
                # Only ids / scores / text were extracted from the result; metadata is not exposed.
                continue
            confidence, _ = adjusted_confidence(
                flow,
                Confidence.MEDIUM if flow.sink.kind is SinkKind.HTTP_RESPONSE else Confidence.LOW,
            )
            findings.append(
                finding_from_flow(
                    ctx,
                    self,
                    flow,
                    severity=Severity.MEDIUM
                    if flow.sink.kind is SinkKind.HTTP_RESPONSE
                    else Severity.LOW,
                    confidence=confidence,
                    review_required=True,
                    title="Retrieved documents returned to the client"
                    if flow.sink.kind is SinkKind.HTTP_RESPONSE
                    else "Retrieved documents written to logs",
                )
            )
        return findings


SAFE_RESULT_FIELDS = {
    "ids",
    "id",
    "score",
    "scores",
    "distances",
    "distance",
    "similarity",
    "page_content",
    "text",
    "content",
    "n_results",
    "count",
    "total",
    "embeddings",
}


def _narrowed_to_safe_fields(via: tuple[str, ...]) -> bool:
    """True when the taint path only accessed non-metadata fields of the retrieval result."""
    keys = [step[1:] for step in via if step.startswith(".")]
    return bool(keys) and all(key in SAFE_RESULT_FIELDS for key in keys)


def _sensitive_keys(node: ast.AST) -> list[str]:
    keys: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Dict):
            for key in child.keys:
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and SENSITIVE_METADATA_KEY.match(key.value)
                ):
                    keys.append(key.value)
    return sorted(set(keys))
