"""LLM003: sensitive values embedded in prompts or sent to model APIs."""

from __future__ import annotations

from aegisai.analyzers.dataflow import SinkKind, SourceKind
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack
from aegisai.rules.common import adjusted_confidence, finding_from_flow


class SecretsInPromptsRule(Rule):
    metadata = RuleMetadata(
        rule_id="LLM003",
        name="Secret value embedded in a prompt",
        version="1.1.0",
        description=(
            "A credential (from the environment, a secrets manager, or a variable whose name "
            "indicates a secret) is interpolated into prompt text, a message object, or passed as "
            "prompt input to a model API. Prompts are transmitted to the provider, retained in "
            "traces, and can be exfiltrated through prompt injection."
        ),
        category=Category.LLM,
        pack=RulePack.LLM,
        default_severity=Severity.HIGH,
        default_confidence=Confidence.HIGH,
        confidence_behavior=(
            "High when the value comes from an explicit secret source; medium when only the "
            "variable name indicates a secret. Passing an api_key= keyword to a client constructor "
            "is not reported."
        ),
        artifact_types=[ArtifactType.PYTHON],
        impact="Credentials leak to the model provider, observability tooling and any user who can elicit the system prompt.",
        remediation=(
            "Keep secrets out of prompts. Give tools access to credentials server-side and pass "
            "only opaque identifiers through the model."
        ),
        references=[
            "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
        cwe_ids=["CWE-200"],
        owasp_references=["OWASP Top 10 for LLM Applications 2025 LLM02"],
        tags=["llm", "secrets"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        dataflow = ctx.dataflow
        if dataflow is None:
            return []
        findings: list[Finding] = []
        for flow in dataflow.flows_matching({SourceKind.SECRET_VALUE}, {SinkKind.PROMPT}):
            if flow.sink.argument in {"api_key", "key", "token", "auth", "credentials"}:
                # Authentication parameters of client objects are expected to carry secrets.
                continue
            confidence, review = adjusted_confidence(flow, Confidence.HIGH)
            findings.append(
                finding_from_flow(
                    ctx,
                    self,
                    flow,
                    severity=Severity.HIGH if not flow.source.name_based else Severity.MEDIUM,
                    confidence=confidence,
                    review_required=review,
                )
            )
        return findings
