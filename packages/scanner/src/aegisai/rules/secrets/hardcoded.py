"""SEC001: potential hard-coded credentials (built-in detector; Gitleaks adds coverage)."""

from __future__ import annotations

from aegisai.analyzers.configuration import MCP_CONFIG_FILENAMES, find_mcp_servers
from aegisai.analyzers.secrets import scan_text_for_secrets
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Evidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack
from aegisai.utils.redaction import mask_value, redact_known_value


class HardcodedCredentialsRule(Rule):
    metadata = RuleMetadata(
        rule_id="SEC001",
        name="Potential hard-coded credential",
        version="1.0.0",
        description=(
            "A string literal that looks like an API key, token, password or private key is "
            "embedded in source or configuration. Hard-coded secrets leak through version "
            "control, build artifacts and logs, and cannot be rotated without a code change."
        ),
        category=Category.SECRETS,
        pack=RulePack.SECRETS,
        default_severity=Severity.HIGH,
        default_confidence=Confidence.MEDIUM,
        confidence_behavior=(
            "High when the value matches a known provider token format (e.g. OpenAI, AWS, GitHub) "
            "or has high entropy; medium for generic key=value assignments. Placeholders and "
            "environment references are ignored."
        ),
        artifact_types=[
            ArtifactType.PYTHON,
            ArtifactType.JAVASCRIPT,
            ArtifactType.TYPESCRIPT,
            ArtifactType.JSON,
            ArtifactType.YAML,
            ArtifactType.TOML,
            ArtifactType.ENV,
            ArtifactType.TEXT,
            ArtifactType.MANIFEST,
        ],
        impact="Anyone with read access to the repository or artifact can use the credential.",
        remediation=(
            "Move the secret to an environment variable or a secrets manager, rotate the exposed "
            "value, and add the file pattern to your secret-scanning pre-commit hook."
        ),
        references=[
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        ],
        cwe_ids=["CWE-798"],
        owasp_references=["OWASP Top 10 2021 A07"],
        tags=["secrets"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        if (
            ctx.path.name in MCP_CONFIG_FILENAMES
            and ctx.structured is not None
            and find_mcp_servers(ctx.structured)
        ):
            # MCP003 reports secrets inside MCP server configuration with MCP-specific guidance.
            return []
        if ctx.path.name.endswith((".example", ".sample", ".template")):
            return []
        findings: list[Finding] = []
        unquoted = ctx.artifact_type in (ArtifactType.ENV, ArtifactType.YAML)
        for match in scan_text_for_secrets(ctx.text, allow_unquoted=unquoted):
            line_text = ctx.line(match.line)
            redacted_line = redact_known_value(line_text.strip(), match.value)
            masked = mask_value(match.value)
            label = match.key or match.detector
            findings.append(
                ctx.new_finding(
                    self,
                    line=match.line,
                    column=match.column,
                    end_line=match.line,
                    end_column=match.end_column,
                    evidence=[
                        Evidence(
                            kind="line",
                            description=f"detector: {match.detector}",
                            snippet=redacted_line,
                            line=match.line,
                            column=match.column,
                        ),
                        Evidence(
                            kind="value",
                            description=f"redacted value for '{label}'",
                            snippet=masked,
                            line=match.line,
                        ),
                    ],
                    evidence_summary=f"{label} = {masked}",
                    confidence={"high": Confidence.HIGH, "low": Confidence.LOW}.get(
                        match.confidence, Confidence.MEDIUM
                    ),
                    severity=Severity.LOW if match.confidence == "low" else None,
                    title=f"Potential hard-coded credential ({label})",
                    analyzer="secrets",
                    fingerprint_material=f"{label}:{masked}",
                    review_required=match.confidence != "high",
                )
            )
        return findings
