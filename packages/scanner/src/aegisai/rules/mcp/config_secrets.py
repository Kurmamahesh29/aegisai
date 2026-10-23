"""MCP003: secrets or credentials exposed in MCP configuration."""

from __future__ import annotations

import re

from aegisai.analyzers.configuration import find_mcp_servers, locate_key, locate_value
from aegisai.analyzers.dataflow import is_secret_name
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Evidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack
from aegisai.utils.redaction import KNOWN_TOKEN_PATTERNS, is_placeholder, mask_value

_URL_SECRET = re.compile(r"(?i)[?&](api[_-]?key|token|access_token|key|secret|password)=([^&\s]+)")
_URL_USERINFO = re.compile(r"(?i)^[a-z][a-z0-9+.\-]*://([^:/\s@]+):([^@/\s]+)@")


class MCPConfigSecretsRule(Rule):
    metadata = RuleMetadata(
        rule_id="MCP003",
        name="Secret exposed in MCP configuration",
        version="1.0.0",
        description=(
            "An MCP server definition contains a literal credential: an environment variable "
            "value that looks like a secret, an Authorization header, or a URL with embedded "
            "credentials. MCP configuration files are frequently committed, synced between "
            "machines and readable by every local process."
        ),
        category=Category.MCP,
        pack=RulePack.MCP,
        default_severity=Severity.HIGH,
        default_confidence=Confidence.HIGH,
        confidence_behavior=(
            "High when the value matches a known token format or sits in an Authorization header "
            "or URL; medium when only the key name indicates a secret. Placeholders and ${VAR} "
            "references are ignored."
        ),
        artifact_types=[ArtifactType.JSON, ArtifactType.YAML],
        impact="Credentials are exposed to anyone with access to the config file or repository.",
        remediation=(
            "Reference secrets through environment variables or the client's secret store "
            "(e.g. ${VAR} / input variables) and rotate the exposed credential."
        ),
        references=[
            "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        cwe_ids=["CWE-798"],
        owasp_references=["OWASP Top 10 2021 A07"],
        tags=["mcp", "secrets"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        servers = find_mcp_servers(ctx.structured)
        if not servers:
            return []
        findings: list[Finding] = []

        def report(
            server: str, key: str, value: str, what: str, confidence: Confidence, after_line: int
        ) -> None:
            located = locate_value(ctx.text, value, after_line=after_line)
            if located is None:
                located = locate_key(ctx.text, key, after_line=after_line)
            line, column = located
            masked = mask_value(value)
            findings.append(
                ctx.new_finding(
                    self,
                    line=line,
                    column=column,
                    end_line=line,
                    end_column=column + len(value),
                    evidence=[
                        Evidence(
                            kind="config_key",
                            description=what,
                            snippet=ctx.line(line).strip().replace(value, masked)[:200],
                            line=line,
                            column=column,
                        ),
                        Evidence(
                            kind="value", description="redacted value", snippet=masked, line=line
                        ),
                    ],
                    evidence_summary=f"server '{server}': {what} ({key} = {masked})",
                    confidence=confidence,
                    title=f"Secret in MCP configuration: {what}",
                    analyzer="configuration",
                    fingerprint_material=f"{server}:{key}:{masked}",
                    review_required=confidence is not Confidence.HIGH,
                )
            )

        for server, config in servers.items():
            server_line, _ = locate_key(ctx.text, server)
            env = config.get("env") or {}
            if isinstance(env, dict):
                for key, value in env.items():
                    if not isinstance(value, str) or is_placeholder(value) or len(value) < 8:
                        continue
                    known = _known_token(value)
                    if known:
                        report(
                            server,
                            str(key),
                            value,
                            f"{known} token in env.{key}",
                            Confidence.HIGH,
                            server_line,
                        )
                    elif is_secret_name(str(key)):
                        report(
                            server,
                            str(key),
                            value,
                            f"literal secret in env.{key}",
                            Confidence.MEDIUM,
                            server_line,
                        )
            headers = config.get("headers") or {}
            if isinstance(headers, dict):
                for key, value in headers.items():
                    if not isinstance(value, str) or is_placeholder(value):
                        continue
                    if str(key).lower() in {
                        "authorization",
                        "x-api-key",
                        "api-key",
                        "x-auth-token",
                        "proxy-authorization",
                    } or is_secret_name(str(key)):
                        token = value.split(" ", 1)[1] if " " in value else value
                        if is_placeholder(token) or len(token) < 8:
                            continue
                        report(
                            server,
                            str(key),
                            token,
                            f"credential in header {key}",
                            Confidence.HIGH,
                            server_line,
                        )
            for url_key in ("url", "serverUrl", "endpoint", "uri"):
                url = config.get(url_key)
                if not isinstance(url, str):
                    continue
                userinfo = _URL_USERINFO.match(url)
                if userinfo and not is_placeholder(userinfo.group(2)):
                    report(
                        server,
                        url_key,
                        userinfo.group(2),
                        f"credentials embedded in {url_key}",
                        Confidence.HIGH,
                        server_line,
                    )
                for match in _URL_SECRET.finditer(url):
                    if not is_placeholder(match.group(2)):
                        report(
                            server,
                            url_key,
                            match.group(2),
                            f"{match.group(1)} passed in {url_key} query string",
                            Confidence.HIGH,
                            server_line,
                        )
        return findings


def _known_token(value: str) -> str | None:
    for name, pattern in KNOWN_TOKEN_PATTERNS:
        if name in {"bearer", "url_credentials", "jwt"}:
            continue
        if pattern.search(value):
            return name
    return None
