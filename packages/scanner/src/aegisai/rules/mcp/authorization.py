"""MCP004: potential missing authorization at a sensitive MCP tool boundary."""

from __future__ import annotations

import re

from aegisai.analyzers.dataflow import FunctionRole, function_is_high_impact
from aegisai.analyzers.python_ast import constant_value, get_keyword
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Evidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack

SERVER_AUTH_MARKER = re.compile(
    r"(?i)(TokenVerifier|AuthSettings|BearerAuthProvider|JWTVerifier|OAuthProvider|"
    r"OAuthAuthorizationServerProvider|require_auth|get_access_token|AuthMiddleware|"
    r"RemoteAuthProvider|StaticTokenVerifier|IntrospectionTokenVerifier|verify_token|"
    r"authenticate|AuthProvider|auth_provider)"
)
NETWORK_TRANSPORTS = {"sse", "streamable-http", "http", "streamable_http"}


def server_has_auth(ctx: FileContext) -> bool:
    """Recognise server-level authentication from code structure (not comments or strings)."""
    dataflow = ctx.dataflow
    module = ctx.python_module
    if dataflow is None or module is None:
        return False
    for imported in module.imports:
        if ".auth" in imported or imported.endswith("auth") or SERVER_AUTH_MARKER.search(imported):
            return True
    for call in dataflow.calls:
        if SERVER_AUTH_MARKER.search(call.name) or SERVER_AUTH_MARKER.search(call.tail):
            return True
        for keyword in call.node.keywords:
            if keyword.arg in {
                "auth",
                "auth_provider",
                "token_verifier",
                "auth_server_provider",
                "authenticator",
            }:
                return True
    return any(SERVER_AUTH_MARKER.search(d) for info in dataflow.functions for d in info.decorators)


class MCPMissingAuthorizationRule(Rule):
    metadata = RuleMetadata(
        rule_id="MCP004",
        name="Potential missing authorization at MCP tool boundary",
        version="1.0.0",
        description=(
            "An MCP tool performs a high-impact action (execution, SQL, filesystem, network or a "
            "destructive operation) and neither the tool body nor the server setup shows a "
            "recognised authorization mechanism (auth provider, token verifier, per-request "
            "principal checks). Over stdio the host process is the trust boundary, so the finding "
            "is reported at low severity; over network transports it is reported at medium."
        ),
        category=Category.MCP,
        pack=RulePack.MCP,
        default_severity=Severity.MEDIUM,
        default_confidence=Confidence.LOW,
        confidence_behavior=(
            "Low: authorization helpers are recognised by naming convention only, so a custom "
            "mechanism may be missed. Always review-required."
        ),
        artifact_types=[ArtifactType.PYTHON],
        impact="Any client able to reach the server can invoke sensitive tools as the server's identity.",
        remediation=(
            "Configure server-level authentication (OAuth/bearer token verification) for network "
            "transports and enforce per-tool authorization against the authenticated principal."
        ),
        references=[
            "https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization",
            "https://cwe.mitre.org/data/definitions/862.html",
        ],
        cwe_ids=["CWE-862"],
        owasp_references=["OWASP Top 10 for LLM Applications 2025 LLM06"],
        heuristic=True,
        tags=["mcp", "authorization"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        dataflow = ctx.dataflow
        if dataflow is None:
            return []
        if server_has_auth(ctx):
            return []
        network = _uses_network_transport(ctx)
        findings: list[Finding] = []
        for info in dataflow.functions_with_role(
            FunctionRole.MCP_TOOL, FunctionRole.MCP_CALL_TOOL_HANDLER
        ):
            high_impact, reason = function_is_high_impact(info)
            if not high_impact or info.auth_guards or info.approval_guards:
                continue
            node = info.node
            assert node is not None
            name = info.tool_name or info.name
            findings.append(
                ctx.new_finding(
                    self,
                    line=node.lineno,
                    column=node.col_offset + 1,
                    end_line=node.lineno,
                    end_column=node.col_offset + len("def ") + len(node.name) + 1,
                    evidence=[
                        Evidence(
                            kind="tool", description=f"MCP tool '{name}' {reason}", line=node.lineno
                        ),
                        Evidence(
                            kind="missing",
                            description="no authorization call, decorator or server auth configuration recognised",
                            line=node.lineno,
                        ),
                        Evidence(
                            kind="transport",
                            description="network transport configured"
                            if network
                            else "stdio transport (host is the trust boundary)",
                            line=node.lineno,
                        ),
                    ],
                    evidence_summary=f"MCP tool '{name}' {reason} without recognised authorization"
                    + (" over a network transport" if network else " (stdio)"),
                    severity=Severity.MEDIUM if network else Severity.LOW,
                    confidence=Confidence.LOW,
                    review_required=True,
                    analyzer="dataflow",
                    fingerprint_material=f"tool:{name}:{reason}",
                )
            )
        return findings


def _uses_network_transport(ctx: FileContext) -> bool:
    dataflow = ctx.dataflow
    if dataflow is None:
        return False
    for call in dataflow.calls:
        if call.tail in {"run", "run_async", "serve"}:
            transport = constant_value(get_keyword(call.node, "transport"))
            if transport is None and call.node.args:
                transport = constant_value(call.node.args[0])
            if isinstance(transport, str) and transport.lower() in NETWORK_TRANSPORTS:
                return True
        if call.tail in {"sse_app", "streamable_http_app", "http_app"}:
            return True
        if call.name in {"uvicorn.run"}:
            return True
    return False
