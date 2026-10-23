"""MCP005: risky network binding or transport configuration."""

from __future__ import annotations

import ast
import re

from aegisai.analyzers.configuration import find_mcp_servers, locate_key
from aegisai.analyzers.javascript import find_network_binds, imports_mcp_sdk
from aegisai.analyzers.python_ast import constant_value, dotted_name, get_keyword, node_end
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Evidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack
from aegisai.rules.mcp.authorization import server_has_auth

ALL_INTERFACES = {"0.0.0.0", "::", "[::]"}  # noqa: S104 - detection target
LOCAL_HOSTS = re.compile(
    r"(?i)^(localhost|127\.0\.0\.1|\[::1\]|::1|0\.0\.0\.0|host\.docker\.internal)$"
)
NETWORK_TRANSPORTS = {"sse", "streamable-http", "http", "streamable_http"}


class MCPTransportRule(Rule):
    metadata = RuleMetadata(
        rule_id="MCP005",
        name="Risky MCP network binding or transport",
        version="1.0.0",
        description=(
            "An MCP server binds a network transport to all interfaces (0.0.0.0 / ::), runs a "
            "network transport without recognised authentication, or a client configuration "
            "connects to a remote MCP server over cleartext HTTP. Network-exposed MCP servers are "
            "reachable by other hosts and browsers (DNS rebinding) unless bound to loopback and "
            "authenticated."
        ),
        category=Category.MCP,
        pack=RulePack.MCP,
        default_severity=Severity.MEDIUM,
        default_confidence=Confidence.HIGH,
        confidence_behavior=(
            "High for literal 0.0.0.0 bindings and cleartext remote URLs; medium for a network "
            "transport without a recognised auth marker (review required)."
        ),
        artifact_types=[
            ArtifactType.PYTHON,
            ArtifactType.JSON,
            ArtifactType.YAML,
            ArtifactType.JAVASCRIPT,
            ArtifactType.TYPESCRIPT,
        ],
        impact="Unauthenticated remote invocation of MCP tools; credential interception over cleartext.",
        remediation=(
            "Bind to 127.0.0.1 unless remote access is required, require authentication on SSE/HTTP "
            "transports, validate Origin headers, and use HTTPS for remote servers."
        ),
        references=[
            "https://modelcontextprotocol.io/specification/2025-06-18/basic/transports",
            "https://cwe.mitre.org/data/definitions/1327.html",
        ],
        cwe_ids=["CWE-1327", "CWE-319"],
        owasp_references=["OWASP Top 10 for LLM Applications 2025 LLM06"],
        tags=["mcp", "transport"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        if ctx.artifact_type is ArtifactType.PYTHON:
            return self._check_python(ctx)
        if ctx.artifact_type in (ArtifactType.JAVASCRIPT, ArtifactType.TYPESCRIPT):
            return self._check_javascript(ctx)
        return self._check_config(ctx)

    def _check_python(self, ctx: FileContext) -> list[Finding]:
        dataflow = ctx.dataflow
        module = ctx.python_module
        if (
            dataflow is None
            or module is None
            or not (dataflow.mcp_instances or ctx.has_framework())
        ):
            return []
        if not any(imp == "mcp" or imp.startswith(("mcp.", "fastmcp")) for imp in module.imports):
            return []
        findings: list[Finding] = []
        has_auth = server_has_auth(ctx)
        for call in dataflow.calls:
            node = call.node
            host = constant_value(get_keyword(node, "host"))
            transport = constant_value(get_keyword(node, "transport"))
            if transport is None and call.tail == "run" and node.args:
                transport = constant_value(node.args[0])
            if (
                isinstance(host, str)
                and host in ALL_INTERFACES
                and (
                    call.tail in {"run", "FastMCP", "Server", "run_async"}
                    or call.name == "uvicorn.run"
                )
            ):
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
                                kind="binding",
                                description=f"host={host!r} binds all interfaces",
                                snippet=module.snippet(node),
                                line=node.lineno,
                            )
                        ],
                        evidence_summary=f"{call.name or call.tail}() binds MCP transport to {host}",
                        severity=Severity.HIGH if not has_auth else Severity.MEDIUM,
                        title="MCP server bound to all network interfaces",
                        analyzer="python_ast",
                        fingerprint_material=f"bind:{host}:{module.snippet(node)}",
                    )
                )
            elif (
                isinstance(transport, str)
                and transport.lower() in NETWORK_TRANSPORTS
                and not has_auth
            ):
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
                                kind="transport",
                                description=f"transport={transport!r} without a recognised authentication provider",
                                snippet=module.snippet(node),
                                line=node.lineno,
                            )
                        ],
                        evidence_summary=f"{call.name or call.tail}(transport={transport!r}) without recognised authentication",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        title=f"MCP {transport} transport without recognised authentication",
                        review_required=True,
                        analyzer="python_ast",
                        fingerprint_material=f"transport:{transport}:{module.snippet(node)}",
                    )
                )
        for stmt in module.tree.body:
            # mcp.settings.host = "0.0.0.0"
            if isinstance(stmt, ast.Assign):
                value = stmt.value
                for target in stmt.targets:
                    name = dotted_name(target)
                    if (
                        name.endswith(".host")
                        and isinstance(constant_value(value), str)
                        and constant_value(value) in ALL_INTERFACES
                    ):
                        findings.append(
                            ctx.new_finding(
                                self,
                                line=stmt.lineno,
                                column=stmt.col_offset + 1,
                                evidence=[
                                    Evidence(
                                        kind="binding",
                                        description=f"{name} = {constant_value(value)!r}",
                                        snippet=module.snippet(stmt),
                                        line=stmt.lineno,
                                    )
                                ],
                                evidence_summary=f"{name} set to {constant_value(value)}",
                                severity=Severity.HIGH if not has_auth else Severity.MEDIUM,
                                title="MCP server bound to all network interfaces",
                                analyzer="python_ast",
                                fingerprint_material=f"bind:{name}",
                            )
                        )
        return findings

    def _check_javascript(self, ctx: FileContext) -> list[Finding]:
        if not imports_mcp_sdk(ctx.text):
            return []
        findings: list[Finding] = []
        for line, column, snippet in find_network_binds(ctx.text):
            findings.append(
                ctx.new_finding(
                    self,
                    line=line,
                    column=column,
                    evidence=[
                        Evidence(
                            kind="binding",
                            description="server bound to 0.0.0.0 in an MCP SDK module",
                            snippet=snippet,
                            line=line,
                            column=column,
                        )
                    ],
                    evidence_summary="MCP server module binds to 0.0.0.0",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    title="MCP server bound to all network interfaces (heuristic)",
                    review_required=True,
                    analyzer="javascript_heuristics",
                    fingerprint_material=f"js-bind:{snippet}",
                )
            )
        return findings

    def _check_config(self, ctx: FileContext) -> list[Finding]:
        servers = find_mcp_servers(ctx.structured)
        if not servers:
            return []
        findings: list[Finding] = []
        for server, config in servers.items():
            server_line, _ = locate_key(ctx.text, server)
            for url_key in ("url", "serverUrl", "endpoint", "uri"):
                url = config.get(url_key)
                if not isinstance(url, str) or not url.lower().startswith("http://"):
                    continue
                host = re.sub(r"^http://", "", url, flags=re.IGNORECASE).split("/")[0].split(":")[0]
                if LOCAL_HOSTS.match(host):
                    continue
                line, column = locate_key(ctx.text, url_key, after_line=server_line)
                findings.append(
                    ctx.new_finding(
                        self,
                        line=line,
                        column=column,
                        evidence=[
                            Evidence(
                                kind="config_key",
                                description=f"cleartext MCP endpoint {url_key}",
                                snippet=ctx.line(line).strip()[:200],
                                line=line,
                                column=column,
                            )
                        ],
                        evidence_summary=f"server '{server}' connects over cleartext http:// to {host}",
                        severity=Severity.MEDIUM,
                        title="Remote MCP server configured over cleartext HTTP",
                        analyzer="configuration",
                        fingerprint_material=f"{server}:{url_key}:cleartext",
                    )
                )
        return findings
