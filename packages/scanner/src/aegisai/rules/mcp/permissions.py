"""MCP002: overly broad tool permissions or unsafe execution configuration."""

from __future__ import annotations

import re
from typing import Any

from aegisai.analyzers.configuration import find_mcp_servers, locate_key
from aegisai.analyzers.dataflow import FunctionRole, SinkKind
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Evidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack

SHELL_COMMANDS = {
    "bash",
    "sh",
    "zsh",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
}
DANGEROUS_ARGS = {
    "--dangerously-skip-permissions",
    "--yolo",
    "--allow-all",
    "--no-sandbox",
    "--unrestricted",
    "--trust-all",
    "--auto-approve",
    "--disable-sandbox",
    "--allow-dangerous",
}
ROOT_PATHS = re.compile(r"^(?:/|~|\$HOME|%USERPROFILE%|[A-Za-z]:\\?|/home/?|/Users/?|/root/?)$")
FILESYSTEM_SERVER = re.compile(r"server-filesystem|mcp-filesystem|filesystem")
AUTO_APPROVE_KEYS = {
    "autoApprove",
    "auto_approve",
    "alwaysAllow",
    "always_allow",
    "alwaysAllowTools",
    "trust",
    "autoAccept",
    "allowedTools",
}
DESTRUCTIVE_TOOL = re.compile(
    r"(?i)(delete|remove|write|exec|execute|run|shell|command|rm|drop|destroy|send|deploy|install|terminal|bash)"
)
EXEC_TOOL_NAME = re.compile(
    r"(?i)(run_command|execute_command|run_shell|shell|bash|exec$|execute$|run_python|eval|execute_sql|run_sql|execute_code|run_script|terminal|powershell|^cmd$|run_cmd)"
)


class MCPBroadPermissionsRule(Rule):
    metadata = RuleMetadata(
        rule_id="MCP002",
        name="Overly broad MCP permissions or unsafe execution configuration",
        version="1.0.0",
        description=(
            "An MCP server exposes a generic command/code execution tool, or an MCP client "
            "configuration grants broad trust: shell wrappers as server commands, dangerous "
            "flags, filesystem servers rooted at '/' or the home directory, or auto-approval of "
            "all/destructive tools."
        ),
        category=Category.MCP,
        pack=RulePack.MCP,
        default_severity=Severity.HIGH,
        default_confidence=Confidence.HIGH,
        confidence_behavior="High: matched on literal configuration values or tool names combined with execution sinks.",
        artifact_types=[ArtifactType.PYTHON, ArtifactType.JSON, ArtifactType.YAML],
        impact="Any connected model or compromised client can execute commands or modify arbitrary files without a human check.",
        remediation=(
            "Expose narrowly scoped tools, restrict filesystem roots to project directories, remove "
            "auto-approval for destructive tools, and never wrap servers in a shell with user-controlled arguments."
        ),
        references=[
            "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices",
            "https://cwe.mitre.org/data/definitions/250.html",
        ],
        cwe_ids=["CWE-250"],
        owasp_references=["OWASP Top 10 for LLM Applications 2025 LLM06"],
        tags=["mcp", "permissions"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        if ctx.artifact_type is ArtifactType.PYTHON:
            return self._check_python(ctx)
        return self._check_config(ctx)

    def _check_python(self, ctx: FileContext) -> list[Finding]:
        dataflow = ctx.dataflow
        if dataflow is None:
            return []
        findings: list[Finding] = []
        for info in dataflow.functions_with_role(FunctionRole.MCP_TOOL):
            name = info.tool_name or info.name
            if not EXEC_TOOL_NAME.search(name):
                continue
            if not info.has_sink(SinkKind.SHELL_EXEC, SinkKind.CODE_EXEC, SinkKind.SQL_EXEC):
                continue
            node = info.node
            assert node is not None
            kinds = sorted(
                {
                    s.kind.value
                    for s in info.sinks
                    if s.kind in {SinkKind.SHELL_EXEC, SinkKind.CODE_EXEC, SinkKind.SQL_EXEC}
                }
            )
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
                            description=f"MCP tool '{name}' performs {', '.join(kinds)}",
                            line=node.lineno,
                        )
                    ],
                    evidence_summary=f"MCP tool '{name}' exposes generic execution ({', '.join(kinds)})",
                    title=f"MCP tool '{name}' exposes generic command execution",
                    analyzer="dataflow",
                    fingerprint_material=f"tool:{name}:{','.join(kinds)}",
                )
            )
        return findings

    def _check_config(self, ctx: FileContext) -> list[Finding]:
        data = ctx.structured
        servers = find_mcp_servers(data)
        if not servers:
            return []
        findings: list[Finding] = []

        def report(
            server: str, key: str, what: str, severity: Severity, after_line: int = 0
        ) -> None:
            line, column = locate_key(ctx.text, key, after_line=after_line)
            findings.append(
                ctx.new_finding(
                    self,
                    line=line,
                    column=column,
                    evidence=[
                        Evidence(
                            kind="config_key",
                            description=what,
                            snippet=ctx.line(line).strip()[:200],
                            line=line,
                            column=column,
                        )
                    ],
                    evidence_summary=f"server '{server}': {what}",
                    severity=severity,
                    title=f"Unsafe MCP configuration: {what}",
                    analyzer="configuration",
                    fingerprint_material=f"{server}:{key}:{what}",
                )
            )

        for server, config in servers.items():
            server_line, _ = locate_key(ctx.text, server)
            command = str(config.get("command", "") or "")
            args = [
                str(a) for a in config.get("args", []) or [] if isinstance(a, str | int | float)
            ]
            command_base = command.replace("\\", "/").rsplit("/", 1)[-1].lower()
            if command_base in SHELL_COMMANDS and any(
                a in {"-c", "/c", "-Command", "-command"} for a in args
            ):
                report(
                    server,
                    "command",
                    f"server launched through a shell ({command_base} -c)",
                    Severity.HIGH,
                    server_line,
                )
            tokens = {token for arg in args for token in arg.split()}
            dangerous = sorted(tokens & DANGEROUS_ARGS)
            if dangerous:
                report(
                    server,
                    "args",
                    f"dangerous flags {', '.join(dangerous)}",
                    Severity.HIGH,
                    server_line,
                )
            joined = " ".join([command, *args])
            if FILESYSTEM_SERVER.search(joined):
                roots = [a for a in args if ROOT_PATHS.match(a.strip())]
                if roots:
                    report(
                        server,
                        "args",
                        f"filesystem server rooted at {', '.join(roots)}",
                        Severity.HIGH,
                        server_line,
                    )
            for key in AUTO_APPROVE_KEYS:
                value = config.get(key)
                if value is None:
                    continue
                what = _auto_approve_problem(key, value)
                if what:
                    report(
                        server,
                        key,
                        what,
                        Severity.HIGH if "all" in what else Severity.MEDIUM,
                        server_line,
                    )
        return findings


def _auto_approve_problem(key: str, value: Any) -> str | None:
    if value is True:
        return f"{key}: true approves all tool calls"
    if isinstance(value, list):
        names = [str(v) for v in value]
        if "*" in names or "all" in [n.lower() for n in names]:
            return f"{key} approves all tools"
        destructive = [n for n in names if DESTRUCTIVE_TOOL.search(n)]
        if destructive:
            return f"{key} auto-approves destructive tools: {', '.join(destructive[:5])}"
    return None
