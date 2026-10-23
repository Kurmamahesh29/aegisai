"""CFG001: unsafe or overly permissive security-related configuration."""

from __future__ import annotations

import ast
from typing import Any

from aegisai.analyzers.configuration import iter_scalars, locate_path
from aegisai.analyzers.dataflow import is_unsafe_yaml_loader
from aegisai.analyzers.python_ast import (
    constant_value,
    dotted_name,
    get_keyword,
    is_truthy_constant,
    node_end,
)
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Evidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack


class UnsafeConfigurationRule(Rule):
    metadata = RuleMetadata(
        rule_id="CFG001",
        name="Unsafe security configuration",
        version="1.0.0",
        description=(
            "A security-relevant setting is configured in an unsafe way: debug mode enabled, TLS "
            "verification disabled, wildcard CORS with credentials, wildcard allowed hosts, "
            "unsafe YAML/pickle loading, privileged containers or write-all workflow permissions."
        ),
        category=Category.CONFIGURATION,
        pack=RulePack.CODE,
        default_severity=Severity.MEDIUM,
        default_confidence=Confidence.HIGH,
        confidence_behavior="High: each pattern is matched syntactically on a literal value.",
        artifact_types=[ArtifactType.PYTHON, ArtifactType.YAML, ArtifactType.JSON],
        impact="Weakens transport security, exposes debugging interfaces, or widens the attack surface.",
        remediation="Use the secure default for the setting in production and load environment-specific values from configuration.",
        references=[
            "https://cwe.mitre.org/data/definitions/16.html",
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        ],
        cwe_ids=["CWE-16"],
        owasp_references=["OWASP Top 10 2021 A05"],
        tags=["configuration"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        if ctx.artifact_type is ArtifactType.PYTHON:
            return self._check_python(ctx)
        return self._check_structured(ctx)

    # -- Python --------------------------------------------------------------------

    def _check_python(self, ctx: FileContext) -> list[Finding]:
        module = ctx.python_module
        if module is None:
            return []
        findings: list[Finding] = []

        def report(
            node: ast.AST, what: str, severity: Severity, remediation: str, cwe: str | None = None
        ) -> None:
            end_line, end_col = node_end(node)
            findings.append(
                ctx.new_finding(
                    self,
                    line=int(getattr(node, "lineno", 1)),
                    column=int(getattr(node, "col_offset", 0)) + 1,
                    end_line=end_line,
                    end_column=end_col,
                    evidence=[
                        Evidence(
                            kind="config",
                            description=what,
                            snippet=module.snippet(node),
                            line=int(getattr(node, "lineno", 1)),
                        )
                    ],
                    evidence_summary=what,
                    severity=severity,
                    title=f"Unsafe configuration: {what}",
                    remediation=remediation,
                    analyzer="python_ast",
                    tags=[cwe] if cwe else [],
                )
            )

        for node in ast.walk(module.tree):
            if isinstance(node, ast.Call):
                name = module.call_name(node) or ""
                tail = name.rsplit(".", 1)[-1]
                if tail == "run" and is_truthy_constant(get_keyword(node, "debug")):
                    host = constant_value(get_keyword(node, "host"))
                    severity = Severity.HIGH if host == "0.0.0.0" else Severity.MEDIUM  # noqa: S104
                    report(
                        node,
                        "debug=True in application run()",
                        severity,
                        "Disable debug mode in production; the debugger allows code execution.",
                        "CWE-489",
                    )
                if name.startswith(("requests.", "httpx.")) or tail in {
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                    "request",
                    "Client",
                    "AsyncClient",
                    "Session",
                }:
                    verify = get_keyword(node, "verify")
                    if isinstance(verify, ast.Constant) and verify.value is False:
                        report(
                            node,
                            "TLS certificate verification disabled (verify=False)",
                            Severity.HIGH,
                            "Remove verify=False; configure a CA bundle instead.",
                            "CWE-295",
                        )
                if (
                    name in {"ssl._create_unverified_context", "ssl._create_default_https_context"}
                    or tail == "_create_unverified_context"
                ):
                    report(
                        node,
                        "unverified SSL context",
                        Severity.HIGH,
                        "Use ssl.create_default_context() with certificate verification.",
                        "CWE-295",
                    )
                if tail in {"CORSMiddleware", "CORS"} or name.endswith("add_middleware"):
                    origins = get_keyword(node, "allow_origins") or get_keyword(node, "origins")
                    credentials = get_keyword(node, "allow_credentials") or get_keyword(
                        node, "supports_credentials"
                    )
                    if _contains_wildcard(origins) and is_truthy_constant(credentials):
                        report(
                            node,
                            "CORS wildcard origin with credentials",
                            Severity.HIGH,
                            "Set an explicit list of trusted origins when allowing credentials.",
                            "CWE-942",
                        )
                if name == "yaml.load":
                    loader = get_keyword(node, "Loader") or (
                        node.args[1] if len(node.args) > 1 else None
                    )
                    loader_name = dotted_name(loader) if loader is not None else ""
                    if loader is None or is_unsafe_yaml_loader(loader_name):
                        report(
                            node,
                            "yaml.load without a safe Loader",
                            Severity.HIGH,
                            "Use yaml.safe_load() or Loader=yaml.SafeLoader.",
                            "CWE-502",
                        )
                if name in {"yaml.unsafe_load", "yaml.full_load"}:
                    report(
                        node,
                        f"{name}() enables arbitrary object construction",
                        Severity.HIGH,
                        "Use yaml.safe_load().",
                        "CWE-502",
                    )
                if name in {"os.chmod"} and len(node.args) > 1:
                    mode = constant_value(node.args[1])
                    if isinstance(mode, int) and mode & 0o002:
                        report(
                            node,
                            "world-writable file permissions",
                            Severity.MEDIUM,
                            "Avoid world-writable modes; use 0o640/0o750 or stricter.",
                            "CWE-732",
                        )
                if tail in {"FastMCP", "Flask", "FastAPI"} and is_truthy_constant(
                    get_keyword(node, "debug")
                ):
                    report(
                        node,
                        "debug=True in application constructor",
                        Severity.MEDIUM,
                        "Disable debug mode in production.",
                        "CWE-489",
                    )
            elif isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                target_name = dotted_name(target)
                if target_name in {
                    "DEBUG",
                    "settings.DEBUG",
                    "app.debug",
                    "app.config.DEBUG",
                } and is_truthy_constant(node.value):
                    report(
                        node,
                        f"{target_name} = True",
                        Severity.MEDIUM,
                        "Set DEBUG from the environment and keep it False in production.",
                        "CWE-489",
                    )
                if target_name == "ALLOWED_HOSTS" and _contains_wildcard(node.value):
                    report(
                        node,
                        'ALLOWED_HOSTS = ["*"]',
                        Severity.MEDIUM,
                        "List the concrete hostnames the application serves.",
                        "CWE-16",
                    )
                if (
                    target_name
                    in {"check_hostname", "ctx.check_hostname", "context.check_hostname"}
                    and isinstance(node.value, ast.Constant)
                    and node.value.value is False
                ):
                    report(
                        node,
                        "check_hostname = False",
                        Severity.HIGH,
                        "Keep hostname verification enabled.",
                        "CWE-295",
                    )
                if target_name.endswith("verify_mode") and dotted_name(node.value).endswith(
                    "CERT_NONE"
                ):
                    report(
                        node,
                        "verify_mode = ssl.CERT_NONE",
                        Severity.HIGH,
                        "Use ssl.CERT_REQUIRED.",
                        "CWE-295",
                    )
            elif isinstance(node, ast.Subscript | ast.Attribute):
                pass
        return findings

    # -- YAML / JSON -----------------------------------------------------------------

    def _check_structured(self, ctx: FileContext) -> list[Finding]:
        data = ctx.structured
        if not isinstance(data, dict | list):
            return []
        findings: list[Finding] = []
        for path, value in iter_scalars(data):
            key = path[-1] if path else ""
            what: str | None = None
            severity = Severity.MEDIUM
            remediation = ""
            if key == "privileged" and value is True:
                what = "privileged: true container"
                severity = Severity.HIGH
                remediation = "Drop privileged mode; grant specific capabilities instead."
            elif key == "permissions" and isinstance(value, str) and value == "write-all":
                what = "workflow permissions: write-all"
                remediation = "Declare the minimal permissions each job needs."
            elif (
                key
                in {
                    "allow_dangerous_code",
                    "allow_dangerous_requests",
                    "allow_dangerous_deserialization",
                    "allowDangerousCode",
                }
                and value is True
            ):
                what = f"{key}: true"
                severity = Severity.HIGH
                remediation = "Do not enable dangerous execution flags in deployed configuration."
            elif (
                key
                in {
                    "verify_ssl",
                    "verify",
                    "tls_verify",
                    "sslVerify",
                    "rejectUnauthorized",
                    "strictSSL",
                }
                and value is False
            ):
                what = f"{key}: false disables TLS verification"
                severity = Severity.HIGH
                remediation = "Enable certificate verification."
            elif (
                key in {"debug", "DEBUG"}
                and value is True
                and any(
                    p in {"app", "server", "flask", "django", "production", "prod"} for p in path
                )
            ):
                what = f"{'.'.join(path)}: true"
                remediation = "Disable debug mode in production configuration."
            if what is None:
                continue
            line, column = locate_path(ctx.text, path)
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
                    evidence_summary=what,
                    severity=severity,
                    title=f"Unsafe configuration: {what}",
                    remediation=remediation or self.metadata.remediation,
                    analyzer="configuration",
                    fingerprint_material=".".join(path),
                )
            )
        return findings


def _contains_wildcard(node: Any) -> bool:
    if isinstance(node, ast.Constant):
        return node.value == "*"
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(isinstance(e, ast.Constant) and e.value == "*" for e in node.elts)
    return False
