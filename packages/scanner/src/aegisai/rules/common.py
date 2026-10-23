"""Helpers shared by dataflow-based rules."""

from __future__ import annotations

from collections.abc import Iterable

from aegisai.analyzers.dataflow import SinkKind, SinkMatch, TaintFlow
from aegisai.analyzers.python_ast import node_end
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Confidence, Evidence, Finding, Severity

SINK_LABEL: dict[SinkKind, str] = {
    SinkKind.SHELL_EXEC: "shell/command execution",
    SinkKind.CODE_EXEC: "code execution",
    SinkKind.SQL_EXEC: "SQL execution",
    SinkKind.FILE_PATH: "filesystem access",
    SinkKind.NETWORK_REQUEST: "outbound network request",
    SinkKind.DYNAMIC_DISPATCH: "dynamic dispatch",
    SinkKind.HTML_RENDER: "HTML rendering",
    SinkKind.REDIRECT: "HTTP redirect",
    SinkKind.DESERIALIZATION: "unsafe deserialization",
    SinkKind.LOGGING: "logging/printing",
    SinkKind.PROMPT: "prompt construction / LLM call",
    SinkKind.TOOL_INVOCATION: "tool invocation",
    SinkKind.HTTP_RESPONSE: "HTTP response",
}

SOURCE_LABEL: dict[str, str] = {
    "user_input": "untrusted user input",
    "llm_output": "LLM output",
    "retrieved_content": "retrieved content",
    "tool_output": "tool output",
    "tool_param": "agent tool parameter",
    "mcp_tool_param": "MCP tool parameter",
    "secret_value": "secret value",
}


def severity_for_sink(kind: SinkKind) -> Severity:
    if kind in (SinkKind.SHELL_EXEC, SinkKind.CODE_EXEC, SinkKind.DESERIALIZATION):
        return Severity.CRITICAL
    if kind in (
        SinkKind.SQL_EXEC,
        SinkKind.FILE_PATH,
        SinkKind.NETWORK_REQUEST,
        SinkKind.HTML_RENDER,
    ):
        return Severity.HIGH
    return Severity.MEDIUM


def flow_evidence(flow: TaintFlow) -> list[Evidence]:
    source = flow.source
    sink = flow.sink
    via = " -> ".join(source.via) if source.via else "(direct)"
    evidence = [
        Evidence(
            kind="source",
            description=f"{SOURCE_LABEL.get(source.kind.value, source.kind.value)} from {source.label}",
            line=source.line,
            column=source.column,
        ),
        Evidence(
            kind="path",
            description=f"propagates through: {via}",
            line=source.line,
        ),
        Evidence(
            kind="sink",
            description=f"{SINK_LABEL[sink.kind]} via {sink.callee}() argument {sink.argument}"
            + (" with shell=True" if sink.shell else ""),
            snippet=flow.snippet,
            line=sink.line,
            column=sink.column,
        ),
    ]
    for guard in flow.guards:
        evidence.append(
            Evidence(
                kind="guard",
                description=f"possible validation: {guard.description}",
                line=guard.line,
            )
        )
    return evidence


_SANDBOX_DOWNGRADE: dict[Severity, Severity] = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
}


def is_sandboxed(sink: SinkMatch) -> bool:
    """True when the sink callee is a sandbox/isolated-execution provider by name."""
    return "sandbox" in sink.callee.lower()


def has_strong_guard(flow: TaintFlow) -> bool:
    """True when an allow-list membership or equality check constrains the tainted value.

    Injection-style rules skip such flows entirely; weaker validation only lowers confidence.
    """
    return any(guard.strong for guard in flow.guards)


def adjusted_confidence(flow: TaintFlow, base: Confidence) -> tuple[Confidence, bool]:
    """Lower confidence when a validation-looking guard references the tainted value."""
    if flow.guards:
        lowered = Confidence.MEDIUM if base is Confidence.HIGH else Confidence.LOW
        return lowered, True
    if flow.source.name_based:
        lowered = Confidence.MEDIUM if base is Confidence.HIGH else Confidence.LOW
        return lowered, True
    return base, False


def finding_from_flow(
    ctx: FileContext,
    rule: Rule,
    flow: TaintFlow,
    *,
    severity: Severity,
    confidence: Confidence,
    title: str | None = None,
    description: str | None = None,
    review_required: bool | None = None,
    tags: Iterable[str] = (),
) -> Finding:
    sink = flow.sink
    end_line, end_col = node_end(sink.node)
    source_label = SOURCE_LABEL.get(flow.source.kind.value, flow.source.kind.value)
    summary = (
        f"{source_label} ({flow.source.label}) reaches {SINK_LABEL[sink.kind]} "
        f"{sink.callee}() in {flow.function.name}()"
    )
    if flow.guards:
        summary += f"; {len(flow.guards)} validation-looking check(s) present"
    extra_tags = list(tags)
    if is_sandboxed(sink):
        # Execution through something named "sandbox" is still worth a look, but it is a
        # deliberate design rather than an accidental injection path.
        summary += "; sink is a sandbox provider"
        severity = _SANDBOX_DOWNGRADE.get(severity, severity)
        confidence = Confidence.MEDIUM if confidence is Confidence.HIGH else confidence
        review_required = True
        extra_tags.append("sandboxed")
    return ctx.new_finding(
        rule,
        line=sink.line,
        column=sink.column,
        end_line=end_line,
        end_column=end_col,
        evidence=flow_evidence(flow),
        evidence_summary=summary,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        review_required=review_required,
        tags=extra_tags,
        analyzer="dataflow",
        fingerprint_material=f"{flow.source.kind.value}:{flow.source.label}:{sink.kind.value}:{flow.snippet}",
    )
