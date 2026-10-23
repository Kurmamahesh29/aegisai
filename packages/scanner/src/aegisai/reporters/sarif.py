"""SARIF 2.1.0 report generation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegisai.models.finding import Finding, FindingStatus, Severity
from aegisai.models.rule import RuleMetadata
from aegisai.models.scan import AnalyzerStatus, ScanResult, ScanStatus

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
FINGERPRINT_KEY = "aegisai/fingerprint/v1"

_LEVELS: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "note",
}

_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.5",
    Severity.INFORMATIONAL: "0.5",
}


def build_sarif(result: ScanResult, rules: list[RuleMetadata]) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log with one run."""
    rule_index: dict[str, int] = {}
    rule_objects: list[dict[str, Any]] = []
    known = {meta.rule_id: meta for meta in rules}
    # Include every rule that produced a finding, even if unknown to the registry.
    rule_ids = sorted({f.rule_id for f in result.findings} | set(known))
    for rule_id in rule_ids:
        meta = known.get(rule_id)
        rule_index[rule_id] = len(rule_objects)
        rule_objects.append(_rule_object(rule_id, meta))

    results = [_result_object(f, rule_index) for f in result.findings]
    notifications = [
        {
            "level": "error"
            if analyzer.status in (AnalyzerStatus.FAILED, AnalyzerStatus.TIMED_OUT)
            else "warning",
            "message": {
                "text": f"analyzer {analyzer.name}: {analyzer.status.value}"
                + (f" - {analyzer.message}" if analyzer.message else "")
            },
            "descriptor": {"id": f"AEGIS-ANALYZER-{analyzer.status.value.upper()}"},
        }
        for analyzer in result.analyzers
        if analyzer.status
        in (AnalyzerStatus.FAILED, AnalyzerStatus.TIMED_OUT, AnalyzerStatus.UNAVAILABLE)
    ]
    notifications.extend(
        {
            "level": "warning",
            "message": {"text": f"{warning.code}: {warning.message}"},
            "descriptor": {"id": f"AEGIS-WARNING-{warning.code.upper()}"},
        }
        for warning in result.warnings
    )
    notifications.extend(
        {
            "level": "error",
            "message": {"text": f"rule {error.rule_id} failed on {error.file_path}: {error.error}"},
            "descriptor": {"id": "AEGIS-RULE-ERROR"},
        }
        for error in result.errors
    )
    invocation: dict[str, Any] = {
        "executionSuccessful": result.status
        in (ScanStatus.SUCCESS, ScanStatus.SUCCESS_WITH_WARNINGS),
        "startTimeUtc": _iso(result.metadata.started_at),
        "endTimeUtc": _iso(result.metadata.finished_at),
        "exitCode": result.summary.exit_code,
        "toolExecutionNotifications": notifications,
        "properties": {"status": result.status.value, "statusReason": result.status_reason},
    }
    if result.metadata.command_line:
        invocation["arguments"] = list(result.metadata.command_line)
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": result.metadata.tool_name,
                "version": result.metadata.tool_version,
                "semanticVersion": result.metadata.tool_version,
                "informationUri": "https://github.com/aegisai/aegisai",
                "rules": rule_objects,
            }
        },
        "automationDetails": {"id": f"aegisai/{'+'.join(result.metadata.profiles)}"},
        "invocations": [invocation],
        "originalUriBaseIds": {"%SRCROOT%": {"uri": _dir_uri(result.metadata.root)}},
        "results": results,
        "columnKind": "unicodeCodePoints",
        "properties": {
            "summary": result.summary.model_dump(mode="json"),
            "analyzers": [a.model_dump(mode="json") for a in result.analyzers],
            "skippedRules": [s.model_dump(mode="json") for s in result.skipped_rules],
        },
    }
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def render_sarif(result: ScanResult, rules: list[RuleMetadata]) -> str:
    return json.dumps(build_sarif(result, rules), indent=2)


def write_sarif(result: ScanResult, rules: list[RuleMetadata], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_sarif(result, rules) + "\n", encoding="utf-8")


def _rule_object(rule_id: str, meta: RuleMetadata | None) -> dict[str, Any]:
    if meta is None:
        return {"id": rule_id, "name": rule_id, "shortDescription": {"text": rule_id}}
    tags = [meta.category.value, meta.pack.value, "security", *meta.tags]
    tags.extend(f"external/cwe/{cwe.lower()}" for cwe in meta.cwe_ids)
    obj: dict[str, Any] = {
        "id": meta.rule_id,
        "name": meta.name.replace(" ", ""),
        "shortDescription": {"text": meta.name},
        "fullDescription": {"text": meta.description},
        "help": {
            "text": f"{meta.description}\n\nRemediation: {meta.remediation}",
            "markdown": f"**{meta.name}**\n\n{meta.description}\n\n**Remediation:** {meta.remediation}",
        },
        "defaultConfiguration": {"level": _LEVELS[meta.default_severity]},
        "properties": {
            "tags": tags,
            "precision": {"high": "high", "medium": "medium", "low": "low"}[
                meta.default_confidence.value
            ],
            "security-severity": _SECURITY_SEVERITY[meta.default_severity],
            "severity": meta.default_severity.value,
            "heuristic": meta.heuristic,
            "ruleVersion": meta.version,
        },
    }
    if meta.references:
        obj["helpUri"] = meta.references[0]
    return obj


def _result_object(finding: Finding, rule_index: dict[str, int]) -> dict[str, Any]:
    loc = finding.location
    region: dict[str, Any] = {
        "startLine": loc.start_line,
        "startColumn": loc.start_column,
        "endLine": loc.end_line,
        "endColumn": loc.end_column,
    }
    snippet = next((e.snippet for e in finding.evidence if e.snippet), None)
    if snippet:
        region["snippet"] = {"text": snippet}
    message = f"{finding.title}: {finding.evidence_summary}"
    if finding.review_required:
        message += " (review required: heuristic finding)"
    obj: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index[finding.rule_id],
        "level": _LEVELS[finding.severity],
        "kind": "fail",
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": loc.file_path, "uriBaseId": "%SRCROOT%"},
                    "region": region,
                }
            }
        ],
        "partialFingerprints": {FINGERPRINT_KEY: finding.fingerprint},
        "properties": {
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "category": finding.category.value,
            "analyzer": finding.analyzer,
            "status": finding.status.value,
            "reviewRequired": finding.review_required,
            "remediation": finding.remediation,
            "impact": finding.impact,
            "cwe": finding.cwe_ids,
            "owasp": finding.owasp_references,
            "tags": finding.tags,
        },
    }
    if finding.status is FindingStatus.SUPPRESSED and finding.suppression is not None:
        obj["suppressions"] = [
            {
                "kind": "inSource" if finding.suppression.source == "inline" else "external",
                "status": "accepted",
                "justification": finding.suppression.reason,
            }
        ]
    obj["baselineState"] = "unchanged" if finding.status is FindingStatus.EXISTING else "new"
    return obj


def _dir_uri(path: str) -> str:
    normalised = path.replace("\\", "/")
    if not normalised.endswith("/"):
        normalised += "/"
    if normalised.startswith("/"):
        return f"file://{normalised}"
    return f"file:///{normalised}"


def _iso(value: Any) -> str:
    text = str(value.isoformat())
    return text.replace("+00:00", "Z")
