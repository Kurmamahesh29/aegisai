"""Semgrep integration with explicitly configured local rule files only.

Registry references (``p/...``, ``r/...``, ``auto``) and URLs are refused so that AegisAI never
downloads or executes rules the user did not review. Upstream findings are reported as SMG001
with the Semgrep check id preserved; AegisAI does not independently verify them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegisai.discovery.project import ProjectContext
from aegisai.exceptions import AnalyzerUnavailableError
from aegisai.integrations.base import (
    ExternalAnalyzer,
    FingerprintCounter,
    IntegrationOutcome,
    build_finding,
    normalize_path,
)
from aegisai.integrations.subprocess_runner import resolve_executable, run_command, tool_version
from aegisai.models.configuration import IntegrationSettings, SemgrepSettings
from aegisai.models.finding import Confidence, Evidence, Severity
from aegisai.models.scan import AnalyzerResult, AnalyzerStatus, ScanWarning

_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def validate_rule_sources(sources: list[str], root: Path) -> tuple[list[Path], list[str]]:
    """Return (accepted local paths, rejection messages)."""
    accepted: list[Path] = []
    rejected: list[str] = []
    for source in sources:
        lowered = source.lower()
        if lowered in {"auto"} or lowered.startswith(("p/", "r/", "http://", "https://", "s/")):
            rejected.append(
                f"refusing remote/registry Semgrep config '{source}'; use local rule files"
            )
            continue
        candidate = Path(source)
        if not candidate.is_absolute():
            candidate = (root / candidate).resolve()
        if not candidate.exists():
            rejected.append(f"Semgrep config not found: {source}")
            continue
        accepted.append(candidate)
    return accepted, rejected


class SemgrepAnalyzer(ExternalAnalyzer):
    name = "semgrep"
    executable_name = "semgrep"

    def run(
        self, project: ProjectContext, settings: IntegrationSettings, timeout_seconds: int
    ) -> IntegrationOutcome:
        from aegisai.engine.registry import default_registry

        rule = default_registry().get("SMG001")
        assert rule is not None
        meta = rule.metadata
        configs = settings.config if isinstance(settings, SemgrepSettings) else []
        accepted, rejected = validate_rule_sources(list(configs), project.root)
        warnings = [ScanWarning(code="semgrep_config", message=message) for message in rejected]
        if not accepted:
            return IntegrationOutcome(
                AnalyzerResult(
                    name=self.name,
                    status=AnalyzerStatus.SKIPPED,
                    required=settings.required,
                    message="no local Semgrep rule files configured (integrations.semgrep.config)",
                ),
                warnings=warnings,
            )
        try:
            executable = resolve_executable(self.executable_name, settings.executable)
        except AnalyzerUnavailableError as exc:
            return IntegrationOutcome(
                AnalyzerResult(
                    name=self.name,
                    status=AnalyzerStatus.UNAVAILABLE,
                    required=settings.required,
                    message=str(exc),
                ),
                warnings=warnings,
            )
        version = tool_version(executable)
        args = [executable, "scan", "--json", "--metrics=off", "--disable-version-check", "--quiet"]
        for config in accepted:
            args.extend(["--config", str(config)])
        args.extend(settings.extra_args)
        args.append(str(project.root))
        try:
            result = run_command(
                args,
                cwd=project.root,
                timeout_seconds=timeout_seconds,
                env={"SEMGREP_SEND_METRICS": "off"},
            )
        except AnalyzerUnavailableError as exc:
            return IntegrationOutcome(
                AnalyzerResult(
                    name=self.name,
                    status=AnalyzerStatus.UNAVAILABLE,
                    required=settings.required,
                    message=str(exc),
                    version=version,
                ),
                warnings=warnings,
            )
        if result.timed_out:
            return IntegrationOutcome(
                AnalyzerResult(
                    name=self.name,
                    status=AnalyzerStatus.TIMED_OUT,
                    required=settings.required,
                    message=f"semgrep exceeded {timeout_seconds}s",
                    version=version,
                    duration_ms=result.duration_ms,
                ),
                warnings=warnings,
            )
        if not result.stdout.strip().startswith("{"):
            return IntegrationOutcome(
                AnalyzerResult(
                    name=self.name,
                    status=AnalyzerStatus.FAILED,
                    required=settings.required,
                    message=f"semgrep exited with {result.returncode}: {(result.stderr or result.stdout).strip()[:300]}",
                    version=version,
                    duration_ms=result.duration_ms,
                ),
                warnings=warnings,
            )
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            return IntegrationOutcome(
                AnalyzerResult(
                    name=self.name,
                    status=AnalyzerStatus.FAILED,
                    required=settings.required,
                    message=f"semgrep output is not valid JSON: {exc}",
                    version=version,
                    duration_ms=result.duration_ms,
                ),
                warnings=warnings,
            )
        outcome = IntegrationOutcome(
            AnalyzerResult(
                name=self.name,
                status=AnalyzerStatus.COMPLETED,
                required=settings.required,
                version=version,
                duration_ms=result.duration_ms,
            ),
            warnings=warnings,
        )
        for error in data.get("errors", []) or []:
            message = error.get("message") if isinstance(error, dict) else str(error)
            outcome.warnings.append(ScanWarning(code="semgrep_error", message=str(message)[:300]))
        counter = FingerprintCounter()
        for item in data.get("results", []) or []:
            finding = self._normalize(item, project.root, meta, counter)
            if finding is not None:
                outcome.findings.append(finding)
        outcome.result.findings_count = len(outcome.findings)
        return outcome

    @staticmethod
    def _normalize(item: dict[str, Any], root: Path, meta: Any, counter: FingerprintCounter) -> Any:
        try:
            check_id = str(item["check_id"])
            rel_path = normalize_path(root, str(item["path"]))
            start = item.get("start") or {}
            end = item.get("end") or {}
            line = int(start.get("line", 1)) or 1
            column = int(start.get("col", 1)) or 1
            end_line = int(end.get("line", line)) or line
            end_column = int(end.get("col", column)) or column
        except (KeyError, TypeError, ValueError):
            return None
        extra = item.get("extra") or {}
        message = str(extra.get("message", "Semgrep finding"))[:500]
        metadata = extra.get("metadata") or {}
        severity = _SEVERITY_MAP.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM)
        snippet = str(extra.get("lines", ""))[:200].strip()
        references = [
            r
            for r in metadata.get("references", []) or []
            if isinstance(r, str) and r.startswith("https://")
        ]
        cwe_ids: list[str] = []
        raw_cwe = metadata.get("cwe")
        for value in raw_cwe if isinstance(raw_cwe, list) else [raw_cwe]:
            if isinstance(value, str) and value.upper().startswith("CWE-"):
                token = value.split(":")[0].strip().upper()
                if token[4:].isdigit():
                    cwe_ids.append(token)
        return build_finding(
            meta,
            rel_path=rel_path,
            line=line,
            column=column,
            end_line=end_line,
            end_column=end_column,
            evidence_summary=f"{check_id}: {snippet or message}",
            analyzer="semgrep",
            counter=counter,
            severity=severity,
            confidence=Confidence.MEDIUM,
            title=f"Semgrep: {check_id.rsplit('.', 1)[-1]}",
            description=message,
            references=references[:10],
            evidence=[
                Evidence(
                    kind="semgrep",
                    description=f"check {check_id}",
                    snippet=snippet or None,
                    line=line,
                    column=column,
                )
            ],
            tags=["analyzer:semgrep", f"semgrep:{check_id}"],
            cwe_ids=cwe_ids,
            fingerprint_material=f"{check_id}:{snippet}",
            review_required=True,
        )
