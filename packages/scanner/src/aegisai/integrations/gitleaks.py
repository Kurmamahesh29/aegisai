"""Gitleaks integration: secret detection normalised to SEC001 findings."""

from __future__ import annotations

import json
import tempfile
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
from aegisai.models.configuration import IntegrationSettings
from aegisai.models.finding import Confidence, Evidence
from aegisai.models.scan import AnalyzerResult, AnalyzerStatus, ScanWarning
from aegisai.utils.redaction import mask_value, redact_known_value

MIN_VERSION_NOTE = "Gitleaks 8.x is required (tested with 8.18+)."


class GitleaksAnalyzer(ExternalAnalyzer):
    name = "gitleaks"
    executable_name = "gitleaks"

    def run(
        self, project: ProjectContext, settings: IntegrationSettings, timeout_seconds: int
    ) -> IntegrationOutcome:
        from aegisai.engine.registry import default_registry

        meta = default_registry().get("SEC001")
        assert meta is not None  # registry always contains SEC001
        try:
            executable = resolve_executable(self.executable_name, settings.executable)
        except AnalyzerUnavailableError as exc:
            return IntegrationOutcome(
                AnalyzerResult(
                    name=self.name,
                    status=AnalyzerStatus.UNAVAILABLE,
                    required=settings.required,
                    message=f"{exc}. {MIN_VERSION_NOTE}",
                )
            )
        version = tool_version(executable, "version")
        with tempfile.TemporaryDirectory(prefix="aegisai-gitleaks-") as tmp:
            report = Path(tmp) / "gitleaks.json"
            args = [
                executable,
                "detect",
                "--no-git",
                "--source",
                str(project.root),
                "--report-format",
                "json",
                "--report-path",
                str(report),
                "--exit-code",
                "0",
                "--no-banner",
                *settings.extra_args,
            ]
            try:
                result = run_command(args, cwd=project.root, timeout_seconds=timeout_seconds)
            except AnalyzerUnavailableError as exc:
                return IntegrationOutcome(
                    AnalyzerResult(
                        name=self.name,
                        status=AnalyzerStatus.UNAVAILABLE,
                        required=settings.required,
                        message=str(exc),
                        version=version,
                    )
                )
            if result.timed_out:
                return IntegrationOutcome(
                    AnalyzerResult(
                        name=self.name,
                        status=AnalyzerStatus.TIMED_OUT,
                        required=settings.required,
                        message=f"gitleaks exceeded {timeout_seconds}s",
                        version=version,
                        duration_ms=result.duration_ms,
                    )
                )
            if result.returncode != 0:
                return IntegrationOutcome(
                    AnalyzerResult(
                        name=self.name,
                        status=AnalyzerStatus.FAILED,
                        required=settings.required,
                        message=f"gitleaks exited with {result.returncode}: {result.stderr.strip()[:300]}",
                        version=version,
                        duration_ms=result.duration_ms,
                    )
                )
            try:
                raw = report.read_text(encoding="utf-8")
            except OSError as exc:
                return IntegrationOutcome(
                    AnalyzerResult(
                        name=self.name,
                        status=AnalyzerStatus.FAILED,
                        required=settings.required,
                        message=f"gitleaks produced no report: {exc}",
                        version=version,
                        duration_ms=result.duration_ms,
                    )
                )
        try:
            entries = json.loads(raw) if raw.strip() else []
        except json.JSONDecodeError as exc:
            return IntegrationOutcome(
                AnalyzerResult(
                    name=self.name,
                    status=AnalyzerStatus.FAILED,
                    required=settings.required,
                    message=f"gitleaks report is not valid JSON: {exc}",
                    version=version,
                    duration_ms=result.duration_ms,
                )
            )
        outcome = IntegrationOutcome(
            AnalyzerResult(
                name=self.name,
                status=AnalyzerStatus.COMPLETED,
                required=settings.required,
                version=version,
                duration_ms=result.duration_ms,
            )
        )
        counter = FingerprintCounter()
        for entry in entries if isinstance(entries, list) else []:
            finding = self._normalize(entry, project.root, meta.metadata, counter)
            if finding is not None:
                outcome.findings.append(finding)
            else:
                outcome.warnings.append(
                    ScanWarning(code="gitleaks_entry", message="skipped malformed gitleaks entry")
                )
        outcome.result.findings_count = len(outcome.findings)
        return outcome

    @staticmethod
    def _normalize(
        entry: dict[str, Any], root: Path, meta: Any, counter: FingerprintCounter
    ) -> Any:
        try:
            rel_path = normalize_path(root, str(entry["File"]))
            line = int(entry.get("StartLine", 1)) or 1
            end_line = int(entry.get("EndLine", line)) or line
            column = int(entry.get("StartColumn", 1)) or 1
            end_column = int(entry.get("EndColumn", column)) or column
        except (KeyError, TypeError, ValueError):
            return None
        secret = str(entry.get("Secret", ""))
        match_text = str(entry.get("Match", ""))
        rule_id = str(entry.get("RuleID", "unknown"))
        description = str(entry.get("Description", "Secret detected"))
        redacted_match = redact_known_value(match_text, secret) if secret else match_text
        summary = f"{rule_id}: {redacted_match}"[:300]
        return build_finding(
            meta,
            rel_path=rel_path,
            line=line,
            column=column,
            end_line=end_line,
            end_column=end_column,
            evidence_summary=summary,
            analyzer="gitleaks",
            counter=counter,
            confidence=Confidence.HIGH,
            title=f"Potential hard-coded secret ({description})",
            evidence=[
                Evidence(
                    kind="secret",
                    description=f"gitleaks rule {rule_id}",
                    snippet=redacted_match,
                    line=line,
                    column=column,
                ),
                Evidence(
                    kind="value",
                    description="redacted secret value",
                    snippet=mask_value(secret) if secret else None,
                    line=line,
                ),
            ],
            tags=["analyzer:gitleaks", f"gitleaks:{rule_id}"],
            fingerprint_material=f"{rule_id}:{mask_value(secret) if secret else redacted_match}",
            review_required=False,
        )
