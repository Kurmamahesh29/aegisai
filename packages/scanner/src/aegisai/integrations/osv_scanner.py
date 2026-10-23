"""OSV-Scanner integration: known vulnerable dependencies normalised to DEP001 findings.

Note: OSV-Scanner queries the OSV.dev API over the network. Enabling this integration is an
explicit opt-in to that network access (see docs/privacy.md).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegisai.discovery.manifests import OSV_SUPPORTED_MANIFESTS
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
from aegisai.models.finding import Confidence, Evidence, Severity
from aegisai.models.scan import AnalyzerResult, AnalyzerStatus, ScanWarning

MIN_VERSION_NOTE = "OSV-Scanner 1.8+ or 2.x is required."
EXIT_VULNS_FOUND = 1
EXIT_NO_PACKAGES = 128


class OsvScannerAnalyzer(ExternalAnalyzer):
    name = "osv_scanner"
    executable_name = "osv-scanner"

    def run(
        self, project: ProjectContext, settings: IntegrationSettings, timeout_seconds: int
    ) -> IntegrationOutcome:
        from aegisai.engine.registry import default_registry

        rule = default_registry().get("DEP001")
        assert rule is not None
        meta = rule.metadata
        supported = [m for m in project.manifests if m.path.name in OSV_SUPPORTED_MANIFESTS]
        unsupported = [
            m.rel_path for m in project.manifests if m.path.name not in OSV_SUPPORTED_MANIFESTS
        ]
        if not supported:
            return IntegrationOutcome(
                AnalyzerResult(
                    name=self.name,
                    status=AnalyzerStatus.SKIPPED,
                    required=settings.required,
                    message="no supported dependency manifests or lockfiles found",
                ),
                warnings=[
                    ScanWarning(
                        code="osv_unsupported_manifest",
                        message=f"manifest not supported by OSV-Scanner: {path}",
                        file_path=path,
                    )
                    for path in unsupported
                ],
            )
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
        version = tool_version(executable)
        lockfile_args: list[str] = []
        for manifest in supported:
            lockfile_args.extend(["--lockfile", str(manifest.path)])
        # v2 syntax first, then v1 syntax.
        attempts = [
            [
                executable,
                "scan",
                "source",
                "--format",
                "json",
                *lockfile_args,
                *settings.extra_args,
            ],
            [executable, "--format", "json", *lockfile_args, *settings.extra_args],
        ]
        result = None
        for args in attempts:
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
                        message=f"osv-scanner exceeded {timeout_seconds}s",
                        version=version,
                        duration_ms=result.duration_ms,
                    )
                )
            if result.stdout.strip().startswith("{"):
                break
        assert result is not None
        if not result.stdout.strip().startswith("{"):
            status = (
                AnalyzerStatus.SKIPPED
                if result.returncode == EXIT_NO_PACKAGES
                else AnalyzerStatus.FAILED
            )
            return IntegrationOutcome(
                AnalyzerResult(
                    name=self.name,
                    status=status,
                    required=settings.required,
                    message=f"osv-scanner exited with {result.returncode}: {(result.stderr or result.stdout).strip()[:300]}",
                    version=version,
                    duration_ms=result.duration_ms,
                )
            )
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            return IntegrationOutcome(
                AnalyzerResult(
                    name=self.name,
                    status=AnalyzerStatus.FAILED,
                    required=settings.required,
                    message=f"osv-scanner output is not valid JSON: {exc}",
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
                files_processed=len(supported),
            ),
            warnings=[
                ScanWarning(
                    code="osv_unsupported_manifest",
                    message=f"manifest not supported by OSV-Scanner: {path}",
                    file_path=path,
                )
                for path in unsupported
            ],
        )
        counter = FingerprintCounter()
        for source_result in data.get("results", []) or []:
            source_path = str((source_result.get("source") or {}).get("path", ""))
            rel_path = normalize_path(project.root, source_path) if source_path else "unknown"
            for package in source_result.get("packages", []) or []:
                info = package.get("package") or {}
                name = str(info.get("name", "unknown"))
                pkg_version = str(info.get("version", "unknown"))
                ecosystem = str(info.get("ecosystem", ""))
                groups = package.get("groups") or []
                vulns = package.get("vulnerabilities") or []
                max_by_group = {tuple(g.get("ids", [])): g.get("max_severity") for g in groups}
                for vuln in vulns:
                    finding = self._normalize(
                        vuln,
                        name,
                        pkg_version,
                        ecosystem,
                        rel_path,
                        project.root,
                        meta,
                        counter,
                        max_by_group,
                    )
                    if finding is not None:
                        outcome.findings.append(finding)
        for error in data.get("errors", []) or []:
            outcome.warnings.append(ScanWarning(code="osv_error", message=str(error)[:300]))
        outcome.result.findings_count = len(outcome.findings)
        return outcome

    @staticmethod
    def _normalize(
        vuln: dict[str, Any],
        name: str,
        version: str,
        ecosystem: str,
        rel_path: str,
        root: Path,
        meta: Any,
        counter: FingerprintCounter,
        max_by_group: dict[tuple[str, ...], Any],
    ) -> Any:
        vuln_id = str(vuln.get("id", "")).strip()
        if not vuln_id:
            return None
        aliases = [str(a) for a in vuln.get("aliases", []) or []]
        summary = str(vuln.get("summary") or vuln.get("details") or "known vulnerability")[:300]
        score = _max_score(vuln, max_by_group)
        severity, confidence = _severity_from_score(score)
        fixed = _fixed_versions(vuln, name)
        references = [f"https://osv.dev/vulnerability/{vuln_id}"]
        for ref in vuln.get("references", []) or []:
            url = ref.get("url") if isinstance(ref, dict) else None
            if isinstance(url, str) and url.startswith("https://"):
                references.append(url)
        cwe_ids = []
        db = vuln.get("database_specific") or {}
        for cwe in db.get("cwe_ids", []) or []:
            if isinstance(cwe, str) and cwe.startswith("CWE-"):
                cwe_ids.append(cwe)
        line = _locate_package_line(root / rel_path, name)
        remediation = (
            f"Upgrade {name} to a fixed version ({', '.join(fixed)})."
            if fixed
            else f"Check the advisory for {name}; no fixed version was reported by OSV."
        )
        return build_finding(
            meta,
            rel_path=rel_path,
            line=line,
            evidence_summary=f"{name}@{version} affected by {vuln_id}",
            analyzer="osv_scanner",
            counter=counter,
            severity=severity,
            confidence=confidence,
            title=f"Vulnerable dependency {name} {version}: {vuln_id}",
            description=summary,
            remediation=remediation,
            references=references[:10],
            evidence=[
                Evidence(
                    kind="package",
                    description=f"{ecosystem} package {name} version {version}",
                    line=line,
                ),
                Evidence(
                    kind="advisory",
                    description=f"{vuln_id}"
                    + (f" (aliases: {', '.join(aliases)})" if aliases else ""),
                    line=line,
                ),
                Evidence(
                    kind="score",
                    description=f"max severity score {score}"
                    if score is not None
                    else "no severity score provided",
                    line=line,
                ),
            ],
            tags=["analyzer:osv_scanner", f"osv:{vuln_id}", *(f"alias:{a}" for a in aliases[:5])],
            cwe_ids=cwe_ids,
            fingerprint_material=f"{name}@{version}:{vuln_id}",
            review_required=score is None,
        )


def _max_score(vuln: dict[str, Any], max_by_group: dict[tuple[str, ...], Any]) -> float | None:
    vuln_id = str(vuln.get("id", ""))
    for ids, max_sev in max_by_group.items():
        if vuln_id in ids and max_sev not in (None, ""):
            try:
                return float(max_sev)
            except (TypeError, ValueError):
                pass
    best: float | None = None
    for entry in vuln.get("severity", []) or []:
        score = entry.get("score") if isinstance(entry, dict) else None
        if isinstance(score, int | float):
            best = max(best or 0.0, float(score))
    db = vuln.get("database_specific") or {}
    text = str(db.get("severity", "")).upper()
    if best is None and text:
        best = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.5}.get(text)
    return best


def _severity_from_score(score: float | None) -> tuple[Severity, Confidence]:
    if score is None:
        return Severity.MEDIUM, Confidence.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL, Confidence.HIGH
    if score >= 7.0:
        return Severity.HIGH, Confidence.HIGH
    if score >= 4.0:
        return Severity.MEDIUM, Confidence.HIGH
    return Severity.LOW, Confidence.HIGH


def _fixed_versions(vuln: dict[str, Any], name: str) -> list[str]:
    fixed: list[str] = []
    for affected in vuln.get("affected", []) or []:
        package = affected.get("package") or {}
        if str(package.get("name", "")).lower() != name.lower():
            continue
        for rng in affected.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                value = event.get("fixed")
                if isinstance(value, str) and value not in fixed:
                    fixed.append(value)
    return fixed


def _locate_package_line(path: Path, package: str) -> int:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 1
    needle = package.lower()
    for number, line in enumerate(lines, start=1):
        if needle in line.lower():
            return number
    return 1
