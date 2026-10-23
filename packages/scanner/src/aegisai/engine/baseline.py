"""Baseline files: record known findings so CI only fails on new ones."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aegisai.exceptions import BaselineError
from aegisai.models.finding import Finding, FindingStatus
from aegisai.models.scan import BaselineSummary, ScanResult

BASELINE_VERSION = 1


class BaselineEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fingerprint: str
    rule_id: str
    file_path: str
    first_seen: datetime


class Baseline(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = BASELINE_VERSION
    created_at: datetime
    tool_version: str
    entries: list[BaselineEntry] = Field(default_factory=list)

    def fingerprints(self) -> dict[str, BaselineEntry]:
        return {entry.fingerprint: entry for entry in self.entries}


def load_baseline(path: Path) -> Baseline:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineError(f"baseline {path} is not valid JSON: {exc}") from exc
    # Accept a full scan report as a baseline for convenience.
    if isinstance(raw, dict) and "findings" in raw and "entries" not in raw:
        try:
            result = ScanResult.model_validate(raw)
        except ValidationError as exc:
            raise BaselineError(
                f"baseline {path} is neither a baseline nor a scan report: {exc}"
            ) from exc
        return baseline_from_result(result)
    try:
        baseline = Baseline.model_validate(raw)
    except ValidationError as exc:
        raise BaselineError(f"invalid baseline {path}: {exc}") from exc
    if baseline.version != BASELINE_VERSION:
        raise BaselineError(f"unsupported baseline version {baseline.version}")
    return baseline


def baseline_from_result(result: ScanResult) -> Baseline:
    now = datetime.now(UTC)
    entries = [
        BaselineEntry(
            fingerprint=f.fingerprint,
            rule_id=f.rule_id,
            file_path=f.location.file_path,
            first_seen=f.first_seen or now,
        )
        for f in result.findings
        if f.status is not FindingStatus.SUPPRESSED
    ]
    return Baseline(created_at=now, tool_version=result.metadata.tool_version, entries=entries)


def write_baseline(baseline: Baseline, path: Path) -> None:
    path.write_text(baseline.model_dump_json(indent=2), encoding="utf-8")


def apply_baseline(
    findings: list[Finding], baseline: Baseline, baseline_path: str
) -> tuple[list[Finding], BaselineSummary]:
    """Mark findings as existing/new and compute resolved fingerprints.

    Suppressed findings keep their status; a baseline never hides scan failures because it
    only annotates findings and is applied after analyzer status has been recorded.
    """
    known = baseline.fingerprints()
    seen: set[str] = set()
    updated: list[Finding] = []
    summary = BaselineSummary(baseline_path=baseline_path)
    for finding in findings:
        seen.add(finding.fingerprint)
        if finding.status is FindingStatus.SUPPRESSED:
            updated.append(finding)
            continue
        entry = known.get(finding.fingerprint)
        if entry is not None:
            summary.existing += 1
            updated.append(
                finding.model_copy(
                    update={"status": FindingStatus.EXISTING, "first_seen": entry.first_seen}
                )
            )
        else:
            summary.new += 1
            updated.append(finding)
    resolved = sorted(fp for fp in known if fp not in seen)
    summary.resolved = len(resolved)
    summary.resolved_fingerprints = resolved
    return updated, summary
