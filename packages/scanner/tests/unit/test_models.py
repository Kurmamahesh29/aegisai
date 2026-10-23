"""Finding / scan model validation tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aegisai.models import (
    Category,
    Confidence,
    Finding,
    FindingStatus,
    Location,
    ScanMetadata,
    ScanResult,
    ScanStatus,
    ScanSummary,
    Severity,
)


def _finding(**overrides: object) -> Finding:
    base: dict[str, object] = {
        "finding_id": "abc123",
        "rule_id": "LLM001",
        "rule_version": "1.0.0",
        "title": "t",
        "description": "d",
        "category": Category.LLM,
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "location": Location(file_path="a\\b.py", start_line=3, end_line=3),
        "evidence_summary": "s",
        "impact": "i",
        "remediation": "r",
        "analyzer": "dataflow",
        "fingerprint": "f" * 64,
    }
    base.update(overrides)
    return Finding(**base)  # type: ignore[arg-type]


def test_severity_ordering() -> None:
    assert (
        Severity.CRITICAL.rank
        > Severity.HIGH.rank
        > Severity.MEDIUM.rank
        > Severity.LOW.rank
        > Severity.INFORMATIONAL.rank
    )
    assert Severity.HIGH.at_least(Severity.MEDIUM)
    assert not Severity.LOW.at_least(Severity.HIGH)


def test_location_normalises_backslashes() -> None:
    assert _finding().location.file_path == "a/b.py"


def test_rule_id_pattern_enforced() -> None:
    with pytest.raises(ValidationError):
        _finding(rule_id="bad-id")


def test_cwe_ids_validated() -> None:
    assert _finding(cwe_ids=["CWE-78"]).cwe_ids == ["CWE-78"]
    with pytest.raises(ValidationError):
        _finding(cwe_ids=["78"])


def test_unknown_fields_rejected() -> None:
    with pytest.raises(ValidationError):
        _finding(unexpected="x")


def test_suppressed_finding_is_not_active() -> None:
    assert _finding().is_active
    assert not _finding(status=FindingStatus.SUPPRESSED).is_active


def test_scan_result_round_trip() -> None:
    now = datetime.now(UTC)
    result = ScanResult(
        status=ScanStatus.SUCCESS,
        metadata=ScanMetadata(
            tool_version="0.1.0",
            started_at=now,
            finished_at=now,
            duration_ms=1,
            root="/x",
            profiles=["all"],
        ),
        summary=ScanSummary(),
        findings=[_finding()],
    )
    text = result.model_dump_json()
    parsed = ScanResult.model_validate_json(text)
    assert parsed.findings[0].fingerprint == "f" * 64
    assert parsed.is_clean is False
    assert (
        ScanResult.model_validate_json(
            text.replace('"total_findings":0', '"total_findings":0')
        ).status
        is ScanStatus.SUCCESS
    )
