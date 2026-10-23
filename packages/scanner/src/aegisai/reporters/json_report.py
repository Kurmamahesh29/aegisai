"""JSON report: the ScanResult model serialised verbatim, plus JSON Schema export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegisai.models.finding import Finding
from aegisai.models.scan import ScanResult


def render_json(result: ScanResult, *, indent: int = 2) -> str:
    return result.model_dump_json(indent=indent, exclude_none=False)


def write_json(result: ScanResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_json(result) + "\n", encoding="utf-8")


def parse_json(text: str) -> ScanResult:
    """Validate a JSON report back into the model (used by the VS Code extension tests)."""
    return ScanResult.model_validate_json(text)


def scan_result_schema() -> dict[str, Any]:
    schema = ScanResult.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "https://aegisai.dev/schema/scan-result-1.0.0.json"
    schema["title"] = "AegisAI scan result"
    return schema


def finding_schema() -> dict[str, Any]:
    schema = Finding.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "https://aegisai.dev/schema/finding-1.0.0.json"
    schema["title"] = "AegisAI finding"
    return schema


def write_schemas(directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    outputs = {
        "scan-result.schema.json": scan_result_schema(),
        "finding.schema.json": finding_schema(),
    }
    written: list[Path] = []
    for name, schema in outputs.items():
        target = directory / name
        target.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(target)
    return written
