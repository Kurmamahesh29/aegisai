"""Reporter tests: JSON schema conformance, SARIF structure, HTML escaping, terminal output."""

from __future__ import annotations

import io
import json
from pathlib import Path

import jsonschema

from aegisai.engine.registry import default_registry
from aegisai.models.configuration import Profile
from aegisai.reporters import build_sarif, render_html, render_json, render_terminal, write_schemas
from aegisai.reporters.json_report import parse_json, scan_result_schema
from aegisai.reporters.sarif import FINGERPRINT_KEY
from conftest import scan_dir

VULNERABLE = """
import subprocess
from flask import request

def ping():
    host = request.args.get("host")  # aegisai: ignore[SEC003] reason="fixture"
    subprocess.check_output("ping " + host, shell=True)

def other():
    subprocess.check_output("ping " + request.args["h"], shell=True)
"""


def _result(project):
    root = project({"app.py": VULNERABLE, "x.html": "<script>alert(1)</script>"})
    return scan_dir(root, profiles=[Profile.CODE])


def test_json_report_validates_against_schema(project) -> None:
    result = _result(project)
    text = render_json(result)
    payload = json.loads(text)
    jsonschema.validate(payload, scan_result_schema())
    parsed = parse_json(text)
    assert parsed.summary.total_findings == result.summary.total_findings == 2
    assert parsed.findings[0].status.value in {"new", "suppressed"}


def test_schema_files_are_written(tmp_path: Path) -> None:
    written = write_schemas(tmp_path)
    assert {p.name for p in written} == {"scan-result.schema.json", "finding.schema.json"}
    data = json.loads(written[0].read_text(encoding="utf-8"))
    assert data["$schema"].startswith("https://json-schema.org/")


def test_sarif_structure(project) -> None:
    result = _result(project)
    sarif = build_sarif(result, default_registry().metadata())
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "AegisAI" and driver["version"]
    rule_ids = [r["id"] for r in driver["rules"]]
    assert len(rule_ids) == len(set(rule_ids)) >= 23
    assert run["originalUriBaseIds"]["%SRCROOT%"]["uri"].startswith("file:///")
    results = run["results"]
    assert len(results) == 2
    for item in results:
        assert item["ruleId"] == rule_ids[item["ruleIndex"]]
        assert item["level"] in {"error", "warning", "note"}
        location = item["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
        assert location["artifactLocation"]["uri"] == "app.py"
        assert location["region"]["startLine"] >= 1
        assert FINGERPRINT_KEY in item["partialFingerprints"]
        assert item["baselineState"] in {"new", "unchanged"}
    suppressed = [r for r in results if "suppressions" in r]
    assert len(suppressed) == 1 and suppressed[0]["suppressions"][0]["justification"] == "fixture"
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is True
    assert invocation["exitCode"] == 1
    json.dumps(sarif)  # must be serialisable


def test_sarif_reports_analyzer_failures(project) -> None:
    result = _result(project)
    from aegisai.models.scan import AnalyzerResult, AnalyzerStatus

    result.analyzers.append(
        AnalyzerResult(name="gitleaks", status=AnalyzerStatus.UNAVAILABLE, message="missing")
    )
    sarif = build_sarif(result, default_registry().metadata())
    notes = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert any("gitleaks" in n["message"]["text"] for n in notes)


def test_html_escapes_content(project) -> None:
    result = _result(project)
    result.findings[0].title = "<script>alert('x')</script>"
    html = render_html(result)
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
    assert "app.py" in html


def test_terminal_quiet_and_full(project) -> None:
    result = _result(project)
    quiet = io.StringIO()
    render_terminal(result, stream=quiet, color=False, quiet=True)
    assert "exit code: 1" in quiet.getvalue()
    assert "\n" in quiet.getvalue() and quiet.getvalue().count("\n") <= 2
    full = io.StringIO()
    render_terminal(result, stream=full, color=False, verbose=True)
    text = full.getvalue()
    assert "SEC003" in text and "suppressed" in text and "Skipped rules" in text
