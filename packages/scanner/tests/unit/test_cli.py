"""CLI argument and exit-code tests."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aegisai import __version__
from aegisai.cli import app
from aegisai.models.scan import ExitCode

runner = CliRunner()

VULNERABLE = """
import subprocess
from flask import request

def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping " + host, shell=True)
"""


def _invoke(*args: str):
    return runner.invoke(app, list(args))


def test_version_and_rules_commands() -> None:
    result = _invoke("version")
    assert result.exit_code == 0 and __version__ in result.output
    listing = _invoke("rules", "list")
    assert listing.exit_code == 0 and "LLM001" in listing.output and "23 rule(s)" in listing.output
    filtered = _invoke("rules", "list", "--profile", "mcp")
    assert "MCP001" in filtered.output and "LLM001" not in filtered.output
    as_json = _invoke("rules", "list", "--json")
    assert json.loads(as_json.output)[0]["rule_id"]
    show = _invoke("rules", "show", "llm001")
    assert show.exit_code == 0 and "LLM001" in show.output and "remediation:" in show.output
    unknown = _invoke("rules", "show", "NOPE999")
    assert unknown.exit_code == ExitCode.FAILED


def test_config_init(tmp_path: Path) -> None:
    target = tmp_path / ".aegisai.yaml"
    assert _invoke("config", "init", "--path", str(target)).exit_code == 0
    assert target.exists()
    assert _invoke("config", "init", "--path", str(target)).exit_code == ExitCode.FAILED
    assert _invoke("config", "init", "--path", str(target), "--force").exit_code == 0


def test_scan_exit_codes_and_outputs(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(VULNERABLE, encoding="utf-8")
    json_out = tmp_path / "out" / "report.json"
    sarif_out = tmp_path / "out" / "report.sarif"
    result = _invoke(
        "scan",
        str(tmp_path),
        "--no-integrations",
        "--no-config",
        "--profile",
        "code",
        "--format",
        "json",
        "--format",
        "sarif",
        "--output",
        str(json_out),
        "--output",
        str(sarif_out),
        "--quiet",
    )
    assert result.exit_code == ExitCode.FINDINGS_AT_THRESHOLD, result.output
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["summary"]["exit_code"] == 1 and payload["findings"][0]["rule_id"] == "SEC003"
    sarif = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"

    none = _invoke(
        "scan", str(tmp_path), "--no-integrations", "--no-config", "--fail-on", "none", "--quiet"
    )
    assert none.exit_code == ExitCode.SUCCESS
    critical = _invoke(
        "scan",
        str(tmp_path),
        "--no-integrations",
        "--no-config",
        "--fail-on",
        "critical",
        "--quiet",
    )
    assert (
        critical.exit_code == ExitCode.FINDINGS_AT_THRESHOLD
    )  # shell=True string command is critical
    filtered = _invoke(
        "scan",
        str(tmp_path),
        "--no-integrations",
        "--no-config",
        "--severity",
        "critical",
        "--disable-rule",
        "SEC003",
        "--quiet",
    )
    assert filtered.exit_code == ExitCode.SUCCESS


def test_scan_json_to_stdout_keeps_stdout_clean(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    result = _invoke(
        "scan", str(tmp_path), "--no-integrations", "--no-config", "--format", "json", "--quiet"
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "success" and payload["summary"]["total_findings"] == 0


def test_scan_failure_exit_codes(tmp_path: Path) -> None:
    missing = _invoke("scan", str(tmp_path / "missing"), "--no-integrations", "--no-config")
    assert missing.exit_code == ExitCode.FAILED
    bad_profile = _invoke("scan", str(tmp_path), "--profile", "nope")
    assert bad_profile.exit_code != 0
    bad_config = tmp_path / "bad.yaml"
    bad_config.write_text("scan:\n  unknown: 1\n", encoding="utf-8")
    cfg = _invoke("scan", str(tmp_path), "--config", str(bad_config), "--no-integrations")
    assert cfg.exit_code == ExitCode.FAILED and "unknown" in cfg.output


def test_scan_incomplete_with_required_integration(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / ".aegisai.yaml").write_text(
        "version: 1\nintegrations:\n  gitleaks:\n    enabled: true\n    required: true\n    executable: "
        + json.dumps(str(tmp_path / "missing-gitleaks.exe"))
        + "\n  osv_scanner:\n    enabled: false\n",
        encoding="utf-8",
    )
    result = _invoke("scan", str(tmp_path), "--quiet", "--format", "json")
    assert result.exit_code == ExitCode.INCOMPLETE
    payload = json.loads(result.stdout)
    assert payload["status"] == "incomplete"


def test_baseline_workflow(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(VULNERABLE, encoding="utf-8")
    baseline = tmp_path / "aegis-baseline.json"
    created = _invoke(
        "baseline",
        "create",
        str(tmp_path),
        "--output",
        str(baseline),
        "--no-integrations",
        "--profile",
        "code",
    )
    assert created.exit_code == 0, created.output
    assert json.loads(baseline.read_text(encoding="utf-8"))["entries"]
    rescan = _invoke(
        "scan",
        str(tmp_path),
        "--no-integrations",
        "--no-config",
        "--baseline",
        str(baseline),
        "--quiet",
    )
    assert rescan.exit_code == ExitCode.SUCCESS


def test_exclude_file_and_patterns(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(VULNERABLE, encoding="utf-8")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.py").write_text(VULNERABLE, encoding="utf-8")
    excludes = tmp_path / ".aegisignore"
    excludes.write_text("# comment\nvendor/**\n", encoding="utf-8")
    result = _invoke(
        "scan",
        str(tmp_path),
        "--no-integrations",
        "--no-config",
        "--exclude-file",
        str(excludes),
        "--exclude",
        "app.py",
        "--quiet",
    )
    assert result.exit_code == ExitCode.SUCCESS


def test_doctor_runs() -> None:
    result = _invoke("doctor")
    assert result.exit_code == 0 and "gitleaks" in result.output
