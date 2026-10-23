"""External scanner integration tests using monkeypatching and fake executables."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegisai.discovery.project import build_project_context
from aegisai.exceptions import AnalyzerUnavailableError
from aegisai.integrations import gitleaks as gitleaks_mod
from aegisai.integrations import osv_scanner as osv_mod
from aegisai.integrations import semgrep as semgrep_mod
from aegisai.integrations.gitleaks import GitleaksAnalyzer
from aegisai.integrations.osv_scanner import OsvScannerAnalyzer
from aegisai.integrations.semgrep import SemgrepAnalyzer, validate_rule_sources
from aegisai.integrations.subprocess_runner import CommandResult, resolve_executable, run_command
from aegisai.models.configuration import (
    IntegrationSettings,
    Profile,
    ScanConfiguration,
    ScanSection,
    SemgrepSettings,
)
from aegisai.models.finding import Severity
from aegisai.models.scan import AnalyzerStatus, ExitCode, ScanStatus
from conftest import make_fake_executable, scan_dir

FAKE_SECRET = "ghp_FAKE000000000000000000000000000000ABCD"


def _project(tmp_path: Path, files: dict[str, str]):
    for rel, content in files.items():
        (tmp_path / rel).write_text(content, encoding="utf-8")
    return build_project_context(tmp_path, ScanSection())


# -- subprocess runner -------------------------------------------------------------------


def test_resolve_executable_rejects_relative_and_missing(tmp_path: Path) -> None:
    with pytest.raises(AnalyzerUnavailableError, match="absolute"):
        resolve_executable("gitleaks", "relative/gitleaks")
    with pytest.raises(AnalyzerUnavailableError, match="not found"):
        resolve_executable("gitleaks", str(tmp_path / "missing"))
    with pytest.raises(AnalyzerUnavailableError):
        resolve_executable("definitely-not-a-real-binary-aegisai")


def test_run_command_timeout_and_bounded_output(tmp_path: Path) -> None:
    sleeper = make_fake_executable(tmp_path, "sleeper", "import time; time.sleep(10)")
    result = run_command([str(sleeper)], timeout_seconds=1)
    assert result.timed_out
    chatty = make_fake_executable(tmp_path, "chatty", "import sys; sys.stdout.write('x' * 5000)")
    result = run_command([str(chatty)], timeout_seconds=20, max_output_bytes=100)
    assert result.truncated and len(result.stdout) == 100


def test_run_command_requires_absolute_path() -> None:
    with pytest.raises(AnalyzerUnavailableError):
        run_command(["python", "-c", "pass"])


# -- gitleaks ---------------------------------------------------------------------------


def test_gitleaks_normalises_and_redacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = _project(tmp_path, {"config.py": f'TOKEN = "{FAKE_SECRET}"\n'})
    entries = [
        {
            "Description": "GitHub Personal Access Token",
            "StartLine": 1,
            "EndLine": 1,
            "StartColumn": 9,
            "EndColumn": 50,
            "Match": f'TOKEN = "{FAKE_SECRET}"',
            "Secret": FAKE_SECRET,
            "File": "config.py",
            "RuleID": "github-pat",
        },
        {"bad": "entry"},
    ]

    def fake_run(args, **kwargs):
        report = Path(args[args.index("--report-path") + 1])
        report.write_text(json.dumps(entries), encoding="utf-8")
        return CommandResult(args=args, returncode=0, stdout="", stderr="", duration_ms=5)

    monkeypatch.setattr(
        gitleaks_mod, "resolve_executable", lambda name, explicit=None: str(tmp_path / "gitleaks")
    )
    monkeypatch.setattr(gitleaks_mod, "tool_version", lambda *a, **k: "v8.18.0")
    monkeypatch.setattr(gitleaks_mod, "run_command", fake_run)
    outcome = GitleaksAnalyzer().run(project, IntegrationSettings(), 30)
    assert outcome.result.status is AnalyzerStatus.COMPLETED
    assert len(outcome.findings) == 1 and outcome.warnings
    finding = outcome.findings[0]
    assert finding.rule_id == "SEC001" and finding.analyzer == "gitleaks"
    assert finding.location.file_path == "config.py" and finding.location.start_line == 1
    assert FAKE_SECRET not in finding.model_dump_json()


def test_gitleaks_unavailable_required_marks_scan_incomplete(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    config = ScanConfiguration.model_validate(
        {
            "integrations": {
                "gitleaks": {
                    "enabled": True,
                    "required": True,
                    "executable": str(tmp_path / "nope.exe"),
                },
                "osv_scanner": {"enabled": False},
            }
        }
    )
    result = scan_dir(tmp_path, config=config, no_integrations=False, profiles=[Profile.CODE])
    assert result.status is ScanStatus.INCOMPLETE
    assert result.summary.exit_code == ExitCode.INCOMPLETE
    analyzer = next(a for a in result.analyzers if a.name == "gitleaks")
    assert analyzer.status is AnalyzerStatus.UNAVAILABLE and analyzer.required
    assert not result.is_clean


def test_gitleaks_unavailable_optional_is_warning(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    config = ScanConfiguration.model_validate(
        {
            "integrations": {
                "gitleaks": {"enabled": True, "executable": str(tmp_path / "nope.exe")},
                "osv_scanner": {"enabled": False},
            }
        }
    )
    result = scan_dir(tmp_path, config=config, no_integrations=False, profiles=[Profile.CODE])
    assert result.status is ScanStatus.SUCCESS_WITH_WARNINGS
    assert result.summary.exit_code == ExitCode.SUCCESS
    strict = scan_dir(
        tmp_path,
        config=config,
        no_integrations=False,
        profiles=[Profile.CODE],
        strict_integrations=True,
    )
    assert strict.status is ScanStatus.INCOMPLETE


def test_gitleaks_failure_and_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = _project(tmp_path, {"a.py": "x = 1\n"})
    monkeypatch.setattr(
        gitleaks_mod, "resolve_executable", lambda name, explicit=None: str(tmp_path / "gitleaks")
    )
    monkeypatch.setattr(gitleaks_mod, "tool_version", lambda *a, **k: None)
    monkeypatch.setattr(
        gitleaks_mod,
        "run_command",
        lambda args, **k: CommandResult(
            args=args, returncode=2, stdout="", stderr="bad", duration_ms=1
        ),
    )
    assert (
        GitleaksAnalyzer().run(project, IntegrationSettings(), 30).result.status
        is AnalyzerStatus.FAILED
    )
    monkeypatch.setattr(
        gitleaks_mod,
        "run_command",
        lambda args, **k: CommandResult(
            args=args, returncode=0, stdout="", stderr="", duration_ms=1, timed_out=True
        ),
    )
    assert (
        GitleaksAnalyzer().run(project, IntegrationSettings(), 30).result.status
        is AnalyzerStatus.TIMED_OUT
    )


# -- osv-scanner ------------------------------------------------------------------------


def test_osv_normalisation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = _project(tmp_path, {"requirements.txt": "flask==2.0.1\nrequests==2.25.1\n"})
    payload = {
        "results": [
            {
                "source": {"path": str(tmp_path / "requirements.txt"), "type": "lockfile"},
                "packages": [
                    {
                        "package": {"name": "flask", "version": "2.0.1", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-m2qf-hxjv-5gpq",
                                "aliases": ["CVE-2023-30861"],
                                "summary": "Flask vulnerable to possible disclosure of permanent session cookie",
                                "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                                "affected": [
                                    {
                                        "package": {"name": "flask"},
                                        "ranges": [
                                            {"events": [{"introduced": "0"}, {"fixed": "2.2.5"}]}
                                        ],
                                    }
                                ],
                                "references": [
                                    {
                                        "type": "ADVISORY",
                                        "url": "https://github.com/advisories/GHSA-m2qf-hxjv-5gpq",
                                    }
                                ],
                                "database_specific": {"cwe_ids": ["CWE-539"]},
                            }
                        ],
                        "groups": [{"ids": ["GHSA-m2qf-hxjv-5gpq"], "max_severity": "7.5"}],
                    }
                ],
            }
        ]
    }
    monkeypatch.setattr(
        osv_mod, "resolve_executable", lambda name, explicit=None: str(tmp_path / "osv-scanner")
    )
    monkeypatch.setattr(osv_mod, "tool_version", lambda *a, **k: "osv-scanner version: 2.0.0")
    monkeypatch.setattr(
        osv_mod,
        "run_command",
        lambda args, **k: CommandResult(
            args=args, returncode=1, stdout=json.dumps(payload), stderr="", duration_ms=1
        ),
    )
    outcome = OsvScannerAnalyzer().run(project, IntegrationSettings(), 30)
    assert outcome.result.status is AnalyzerStatus.COMPLETED
    finding = outcome.findings[0]
    assert finding.rule_id == "DEP001" and finding.severity is Severity.HIGH
    assert finding.location.file_path == "requirements.txt" and finding.location.start_line == 1
    assert "2.2.5" in finding.remediation
    assert "CWE-539" in finding.cwe_ids and "CWE-1395" in finding.cwe_ids
    assert any("osv.dev" in r for r in finding.references)


def test_osv_skips_without_manifests_and_reports_unsupported(tmp_path: Path) -> None:
    project = _project(tmp_path, {"a.py": "x = 1\n", "Pipfile": "[packages]\nflask = '*'\n"})
    outcome = OsvScannerAnalyzer().run(project, IntegrationSettings(), 30)
    assert outcome.result.status is AnalyzerStatus.SKIPPED
    assert any("Pipfile" in w.message for w in outcome.warnings)


def test_osv_invalid_output_is_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = _project(tmp_path, {"requirements.txt": "flask\n"})
    monkeypatch.setattr(
        osv_mod, "resolve_executable", lambda name, explicit=None: str(tmp_path / "osv-scanner")
    )
    monkeypatch.setattr(osv_mod, "tool_version", lambda *a, **k: None)
    monkeypatch.setattr(
        osv_mod,
        "run_command",
        lambda args, **k: CommandResult(
            args=args, returncode=127, stdout="", stderr="boom", duration_ms=1
        ),
    )
    assert (
        OsvScannerAnalyzer().run(project, IntegrationSettings(), 30).result.status
        is AnalyzerStatus.FAILED
    )


# -- semgrep ----------------------------------------------------------------------------


def test_semgrep_refuses_registry_and_remote_configs(tmp_path: Path) -> None:
    local = tmp_path / "rules.yaml"
    local.write_text("rules: []\n", encoding="utf-8")
    accepted, rejected = validate_rule_sources(
        ["p/python", "auto", "https://x/y.yaml", "rules.yaml", "missing.yaml"], tmp_path
    )
    assert accepted == [local.resolve()]
    assert len(rejected) == 4


def test_semgrep_normalisation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "rules.yaml").write_text("rules: []\n", encoding="utf-8")
    project = _project(tmp_path, {"a.py": "eval(x)\n"})
    payload = {
        "results": [
            {
                "check_id": "local.python.eval",
                "path": "a.py",
                "start": {"line": 1, "col": 1},
                "end": {"line": 1, "col": 8},
                "extra": {
                    "message": "eval is dangerous",
                    "severity": "ERROR",
                    "lines": "eval(x)",
                    "metadata": {
                        "cwe": ["CWE-95: Eval Injection"],
                        "references": ["https://cwe.mitre.org/data/definitions/95.html"],
                    },
                },
            }
        ],
        "errors": [{"message": "skipped something"}],
    }
    monkeypatch.setattr(
        semgrep_mod, "resolve_executable", lambda name, explicit=None: str(tmp_path / "semgrep")
    )
    monkeypatch.setattr(semgrep_mod, "tool_version", lambda *a, **k: "1.90.0")
    monkeypatch.setattr(
        semgrep_mod,
        "run_command",
        lambda args, **k: CommandResult(
            args=args, returncode=1, stdout=json.dumps(payload), stderr="", duration_ms=1
        ),
    )
    outcome = SemgrepAnalyzer().run(
        project, SemgrepSettings(enabled=True, config=["rules.yaml"]), 30
    )
    assert outcome.result.status is AnalyzerStatus.COMPLETED
    finding = outcome.findings[0]
    assert (
        finding.rule_id == "SMG001"
        and finding.severity is Severity.HIGH
        and "CWE-95" in finding.cwe_ids
    )
    assert finding.review_required
    assert any(w.code == "semgrep_error" for w in outcome.warnings)


def test_semgrep_without_config_is_skipped(tmp_path: Path) -> None:
    project = _project(tmp_path, {"a.py": "x\n"})
    outcome = SemgrepAnalyzer().run(project, SemgrepSettings(enabled=True, config=["p/ci"]), 30)
    assert outcome.result.status is AnalyzerStatus.SKIPPED and outcome.warnings


def test_integration_findings_respect_scan_excludes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gitleaks walks the whole root; findings in excluded paths must be dropped."""
    (tmp_path / "examples").mkdir()
    (tmp_path / "examples" / "fixture.py").write_text(
        f'TOKEN = "{FAKE_SECRET}"\n', encoding="utf-8"
    )
    (tmp_path / "app.py").write_text(f'TOKEN = "{FAKE_SECRET}"\n', encoding="utf-8")
    entries = [
        {
            "Description": "GitHub PAT",
            "StartLine": 1,
            "EndLine": 1,
            "StartColumn": 9,
            "EndColumn": 50,
            "Match": "x",
            "Secret": FAKE_SECRET,
            "File": "examples/fixture.py",
            "RuleID": "github-pat",
        },
        {
            "Description": "GitHub PAT",
            "StartLine": 1,
            "EndLine": 1,
            "StartColumn": 9,
            "EndColumn": 50,
            "Match": "x",
            "Secret": FAKE_SECRET,
            "File": "app.py",
            "RuleID": "github-pat",
        },
    ]

    def fake_run(args, **kwargs):
        Path(args[args.index("--report-path") + 1]).write_text(
            json.dumps(entries), encoding="utf-8"
        )
        return CommandResult(args=args, returncode=0, stdout="", stderr="", duration_ms=1)

    monkeypatch.setattr(
        gitleaks_mod, "resolve_executable", lambda name, explicit=None: str(tmp_path / "gitleaks")
    )
    monkeypatch.setattr(gitleaks_mod, "tool_version", lambda *a, **k: "v8")
    monkeypatch.setattr(gitleaks_mod, "run_command", fake_run)
    config = ScanConfiguration.model_validate(
        {
            "scan": {"exclude": ["examples/**"]},
            "integrations": {"osv_scanner": {"enabled": False}},
            "rules": {"disabled": ["SEC001"]},
        }
    )
    result = scan_dir(tmp_path, config=config, no_integrations=False, profiles=[Profile.SECRETS])
    assert [f.location.file_path for f in result.findings] == ["app.py"]
    assert next(a for a in result.analyzers if a.name == "gitleaks").findings_count == 1
