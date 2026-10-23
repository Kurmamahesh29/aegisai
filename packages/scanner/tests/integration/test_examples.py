"""End-to-end scans of the example applications shipped in ``examples/``."""

from __future__ import annotations

import pytest

from aegisai.models.finding import Severity
from aegisai.models.scan import ExitCode, ScanStatus
from conftest import EXAMPLES, findings_for, rule_ids, scan_dir

pytestmark = pytest.mark.integration


@pytest.mark.skipif(not EXAMPLES.exists(), reason="examples directory not present")
def test_vulnerable_llm_app() -> None:
    result = scan_dir(EXAMPLES / "vulnerable-llm-app")
    assert result.status is ScanStatus.SUCCESS
    assert {"SEC001", "SEC002", "SEC003", "CFG001", "LLM001", "LLM003", "LLM004"} <= rule_ids(
        result
    )
    assert result.summary.exit_code == ExitCode.FINDINGS_AT_THRESHOLD
    llm001 = findings_for(result, "LLM001")[0]
    assert llm001.location.file_path == "app.py" and llm001.location.start_line == 37
    assert llm001.severity is Severity.CRITICAL
    assert "sk-proj-FAKE" not in result.model_dump_json()


@pytest.mark.skipif(not EXAMPLES.exists(), reason="examples directory not present")
def test_vulnerable_rag_app() -> None:
    result = scan_dir(EXAMPLES / "vulnerable-rag-app")
    assert {"RAG001", "RAG002", "RAG003", "RAG004"} <= rule_ids(result)
    rag003 = sorted(findings_for(result, "RAG003"), key=lambda f: f.location.start_line)
    assert [f.location.start_line for f in rag003] == [43, 46]


@pytest.mark.skipif(not EXAMPLES.exists(), reason="examples directory not present")
def test_vulnerable_agent_app() -> None:
    result = scan_dir(EXAMPLES / "vulnerable-agent-app")
    assert {"AGT001", "AGT002", "AGT003", "AGT004", "LLM002"} <= rule_ids(result)
    agt001 = findings_for(result, "AGT001")
    assert any(f.location.start_line == 21 and f.severity is Severity.CRITICAL for f in agt001)


@pytest.mark.skipif(not EXAMPLES.exists(), reason="examples directory not present")
def test_vulnerable_mcp_server() -> None:
    result = scan_dir(EXAMPLES / "vulnerable-mcp-server")
    assert {"MCP001", "MCP002", "MCP003", "MCP004", "MCP005"} <= rule_ids(result)
    files = {f.location.file_path for f in result.findings}
    assert {"server.py", "server.ts", "claude_desktop_config.json"} <= files
    assert "SEC001" not in rule_ids(result)  # MCP003 supersedes SEC001 inside MCP config
    assert "ghp_FAKE" not in result.model_dump_json()


@pytest.mark.skipif(not EXAMPLES.exists(), reason="examples directory not present")
def test_secure_examples_are_clean() -> None:
    result = scan_dir(EXAMPLES / "secure-examples")
    assert result.findings == [], [f.evidence_summary for f in result.findings]
    assert result.is_clean
    assert result.summary.exit_code == ExitCode.SUCCESS


@pytest.mark.skipif(not EXAMPLES.exists(), reason="examples directory not present")
def test_profiles_limit_rule_packs() -> None:
    from aegisai.models.configuration import Profile

    result = scan_dir(EXAMPLES, profiles=[Profile.MCP])
    assert all(f.rule_id.startswith("MCP") for f in result.findings)
    assert any(s.rule_id == "LLM001" for s in result.skipped_rules)
