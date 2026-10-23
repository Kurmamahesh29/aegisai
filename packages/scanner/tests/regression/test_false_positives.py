"""Regression tests for false positives fixed during development.

Each test documents the original mis-detection so it cannot silently return.
"""

from __future__ import annotations

from aegisai.models.configuration import Profile
from conftest import rule_ids, scan_code, scan_dir


def test_dict_lookup_on_llm_chosen_key_is_not_llm001(project) -> None:
    """``ALLOWED.get(decision.action)`` returned a tainted value; lookups are now clean."""
    code = """
        import subprocess
        from openai import OpenAI
        client = OpenAI()
        ALLOWED = {"status": ["git", "status"]}

        def act():
            r = client.chat.completions.create(model="m", messages=[])
            command = ALLOWED.get(r.choices[0].message.content)
            if command is None:
                return
            subprocess.run(command)
    """
    assert "LLM001" not in rule_ids(scan_code(project, code, profiles=[Profile.LLM]))


def test_allowlist_membership_before_subprocess_list_is_not_agt001(project) -> None:
    """A membership check on the parameter itself is a strong guard."""
    code = """
        import subprocess
        from langchain_core.tools import tool
        SERVICES = {"api", "worker"}

        @tool
        def status(service: str) -> str:
            if service not in SERVICES:
                raise ValueError("unknown")
            return subprocess.run(["systemctl", "status", service]).stdout
    """
    assert "AGT001" not in rule_ids(scan_code(project, code, profiles=[Profile.AGENTS]))


def test_mcp_path_containment_with_allowlist_is_not_mcp001(project) -> None:
    code = """
        from pathlib import Path
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("x")
        ROOT = Path("/data").resolve()
        NAMES = {"daily"}

        @mcp.tool()
        def read(name: str) -> str:
            if name not in NAMES:
                raise ValueError
            target = (ROOT / f"{name}.txt").resolve()
            if not target.is_relative_to(ROOT):
                raise ValueError
            return target.read_text()
    """
    assert "MCP001" not in rule_ids(scan_code(project, code, profiles=[Profile.MCP]))


def test_returning_ids_from_retrieval_is_not_rag004(project) -> None:
    """Only ids/scores extracted from a retrieval result are not a metadata exposure."""
    code = """
        from fastapi import FastAPI
        app = FastAPI()

        @app.get("/s")
        def search(q: str, collection):
            results = collection.query(query_texts=[q], where={"t": 1})
            return {"citations": results["ids"][0]}
    """
    assert "RAG004" not in rule_ids(scan_code(project, code, profiles=[Profile.RAG]))


def test_comment_mentioning_authorization_does_not_suppress_mcp004(project) -> None:
    """The auth marker used to be matched against raw text, including comments."""
    code = """
        import os
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("x")

        @mcp.tool()
        def wipe(path: str) -> str:
            # TODO: add authorization and authentication here
            os.remove(path)
            return "ok"

        mcp.run(transport="sse")
    """
    ids = rule_ids(scan_code(project, code, profiles=[Profile.MCP]))
    assert "MCP004" in ids and "MCP005" in ids


def test_get_requests_in_tools_are_not_high_impact(project) -> None:
    code = """
        import requests
        from langchain_core.tools import tool

        @tool
        def weather(city: str) -> str:
            \"\"\"Get the weather.\"\"\"
            return requests.get("https://api.weather.example/" + city).text
    """
    assert "AGT002" not in rule_ids(scan_code(project, code, profiles=[Profile.AGENTS]))


def test_mask_output_is_not_remasked_in_summaries(project) -> None:
    root = project(
        {
            "mcp.json": '{"mcpServers": {"gh": {"command": "x", "env": {"GITHUB_TOKEN": "ghp_FAKE000000000000000000000000000000ABCD"}}}}'
        }
    )
    from conftest import findings_for, scan_dir

    result = scan_dir(root, profiles=[Profile.MCP])
    summary = findings_for(result, "MCP003")[0].evidence_summary
    assert summary.count("chars]") == 1


def test_path_like_values_are_not_secrets(project) -> None:
    """package-lock.json "secretlint": "bin/secretlint.js" was reported as SEC001."""
    root = project(
        {
            "package-lock.json": '{"packages": {"node_modules/secretlint": {"bin": {"secretlint": "bin/secretlint.js"}}}}',
            "settings.py": 'PRIVATE_KEY_PATH = "./keys/private_key.pem"\nAPI_KEY_FILE = "C:\\\\secrets\\\\api.key"\n',
        }
    )
    result = scan_dir(root, profiles=[Profile.SECRETS])
    assert rule_ids(result) == set(), [f.evidence_summary for f in result.findings]
