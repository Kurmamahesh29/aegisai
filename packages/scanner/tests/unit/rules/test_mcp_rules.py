"""Positive and negative tests for MCP001-MCP005."""

from __future__ import annotations

from aegisai.models.configuration import Profile
from aegisai.models.finding import Confidence, Severity
from conftest import findings_for, rule_ids, scan_code, scan_dir

MCP = [Profile.MCP]


def test_mcp001_python_positive(project) -> None:
    code = """
        import subprocess, sqlite3
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("x")

        @mcp.tool()
        def run(command: str) -> str:
            return subprocess.run(command, shell=True).stdout

        @mcp.tool()
        async def query(sql: str) -> list:
            return sqlite3.connect("db").execute(sql).fetchall()
    """
    found = findings_for(scan_code(project, code, profiles=MCP), "MCP001")
    assert {f.location.start_line: f.severity for f in found} == {
        7: Severity.CRITICAL,
        11: Severity.HIGH,
    }


def test_mcp001_lowlevel_call_tool_handler(project) -> None:
    code = """
        import os
        from mcp.server import Server
        server = Server("x")

        @server.call_tool()
        async def call_tool(name: str, arguments: dict):
            os.remove(arguments["path"])
    """
    assert len(findings_for(scan_code(project, code, profiles=MCP), "MCP001")) == 1


def test_mcp001_typescript_heuristic(project) -> None:
    root = project(
        {
            "server.ts": """
                import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
                import { execSync } from "node:child_process";
                const server = new McpServer({ name: "x", version: "1" });
                server.tool("run", {}, async ({ command }) => {
                  return execSync(`sh -c "${command}"`);
                });
            """,
            "other.ts": """
                import { execSync } from "node:child_process";
                execSync("ls");
            """,
        }
    )
    found = findings_for(scan_dir(root, profiles=MCP), "MCP001")
    assert (
        len(found) == 1
        and found[0].location.file_path == "server.ts"
        and found[0].confidence is Confidence.MEDIUM
    )


def test_mcp001_negative(project) -> None:
    code = """
        import subprocess
        from pathlib import Path
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("x")
        ROOT = Path("/data").resolve()
        REPORTS = {"daily", "weekly"}

        @mcp.tool()
        def read(name: str) -> str:
            if name not in REPORTS:
                raise ValueError
            return (ROOT / f"{name}.txt").read_text()

        @mcp.tool()
        def count(n: int) -> str:
            return subprocess.run(["sleep", str(n)]).stdout
    """
    assert "MCP001" not in rule_ids(scan_code(project, code, profiles=MCP))


def test_mcp002_python_exec_tool(project) -> None:
    code = """
        import subprocess
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("x")

        @mcp.tool(name="execute_command")
        def execute(command: str) -> str:
            return subprocess.run(command, shell=True).stdout

        @mcp.tool()
        def list_dir(path: str) -> str:
            return subprocess.run(["ls", path]).stdout
    """
    found = findings_for(scan_code(project, code, profiles=MCP), "MCP002")
    assert len(found) == 1 and "execute_command" in found[0].evidence_summary


def test_mcp002_and_mcp003_config(project) -> None:
    root = project(
        {
            ".cursor/mcp.json": """
                {
                  // comment allowed in JSONC
                  "mcpServers": {
                    "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\\\"], "autoApprove": ["write_file"]},
                    "sh": {"command": "sh", "args": ["-c", "run --yolo"], "alwaysAllow": true},
                    "gh": {"command": "npx", "args": ["x"], "env": {"GITHUB_TOKEN": "ghp_FAKE000000000000000000000000000000ABCD", "LOG_LEVEL": "debug"}},
                    "remote": {"url": "http://10.0.0.5:8000/sse", "headers": {"Authorization": "Bearer FAKEFAKEFAKEFAKE1234"}},
                  }
                }
            """
        }
    )
    result = scan_dir(root, profiles=MCP)
    mcp002 = findings_for(result, "MCP002")
    summaries = {f.evidence_summary for f in mcp002}
    assert any("filesystem server rooted" in s for s in summaries)
    assert any("auto-approves destructive" in s for s in summaries)
    assert any("launched through a shell" in s for s in summaries)
    assert any("--yolo" in s for s in summaries)
    assert any("approves all tool calls" in s for s in summaries)
    mcp003 = findings_for(result, "MCP003")
    assert {f.evidence_summary.split(":")[1].strip().split(" (")[0] for f in mcp003} == {
        "github token in env.GITHUB_TOKEN",
        "credential in header Authorization",
    }
    assert "ghp_FAKE" not in result.model_dump_json()
    assert "SEC001" not in rule_ids(result)
    mcp005 = findings_for(result, "MCP005")
    assert len(mcp005) == 1 and "cleartext" in mcp005[0].evidence_summary


def test_mcp003_negative(project) -> None:
    root = project(
        {
            "mcp.json": """
                {"mcpServers": {"gh": {"command": "npx", "env": {"GITHUB_TOKEN": "${env:GITHUB_TOKEN}", "API_KEY": "<your-key>"},
                 "headers": {"Authorization": "Bearer ${input:token}"}, "url": "https://mcp.example.com/mcp"}}}
            """
        }
    )
    result = scan_dir(root, profiles=MCP)
    assert rule_ids(result) == set()


def test_mcp004_positive_and_transport_sensitivity(project) -> None:
    code = """
        import os
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("x")

        @mcp.tool()
        def wipe(path: str) -> str:
            os.remove(path)
            return "ok"

        if __name__ == "__main__":
            mcp.run(transport="streamable-http")
    """
    found = findings_for(scan_code(project, code, profiles=MCP), "MCP004")
    assert len(found) == 1 and found[0].severity is Severity.MEDIUM and found[0].review_required
    stdio = code.replace('transport="streamable-http"', 'transport="stdio"')
    found_stdio = findings_for(scan_code(project, stdio, profiles=MCP), "MCP004")
    assert len(found_stdio) == 1 and found_stdio[0].severity is Severity.LOW


def test_mcp004_negative_with_auth(project) -> None:
    code = """
        import os
        from mcp.server.auth.settings import AuthSettings
        from mcp.server.fastmcp import FastMCP, Context
        mcp = FastMCP("x", auth=AuthSettings(issuer_url="https://a", resource_server_url="https://b"))

        @mcp.tool()
        def wipe(path: str, ctx: Context) -> str:
            os.remove(path)
            return "ok"
    """
    assert "MCP004" not in rule_ids(scan_code(project, code, profiles=MCP))
    code2 = """
        import os
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("x")

        @mcp.tool()
        def wipe(path: str, ctx) -> str:
            # authorization is checked below
            if not has_permission(ctx, "wipe"):
                raise PermissionError
            os.remove(path)
            return "ok"
    """
    assert "MCP004" not in rule_ids(scan_code(project, code2, profiles=MCP))


def test_mcp005_python(project) -> None:
    code = """
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("x", host="0.0.0.0", port=9000)
        mcp.settings.host = "0.0.0.0"
        mcp.run(transport="sse")
    """
    found = findings_for(scan_code(project, code, profiles=MCP), "MCP005")
    assert len(found) == 3
    assert sum(1 for f in found if f.severity is Severity.HIGH) == 2


def test_mcp005_negative(project) -> None:
    code = """
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("x", host="127.0.0.1")
        mcp.run(transport="stdio")
    """
    assert "MCP005" not in rule_ids(scan_code(project, code, profiles=MCP))
    plain = """
        import uvicorn
        uvicorn.run("app:app", host="0.0.0.0")
    """
    assert "MCP005" not in rule_ids(scan_code(project, plain, profiles=MCP))
