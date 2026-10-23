"""Positive and negative tests for AGT001-AGT004."""

from __future__ import annotations

from aegisai.models.configuration import Profile
from aegisai.models.finding import Confidence, Severity
from conftest import findings_for, rule_ids, scan_code

AGENTS = [Profile.AGENTS]


def test_agt001_positive_various_frameworks(project) -> None:
    code = """
        import subprocess, sqlite3
        from langchain_core.tools import tool, StructuredTool
        from agents import function_tool

        @tool
        def run(command: str) -> str:
            \"\"\"Run a command.\"\"\"
            return subprocess.check_output(command, shell=True).decode()

        @function_tool
        def query(sql: str) -> str:
            return sqlite3.connect("x").execute(sql).fetchall()

        def registered(path: str) -> str:
            return open(path).read()

        reader = StructuredTool.from_function(registered)
    """
    found = findings_for(scan_code(project, code, profiles=AGENTS), "AGT001")
    by_line = {f.location.start_line: f for f in found}
    assert set(by_line) == {8, 12, 15}
    assert by_line[8].severity is Severity.CRITICAL
    assert by_line[12].severity is Severity.HIGH


def test_agt001_tools_list_registration(project) -> None:
    code = """
        import os
        from pydantic_ai import Agent

        def wipe(path: str) -> None:
            os.remove(path)

        agent = Agent("m", tools=[wipe])
    """
    assert len(findings_for(scan_code(project, code, profiles=AGENTS), "AGT001")) == 1


def test_agt001_negative(project) -> None:
    code = """
        import subprocess
        from typing import Literal
        from langchain_core.tools import tool
        SERVICES = {"api", "worker"}

        @tool
        def status(service: str) -> str:
            if service not in SERVICES:
                raise ValueError("unknown")
            return subprocess.run(["systemctl", "status", service]).stdout

        @tool
        def count(n: int, mode: Literal["a", "b"]) -> str:
            return subprocess.run(["sleep", str(n), mode]).stdout

        def plain(cmd: str) -> str:
            return subprocess.run(cmd, shell=True).stdout
    """
    assert "AGT001" not in rule_ids(scan_code(project, code, profiles=AGENTS))


def test_agt002_positive_and_negative(project) -> None:
    code = """
        import subprocess, requests
        from langchain_core.tools import tool

        @tool
        def deploy(env: str) -> str:
            \"\"\"Deploy to an environment.\"\"\"
            return subprocess.run(["deploy", env]).stdout

        @tool
        def delete_account(account_id: int) -> str:
            \"\"\"Delete an account.\"\"\"
            requests.delete("https://x/" + str(account_id))
            return "ok"

        @tool
        def approved_delete(account_id: int) -> str:
            if not require_approval("delete"):
                return "denied"
            requests.delete("https://x/" + str(account_id))
            return "ok"

        @tool
        def lookup(q: str) -> str:
            \"\"\"Look up weather.\"\"\"
            return requests.get("https://weather/" + q).text
    """
    found = findings_for(scan_code(project, code, profiles=AGENTS), "AGT002")
    names = {f.evidence_summary.split("'")[1] for f in found}
    assert names == {"deploy", "delete_account"}
    assert all(f.review_required for f in found)


def test_agt002_module_marker_suppresses(project) -> None:
    code = """
        import subprocess
        from langchain_core.tools import tool
        from langgraph.prebuilt import create_react_agent

        @tool
        def deploy(env: str) -> str:
            return subprocess.run(["deploy", env]).stdout

        graph = create_react_agent("m", [deploy], interrupt_before=["tools"])
    """
    assert "AGT002" not in rule_ids(scan_code(project, code, profiles=AGENTS))


def test_agt003_positive(project) -> None:
    code = """
        from langchain_community.tools import ShellTool
        from langchain_experimental.tools import PythonREPLTool
        from langchain.agents import load_tools
        from langchain_experimental.agents import create_pandas_dataframe_agent
        from smolagents import CodeAgent
        from langchain_core.tools import tool

        s = ShellTool()
        p = PythonREPLTool()
        t = load_tools(["terminal", "wikipedia"])
        a = create_pandas_dataframe_agent(None, None, allow_dangerous_code=True)
        c = CodeAgent(tools=[], additional_authorized_imports=["*"])

        @tool
        def runner(code: str) -> str:
            \"\"\"Execute arbitrary python code and return the result.\"\"\"
            return code
    """
    found = findings_for(scan_code(project, code, profiles=AGENTS), "AGT003")
    assert len(found) == 6
    assert sum(1 for f in found if f.confidence is Confidence.MEDIUM) == 1


def test_agt003_negative(project) -> None:
    code = """
        from langchain_community.agent_toolkits import FileManagementToolkit
        from langchain.agents import load_tools
        from langchain_core.tools import tool

        fs = FileManagementToolkit(root_dir="/srv/app/data")
        t = load_tools(["wikipedia", "arxiv"])

        @tool
        def weather(city: str) -> str:
            \"\"\"Get the weather for a city.\"\"\"
            return city
    """
    assert "AGT003" not in rule_ids(scan_code(project, code, profiles=AGENTS))


def test_agt004_positive_and_negative(project) -> None:
    code = """
        import subprocess
        from langchain_core.tools import tool

        @tool
        def fetch(url: str) -> str:
            \"\"\"Fetch a page.\"\"\"
            return url

        def research(topic, search_tool):
            page = fetch.invoke(topic)
            exec(page)
            result = search_tool.run(topic)
            subprocess.run(result, shell=True)
            summary = str(len(page))
            exec(summary)
    """
    found = findings_for(scan_code(project, code, profiles=AGENTS), "AGT004")
    assert {f.location.start_line for f in found} == {11, 13}
    assert all(f.review_required for f in found)
