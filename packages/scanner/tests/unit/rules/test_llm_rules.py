"""Positive and negative tests for LLM001-LLM004."""

from __future__ import annotations

from aegisai.models.configuration import Profile
from aegisai.models.finding import Confidence, Severity
from conftest import findings_for, rule_ids, scan_code

LLM = [Profile.LLM]


def test_llm001_shell_and_sql(project) -> None:
    code = """
        import subprocess, sqlite3
        from openai import OpenAI
        client = OpenAI()

        def act(q):
            r = client.chat.completions.create(model="m", messages=[{"role": "user", "content": q}])
            cmd = r.choices[0].message.content
            subprocess.run(cmd, shell=True)
            sqlite3.connect("x").cursor().execute("SELECT * FROM t WHERE n = '" + cmd + "'")
    """
    found = findings_for(scan_code(project, code, profiles=LLM), "LLM001")
    assert [f.severity for f in sorted(found, key=lambda f: f.location.start_line)] == [
        Severity.CRITICAL,
        Severity.HIGH,
    ]
    assert all(f.confidence is Confidence.HIGH for f in found)


def test_llm001_langchain_and_anthropic(project) -> None:
    code = """
        import os, requests
        from anthropic import Anthropic
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI()
        client = Anthropic()

        def a(q):
            answer = llm.invoke(q).content
            requests.get(answer)

        def b(q):
            msg = client.messages.create(model="m", max_tokens=10, messages=[{"role": "user", "content": q}])
            os.remove(msg.content[0].text)
    """
    found = findings_for(scan_code(project, code, profiles=LLM), "LLM001")
    assert len(found) == 2


def test_llm001_negative_validated_or_table_dispatch(project) -> None:
    code = """
        import subprocess
        from openai import OpenAI
        client = OpenAI()
        ACTIONS = {"status": ["git", "status"]}

        def act(q):
            r = client.chat.completions.create(model="m", messages=[{"role": "user", "content": q}])
            choice = r.choices[0].message.content
            if choice not in ACTIONS:
                return
            subprocess.run(ACTIONS[choice])
            ACTIONS[choice]()
    """
    assert "LLM001" not in rule_ids(scan_code(project, code, profiles=LLM))


def test_llm001_weak_guard_lowers_confidence(project) -> None:
    code = """
        import subprocess
        from openai import OpenAI
        client = OpenAI()

        def act(q):
            cmd = client.chat.completions.create(model="m", messages=[]).choices[0].message.content
            if is_safe(cmd):
                subprocess.run(cmd, shell=True)
    """
    found = findings_for(scan_code(project, code, profiles=LLM), "LLM001")
    assert len(found) == 1 and found[0].confidence is Confidence.MEDIUM and found[0].review_required


def test_llm002_positive(project) -> None:
    code = """
        from flask import request
        from langchain_community.tools import ShellTool
        shell = ShellTool()

        def handle(store):
            shell.run(request.json["message"])
            docs = store.similarity_search("x")
            search_tool.invoke(docs[0].page_content)
    """
    found = findings_for(scan_code(project, code, profiles=LLM), "LLM002")
    assert len(found) == 2
    shell_finding = next(f for f in found if "shell" in f.evidence_summary)
    assert shell_finding.severity is Severity.HIGH and shell_finding.confidence is Confidence.HIGH


def test_llm002_negative(project) -> None:
    code = """
        from flask import request
        from langchain_community.tools import ShellTool
        shell = ShellTool()
        ALLOWED = {"uptime", "df -h"}

        def handle():
            cmd = request.json["message"]
            if cmd in ALLOWED:
                shell.run(cmd)
            shell.run("uptime")
    """
    assert "LLM002" not in rule_ids(scan_code(project, code, profiles=LLM))


def test_llm003_positive(project) -> None:
    code = """
        import os
        from openai import OpenAI
        from langchain_core.messages import SystemMessage
        client = OpenAI()
        DB_PASSWORD = os.environ["DB_PASSWORD"]

        def ask(q):
            client.chat.completions.create(model="m", messages=[{"role": "system", "content": f"pw {DB_PASSWORD}"}])
            SystemMessage(content="token: " + os.getenv("AUTH_TOKEN"))
    """
    found = findings_for(scan_code(project, code, profiles=LLM), "LLM003")
    assert {f.location.start_line for f in found} == {8, 9}
    assert all(f.severity is Severity.HIGH for f in found)


def test_llm003_negative(project) -> None:
    code = """
        import os
        from openai import OpenAI
        client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

        def ask(q):
            client.chat.completions.create(model="m", messages=[{"role": "user", "content": q}])
    """
    assert "LLM003" not in rule_ids(scan_code(project, code, profiles=LLM))


def test_llm004_positive(project) -> None:
    code = """
        from flask import Flask, Markup, redirect, render_template_string
        from openai import OpenAI
        app = Flask(__name__)
        client = OpenAI()

        @app.route("/r")
        def r():
            out = client.responses.create(model="m", input="x").output_text
            html = render_template_string("<p>" + out + "</p>")
            redirect(out)
            return Markup(out)
    """
    found = findings_for(scan_code(project, code, profiles=LLM), "LLM004")
    assert len(found) == 3
    assert {f.severity for f in found} == {Severity.HIGH, Severity.MEDIUM}


def test_llm004_negative(project) -> None:
    code = """
        from flask import Flask, jsonify, render_template
        from openai import OpenAI
        from markupsafe import escape
        app = Flask(__name__)
        client = OpenAI()

        @app.route("/r")
        def r():
            out = client.responses.create(model="m", input="x").output_text
            render_template("page.html", answer=out)
            safe = escape(out)
            return jsonify({"answer": out, "safe": str(safe)})
    """
    assert "LLM004" not in rule_ids(scan_code(project, code, profiles=LLM))
