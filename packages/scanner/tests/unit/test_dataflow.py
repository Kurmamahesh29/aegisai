"""Taint analysis unit tests."""

from __future__ import annotations

import textwrap
from pathlib import Path

from aegisai.analyzers.dataflow import (
    DataflowResult,
    FunctionRole,
    SinkKind,
    SourceKind,
    analyze_module,
    is_secret_name,
)
from aegisai.analyzers.python_ast import parse_module


def analyze(code: str) -> DataflowResult:
    source = textwrap.dedent(code).lstrip("\n")
    return analyze_module(parse_module(Path("app.py"), "app.py", source))


def test_user_input_to_shell_flow_with_path() -> None:
    result = analyze(
        """
        import subprocess
        from flask import request

        def run():
            host = request.args.get("host")
            cmd = "ping " + host
            subprocess.run(cmd, shell=True)
        """
    )
    flows = result.flows_matching({SourceKind.USER_INPUT}, {SinkKind.SHELL_EXEC})
    assert len(flows) == 1
    flow = flows[0]
    assert flow.sink.shell is True
    assert flow.source.via == ("host", "cmd")
    assert flow.guards == []


def test_llm_output_source_and_attribute_chain() -> None:
    result = analyze(
        """
        from openai import OpenAI
        client = OpenAI()

        def go(q):
            r = client.chat.completions.create(model="x", messages=[{"role": "user", "content": q}])
            text = r.choices[0].message.content
            eval(text)
        """
    )
    flows = result.flows_matching({SourceKind.LLM_OUTPUT}, {SinkKind.CODE_EXEC})
    assert len(flows) == 1
    assert ".choices" in flows[0].source.via


def test_strong_and_weak_guards() -> None:
    result = analyze(
        """
        import subprocess
        from langchain_core.tools import tool

        @tool
        def strong(service: str) -> str:
            if service not in {"api", "worker"}:
                raise ValueError
            return subprocess.run(["systemctl", "status", service]).stdout

        @tool
        def weak(cmd: str) -> str:
            if "rm" in cmd:
                raise ValueError
            return subprocess.run(cmd, shell=True).stdout
        """
    )
    by_function = {
        f.function.name: f
        for f in result.flows_matching({SourceKind.TOOL_PARAM}, {SinkKind.SHELL_EXEC})
    }
    assert by_function["strong"].guards and by_function["strong"].guards[0].strong
    assert by_function["weak"].guards and not by_function["weak"].guards[0].strong
    assert by_function["strong"].sink.arg_form == "list_other"


def test_lookup_into_untainted_table_is_clean() -> None:
    result = analyze(
        """
        import subprocess
        from flask import request
        TABLE = {"a": ["ls"]}

        def go():
            key = request.args["k"]
            subprocess.run(TABLE[key])
            subprocess.run(TABLE.get(key))
        """
    )
    assert result.flows_matching({SourceKind.USER_INPUT}, {SinkKind.SHELL_EXEC}) == []
    assert len(result.flows_matching({SourceKind.USER_INPUT}, {SinkKind.DYNAMIC_DISPATCH})) == 0


def test_dynamic_dispatch_on_tainted_key_when_called() -> None:
    result = analyze(
        """
        from flask import request
        TOOLS = {}

        def go():
            name = request.args["n"]
            TOOLS[name]()
            getattr(object(), name)
        """
    )
    kinds = [
        (f.sink.argument)
        for f in result.flows_matching({SourceKind.USER_INPUT}, {SinkKind.DYNAMIC_DISPATCH})
    ]
    assert "subscript key" in kinds
    assert "arg1" in kinds


def test_sanitizer_removes_taint() -> None:
    result = analyze(
        """
        import shlex, subprocess
        from flask import request

        def go():
            arg = shlex.quote(request.args["a"])
            subprocess.run("ls " + arg, shell=True)
            n = int(request.args["n"])
            subprocess.run(f"sleep {n}", shell=True)
        """
    )
    assert result.flows_matching({SourceKind.USER_INPUT}, {SinkKind.SHELL_EXEC}) == []


def test_roles_and_typed_params() -> None:
    result = analyze(
        """
        from typing import Literal
        from mcp.server.fastmcp import FastMCP
        from langchain_core.tools import tool
        mcp = FastMCP("x")

        @mcp.tool()
        def a(path: str, count: int, mode: Literal["r", "w"]) -> str:
            return path

        @tool
        def b(x: str) -> str:
            return x

        def helper(y):
            return y
        """
    )
    roles = {f.name: f.role for f in result.functions}
    assert roles["a"] is FunctionRole.MCP_TOOL
    assert roles["b"] is FunctionRole.TOOL
    assert roles["helper"] is FunctionRole.OTHER
    a = next(f for f in result.functions if f.name == "a")
    assert set(a.tainted_params) == {"path"}
    assert "mcp" in result.mcp_instances


def test_secret_sources() -> None:
    result = analyze(
        """
        import os, logging
        log = logging.getLogger()
        API_KEY = "sk-live-FAKE000000000000000000000000"

        def go(password):
            token = os.environ["AUTH_TOKEN"]
            log.info(token)
            log.info(API_KEY)
            print(password)
            print(os.getenv("MAX_TOKENS"))
        """
    )
    flows = result.flows_matching({SourceKind.SECRET_VALUE}, {SinkKind.LOGGING})
    labels = sorted(f.source.label for f in flows)
    assert 'os.environ["AUTH_TOKEN"]' in labels
    assert "hard-coded literal" in labels
    assert any(f.source.name_based for f in flows)
    assert len(flows) == 3


def test_secret_name_heuristics() -> None:
    assert is_secret_name("OPENAI_API_KEY")
    assert is_secret_name("db_password")
    assert is_secret_name("token")
    assert not is_secret_name("max_tokens")
    assert not is_secret_name("tokenizer")
    assert not is_secret_name("public_key")
    assert not is_secret_name("secret_name")


def test_retrieval_and_tool_sources() -> None:
    result = analyze(
        """
        import subprocess
        from langchain_core.tools import tool

        @tool
        def fetch(url: str) -> str:
            return url

        def go(store, retriever):
            docs = store.similarity_search("q")
            subprocess.run(docs[0].page_content, shell=True)
            ctx = retriever.invoke("q")
            eval(ctx)
            page = fetch.invoke("x")
            exec(page)
        """
    )
    assert (
        len(
            result.flows_matching(
                {SourceKind.RETRIEVED_CONTENT}, {SinkKind.SHELL_EXEC, SinkKind.CODE_EXEC}
            )
        )
        == 2
    )
    assert len(result.flows_matching({SourceKind.TOOL_OUTPUT}, {SinkKind.CODE_EXEC})) == 1


def test_route_return_is_http_response_sink() -> None:
    result = analyze(
        """
        from fastapi import FastAPI
        app = FastAPI()

        @app.get("/s")
        def s(q: str, index):
            hits = index.query(q)
            return {"hits": hits}
        """
    )
    flows = result.flows_matching({SourceKind.RETRIEVED_CONTENT}, {SinkKind.HTTP_RESPONSE})
    assert len(flows) == 1
    assert result.functions_with_role(FunctionRole.ROUTE)[0].name == "s"


def test_rule_errors_do_not_occur_on_odd_syntax() -> None:
    result = analyze(
        """
        async def f(*args, **kwargs):
            async with ctx() as c:
                async for item in c:
                    match item:
                        case 1:
                            pass
            x = [y for y in args if y]
            return (z := kwargs)
        """
    )
    assert result.functions


def test_secret_does_not_survive_request_or_helper_calls() -> None:
    """A response/status code/session derived from a call that received a secret is not a secret."""
    result = analyze(
        """
        import os, requests

        def auth(cfg):
            password = cfg["password"]
            token_url = cfg["token_url"]
            data = {"password": password}
            resp = requests.post(token_url, data=data)
            print(resp.status_code)
            session = login(password)
            print(session.id)
            print(token_url)
        """
    )
    assert result.flows_matching({SourceKind.SECRET_VALUE}, {SinkKind.LOGGING}) == []


def test_secret_survives_encoding_and_formatting() -> None:
    result = analyze(
        """
        import base64, os, logging
        log = logging.getLogger()

        def go():
            token = os.environ["API_TOKEN"]
            log.info("Bearer {}".format(token))
            log.info(base64.b64encode(token.encode()))
            log.info(" ".join(["key", token]))
        """
    )
    assert len(result.flows_matching({SourceKind.SECRET_VALUE}, {SinkKind.LOGGING})) == 3


def test_descriptive_secret_names_are_not_secrets() -> None:
    for name in ("token_url", "password_field", "api_key_header", "secret_path", "token_count"):
        assert not is_secret_name(name), name
    for name in ("access_token", "client_secret", "db_password", "api_key"):
        assert is_secret_name(name), name
    # The secret word must end the name: "expected_token_use" describes a token, not a secret.
    assert not is_secret_name("expected_token_use")


def test_destructive_call_heuristic_uses_whole_words() -> None:
    from aegisai.analyzers.dataflow import is_destructive_call

    assert is_destructive_call("requests.delete", "delete")
    assert is_destructive_call("db.drop_table", "drop_table")
    assert not is_destructive_call("langgraph.config.get_stream_writer", "get_stream_writer")
    assert not is_destructive_call("langchain_core.messages.RemoveMessage", "RemoveMessage")


def test_path_constructor_is_not_a_sink_but_path_operations_are() -> None:
    result = analyze(
        """
        from pathlib import Path
        from langchain_core.tools import tool

        @tool
        def a(name: str) -> str:
            p = Path(name)
            return str(p)

        @tool
        def b(name: str) -> str:
            return Path(name).read_text()
        """
    )
    by_function = {
        f.function.name
        for f in result.flows_matching({SourceKind.TOOL_PARAM}, {SinkKind.FILE_PATH})
    }
    assert by_function == {"b"}


def test_yaml_loader_classification() -> None:
    from aegisai.analyzers.dataflow import is_unsafe_yaml_loader

    assert is_unsafe_yaml_loader("yaml.Loader")
    assert is_unsafe_yaml_loader("yaml.FullLoader")
    assert not is_unsafe_yaml_loader("yaml.SafeLoader")
    assert not is_unsafe_yaml_loader("yaml.BaseLoader")
    assert not is_unsafe_yaml_loader("_FrontmatterLoader")
