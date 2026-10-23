"""Intra-procedural taint analysis for Python.

The analyzer walks each function once, in statement order, tracking which local names carry
untrusted or sensitive values (``Taint``) and recording every point where such a value reaches
a security-sensitive call (``TaintFlow``).  It also records guards (validation-looking checks
that mention a tainted name) so rules can lower confidence instead of claiming certainty.

Limitations (documented in docs/limitations.md):
- No inter-procedural tracking: calls to local helpers propagate taint from arguments to the
  return value conservatively, but sinks inside helpers are not linked to the caller's sources.
- Loops are analysed in a single pass.
- Guard detection is flow-insensitive within a function and name based.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field, replace
from enum import StrEnum

from aegisai.analyzers.python_ast import (
    PythonModule,
    attribute_tail,
    constant_value,
    decorator_names,
    docstring_of,
    dotted_name,
    get_keyword,
    is_truthy_constant,
    receiver_name,
    string_value,
)


class SourceKind(StrEnum):
    USER_INPUT = "user_input"
    LLM_OUTPUT = "llm_output"
    RETRIEVED_CONTENT = "retrieved_content"
    TOOL_OUTPUT = "tool_output"
    TOOL_PARAM = "tool_param"
    MCP_TOOL_PARAM = "mcp_tool_param"
    SECRET_VALUE = "secret_value"


class SinkKind(StrEnum):
    SHELL_EXEC = "shell_exec"
    CODE_EXEC = "code_exec"
    SQL_EXEC = "sql_exec"
    FILE_PATH = "file_path"
    NETWORK_REQUEST = "network_request"
    DYNAMIC_DISPATCH = "dynamic_dispatch"
    HTML_RENDER = "html_render"
    REDIRECT = "redirect"
    DESERIALIZATION = "deserialization"
    LOGGING = "logging"
    PROMPT = "prompt"
    TOOL_INVOCATION = "tool_invocation"
    HTTP_RESPONSE = "http_response"


DANGEROUS_SINKS: frozenset[SinkKind] = frozenset(
    {
        SinkKind.SHELL_EXEC,
        SinkKind.CODE_EXEC,
        SinkKind.SQL_EXEC,
        SinkKind.FILE_PATH,
        SinkKind.NETWORK_REQUEST,
        SinkKind.DYNAMIC_DISPATCH,
        SinkKind.DESERIALIZATION,
    }
)


class FunctionRole(StrEnum):
    MODULE = "module"
    OTHER = "other"
    TOOL = "tool"
    MCP_TOOL = "mcp_tool"
    MCP_CALL_TOOL_HANDLER = "mcp_call_tool_handler"
    ROUTE = "route"


@dataclass(frozen=True, slots=True)
class Taint:
    kind: SourceKind
    label: str
    line: int
    column: int
    via: tuple[str, ...] = ()
    name_based: bool = False

    def through(self, name: str) -> Taint:
        if len(self.via) >= 8 or (self.via and self.via[-1] == name):
            return self
        return replace(self, via=(*self.via, name))


@dataclass(slots=True)
class Guard:
    description: str
    line: int
    strong: bool = False
    """True for allow-list membership or equality checks on the tainted value itself."""


@dataclass(slots=True)
class SinkMatch:
    kind: SinkKind
    callee: str
    node: ast.AST
    line: int
    column: int
    argument: str
    shell: bool = False
    arg_form: str = "unknown"
    function: FunctionInfo | None = None


@dataclass(slots=True)
class CallInfo:
    name: str
    tail: str
    receiver: str | None
    node: ast.Call
    function: FunctionInfo


@dataclass(slots=True)
class FunctionInfo:
    name: str
    lineno: int
    role: FunctionRole
    node: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    decorators: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    docstring: str = ""
    tool_name: str | None = None
    tool_description: str = ""
    sinks: list[SinkMatch] = field(default_factory=list)
    calls: list[CallInfo] = field(default_factory=list)
    auth_guards: list[Guard] = field(default_factory=list)
    approval_guards: list[Guard] = field(default_factory=list)
    validation_guards: list[Guard] = field(default_factory=list)
    tainted_params: dict[str, SourceKind] = field(default_factory=dict)

    @property
    def end_lineno(self) -> int:
        if self.node is None:
            return self.lineno
        return self.node.end_lineno or self.lineno

    def has_sink(self, *kinds: SinkKind) -> bool:
        wanted = set(kinds)
        return any(s.kind in wanted for s in self.sinks)


@dataclass(slots=True)
class TaintFlow:
    source: Taint
    sink: SinkMatch
    function: FunctionInfo
    guards: list[Guard]
    snippet: str

    @property
    def line(self) -> int:
        return self.sink.line


@dataclass(slots=True)
class DataflowResult:
    module: PythonModule
    functions: list[FunctionInfo]
    flows: list[TaintFlow]
    calls: list[CallInfo]
    module_markers: set[str] = field(default_factory=set)
    mcp_instances: set[str] = field(default_factory=set)
    app_instances: set[str] = field(default_factory=set)

    def flows_matching(self, sources: set[SourceKind], sinks: set[SinkKind]) -> list[TaintFlow]:
        return [f for f in self.flows if f.source.kind in sources and f.sink.kind in sinks]

    def functions_with_role(self, *roles: FunctionRole) -> list[FunctionInfo]:
        wanted = set(roles)
        return [f for f in self.functions if f.role in wanted]


# --------------------------------------------------------------------------------------
# Pattern tables
# --------------------------------------------------------------------------------------

SECRET_NAME = re.compile(
    r"(?i)(?:^|[_\-.])(?:api[_\-]?key|apikey|secret|passw(?:or)?d|passwd|private[_\-]?key|"
    r"access[_\-]?token|auth[_\-]?token|refresh[_\-]?token|bearer[_\-]?token|id[_\-]?token|"
    r"client[_\-]?secret|credentials?|service[_\-]?key|signing[_\-]?key|encryption[_\-]?key|"
    r"master[_\-]?key|session[_\-]?key|secret[_\-]?key|token|api[_\-]?secret|pwd)(?:$|[_\-.])"
)
SECRET_NAME_EXCLUDE = re.compile(
    r"(?i)(max_tokens|num_tokens|token_count|tokens?_used|tokenizer|token_limit|token_type|"
    r"token_usage|public_key|key_name|cache_key|primary_key|foreign_key|secret_name|secret_id|"
    r"secret_path|password_hash|hashed_password|password_field|token_budget|input_tokens|"
    r"output_tokens|total_tokens|prompt_tokens|completion_tokens|tokens$|key_id|keyword|"
    r"api_key_header|api_key_name|key_file|token_ids|token_len|tokenize|_tokens_|"
    r"credential_type|credentials_file|secret_arn|secret_version)"
)


def is_secret_name(name: str) -> bool:
    if not name:
        return False
    if SECRET_NAME_EXCLUDE.search(name):
        return False
    return SECRET_NAME.search(name) is not None


TOOL_DECORATOR_TAILS = {
    "tool",
    "function_tool",
    "kernel_function",
    "tool_plain",
    "register_for_execution",
    "register_for_llm",
    "agent_tool",
}
MCP_DECORATOR_TAILS = {"tool", "call_tool", "resource", "prompt"}
ROUTE_DECORATOR_TAILS = {
    "route",
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "api_route",
    "websocket",
}
APP_FACTORIES = {
    "flask.Flask",
    "Flask",
    "fastapi.FastAPI",
    "FastAPI",
    "fastapi.APIRouter",
    "APIRouter",
    "flask.Blueprint",
    "Blueprint",
    "starlette.applications.Starlette",
}
MCP_FACTORIES = {
    "mcp.server.fastmcp.FastMCP",
    "fastmcp.FastMCP",
    "FastMCP",
    "mcp.server.Server",
    "mcp.server.lowlevel.Server",
    "mcp.server.lowlevel.server.Server",
    "Server",
}
TOOL_REGISTRATION_CALLS = {
    "Tool",
    "langchain.tools.Tool",
    "langchain_core.tools.Tool",
    "langchain.agents.Tool",
    "StructuredTool.from_function",
    "langchain.tools.StructuredTool.from_function",
    "langchain_core.tools.StructuredTool.from_function",
    "FunctionTool.from_defaults",
    "llama_index.core.tools.FunctionTool.from_defaults",
    "FunctionTool",
    "autogen_core.tools.FunctionTool",
    "register_function",
    "autogen.register_function",
    "register_tool",
    "add_tool",
}
TOOL_LIST_KEYWORDS = {"tools", "functions", "toolkit"}

RECV_RETRIEVAL = re.compile(
    r"(?i)(vector|store|retriev|index|collection|chroma|pinecone|qdrant|weaviate|faiss|milvus|"
    r"knowledge|docs|kb|embedding|memory|search_engine|vdb|table)"
)
RETRIEVAL_TAILS = {
    "similarity_search",
    "similarity_search_with_score",
    "similarity_search_with_relevance_scores",
    "similarity_search_by_vector",
    "asimilarity_search",
    "max_marginal_relevance_search",
    "get_relevant_documents",
    "aget_relevant_documents",
    "retrieve",
    "aretrieve",
    "search",
    "query",
    "hybrid_search",
    "vector_search",
    "knn_search",
    "query_points",
    "get",
    "fetch",
    "nearest",
}
RETRIEVAL_FUNCTIONS = {
    "retrieve_documents",
    "retrieve_context",
    "retrieve_docs",
    "get_context",
    "search_documents",
    "search_knowledge_base",
    "query_index",
    "query_vectorstore",
    "query_vector_store",
    "similarity_search",
    "fetch_context",
}
RECV_LLM = re.compile(
    r"(?i)(llm|model|chain|agent|executor|chat|gpt|claude|gemini|runnable|graph|crew|pipeline|"
    r"assistant|bot|workflow|completion|generator|predictor|engine|runner|openai|anthropic|"
    r"client)"
)
LLM_TAILS = {
    "invoke",
    "ainvoke",
    "predict",
    "apredict",
    "generate",
    "agenerate",
    "stream",
    "astream",
    "batch",
    "abatch",
    "run",
    "arun",
    "run_sync",
    "call",
    "kickoff",
    "chat",
    "complete",
    "query",
    "ask",
    "respond",
}
LLM_CALL_NAMES = {
    "litellm.completion",
    "litellm.acompletion",
    "completion",
    "acompletion",
    "ollama.chat",
    "ollama.generate",
    "openai.ChatCompletion.create",
    "openai.Completion.create",
    "google.generativeai.GenerativeModel.generate_content",
    "Runner.run",
    "Runner.run_sync",
    "agents.Runner.run",
    "agents.Runner.run_sync",
}
LLM_CREATE_CHAIN = re.compile(
    r"\.(chat\.completions|completions|messages|responses|beta\.messages)\.create$"
)
LLM_GENERATE_TAILS = {"generate_content", "generate_content_async", "generate_text", "send_message"}

RECV_TOOL = re.compile(r"(?i)(^|[._])tool(s)?($|[._\[])|tool$|Tool\b|REPL|repl|tool_executor")
TOOL_INVOKE_TAILS = {"run", "arun", "invoke", "ainvoke", "call", "func", "execute", "__call__"}
TOOL_INVOKE_NAMES = {
    "execute_tool",
    "run_tool",
    "call_tool",
    "invoke_tool",
    "dispatch_tool",
    "handle_tool_call",
}

SANITIZER_NAMES = {
    "shlex.quote",
    "html.escape",
    "markupsafe.escape",
    "escape",
    "bleach.clean",
    "re.escape",
    "urllib.parse.quote",
    "urllib.parse.quote_plus",
    "quote",
    "werkzeug.utils.secure_filename",
    "secure_filename",
    "int",
    "float",
    "bool",
    "len",
    "hash",
    "abs",
    "round",
    "isinstance",
    "id",
    "uuid.UUID",
    "ipaddress.ip_address",
}
SANITIZER_PREFIX = re.compile(
    r"(?i)^(validate_|sanitize_|sanitise_|clean_|escape_|normalize_|normalise_|ensure_safe|safe_|"
    r"parse_int|to_int|coerce_)"
)
GUARD_CALL = re.compile(
    r"(?i)(validate|sanitize|sanitise|is_safe|is_valid|is_allowed|allowed|permitted|authorized|"
    r"authorised|check|verify|confirm|approve|match|fullmatch|startswith|endswith|isalnum|"
    r"isdigit|isidentifier|isalpha|has_permission|can_|allowlist|whitelist|in_list|exists|"
    r"resolve|is_relative_to|is_safe_path|safe)"
)
AUTH_PATTERN = re.compile(
    r"(?i)(auth|permission|permitted|has_perm|require_role|login_required|current_user|"
    r"verify_token|check_token|validate_token|access_token|is_admin|is_owner|acl|rbac|scope|"
    r"session\.user|principal|identity|tenant_id|user_id|owner)"
)
APPROVAL_PATTERN = re.compile(
    r"(?i)(approve|approval|confirm|human_in_the_loop|human_review|interrupt|ask_user|"
    r"needs_approval|requires_approval|hitl|manual_review|dry_run|allowlist|allow_list|"
    r"whitelist|policy|guardrail|guard\b|consent|review_required)"
)
# Module-wide approval configuration: framework classes (as names) and constructor keywords.
MODULE_APPROVAL_NAMES = re.compile(
    r"(HumanApprovalCallbackHandler|HumanInTheLoop|ToolApproval|HumanInputRun|ApprovalMiddleware)"
)
MODULE_APPROVAL_KEYWORDS = re.compile(
    r"(?i)^(interrupt_before|interrupt_after|require_approval|needs_approval|needsApproval|"
    r"human_in_the_loop|approval_required|tool_call_approval|requires_approval|"
    r"human_approval|approval_callback)$"
)

USER_INPUT_ATTRS = {
    "args",
    "form",
    "json",
    "data",
    "values",
    "files",
    "cookies",
    "headers",
    "get_json",
    "get_data",
    "GET",
    "POST",
    "body",
    "query_params",
    "path_params",
    "stream",
    "form_data",
}
USER_INPUT_CALLS = {
    "input",
    "builtins.input",
    "streamlit.text_input",
    "streamlit.chat_input",
    "streamlit.text_area",
    "st.text_input",
    "st.chat_input",
    "st.text_area",
    "sys.stdin.read",
    "sys.stdin.readline",
}
SECRET_CALLS = {
    "getpass.getpass",
    "keyring.get_password",
}
SECRET_CALL_TAILS = {"get_secret_value", "get_secret", "access_secret_version", "getpass"}
ENV_READERS = {"os.environ.get", "os.getenv", "environ.get", "getenv"}
CONFIG_RECEIVERS = re.compile(
    r"(?i)(environ|config|settings|secrets?|env|cfg|conf|credentials|creds|params|options|"
    r"payload|kwargs|arguments|args|data|vault)"
)

# Sink specifications: (kind, exact names, tails, receiver regex, argument selectors)
_SHELL_NAMES = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "os.system",
    "os.popen",
    "os.execv",
    "os.execl",
    "os.execvp",
    "os.execlp",
    "os.execve",
    "os.execvpe",
    "os.spawnl",
    "os.spawnv",
    "os.spawnlp",
    "os.spawnvp",
    "asyncio.create_subprocess_shell",
    "asyncio.create_subprocess_exec",
    "commands.getoutput",
    "pexpect.spawn",
    "pexpect.run",
    "sh.Command",
    "invoke.run",
    "fabric.Connection.run",
    "paramiko.SSHClient.exec_command",
}
_SHELL_TAILS = {"exec_command", "run_shell", "run_command", "execute_command", "shell_exec"}
_CODE_NAMES = {
    "eval",
    "exec",
    "builtins.eval",
    "builtins.exec",
    "compile",
    "importlib.import_module",
    "__import__",
    "runpy.run_path",
    "runpy.run_module",
}
_CODE_TAILS = {
    "run_code",
    "execute_code",
    "exec_code",
    "run_python",
    "execute_python",
    "python_exec",
}
_REPL_RECV = re.compile(r"(?i)(repl|interpreter|python_tool|code_interpreter|sandbox)")
_DESER_NAMES = {
    "pickle.loads",
    "pickle.load",
    "cPickle.loads",
    "cPickle.load",
    "dill.loads",
    "dill.load",
    "marshal.loads",
    "marshal.load",
    "shelve.open",
    "jsonpickle.decode",
    "yaml.unsafe_load",
    "yaml.full_load",
    "yaml.load",
    "torch.load",
}
_SQL_TAILS = {"execute", "executemany", "executescript", "raw", "execute_sql", "run_sql", "raw_sql"}
_SQL_RECV = re.compile(
    r"(?i)(cursor|cur\b|conn|connection|db|session|engine|sql|database|pg|mysql|sqlite|client)"
)
_SQL_NAMES = {"sqlalchemy.text", "text", "pandas.read_sql", "pd.read_sql", "pandas.read_sql_query"}
_FILE_NAMES = {
    "open",
    "io.open",
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.removedirs",
    "os.rename",
    "os.replace",
    "os.makedirs",
    "os.mkdir",
    "os.chmod",
    "os.chown",
    "os.listdir",
    "os.scandir",
    "shutil.rmtree",
    "shutil.move",
    "shutil.copy",
    "shutil.copyfile",
    "shutil.copytree",
    "pathlib.Path",
    "Path",
    "aiofiles.open",
    "flask.send_file",
    "send_file",
    "fastapi.responses.FileResponse",
    "FileResponse",
    "zipfile.ZipFile",
    "tarfile.open",
    "os.path.join",
}
_FILE_TAILS = {"read_text", "write_text", "read_bytes", "write_bytes", "unlink", "rmdir"}
_NETWORK_NAMES = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "requests.head",
    "requests.options",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.patch",
    "httpx.delete",
    "httpx.head",
    "httpx.request",
    "urllib.request.urlopen",
    "urllib.request.Request",
    "urllib.request.urlretrieve",
    "urllib3.PoolManager.request",
    "socket.create_connection",
}
_NETWORK_TAILS = {"get", "post", "put", "patch", "delete", "head", "request", "urlopen", "fetch"}
_NETWORK_RECV = re.compile(r"(?i)(http|client|session|requests|httpx|aiohttp|urllib|web)")
_HTML_NAMES = {
    "flask.render_template_string",
    "render_template_string",
    "markupsafe.Markup",
    "flask.Markup",
    "Markup",
    "django.utils.safestring.mark_safe",
    "mark_safe",
    "fastapi.responses.HTMLResponse",
    "HTMLResponse",
    "jinja2.Template",
    "IPython.display.HTML",
    "HTML",
    "streamlit.html",
    "st.html",
    "gradio.HTML",
    "gr.HTML",
}
_HTML_TAILS = {"from_string"}
_REDIRECT_NAMES = {
    "flask.redirect",
    "redirect",
    "fastapi.responses.RedirectResponse",
    "RedirectResponse",
    "django.shortcuts.redirect",
    "django.http.HttpResponseRedirect",
    "HttpResponseRedirect",
}
_LOG_TAILS = {
    "debug",
    "info",
    "warning",
    "warn",
    "error",
    "critical",
    "exception",
    "log",
    "trace",
    "success",
}
_LOG_RECV = re.compile(
    r"(?i)(^|\.)(log|logger|logging|_log|_logger|structlog|loguru|console|LOG|LOGGER)(\.|$)|logger$"
)
_LOG_NAMES = {
    "print",
    "pprint",
    "pprint.pprint",
    "sys.stdout.write",
    "sys.stderr.write",
    "rich.print",
    "logging.log",
}
_PROMPT_MESSAGE_NAMES = {
    "HumanMessage",
    "SystemMessage",
    "AIMessage",
    "ChatMessage",
    "ToolMessage",
    "langchain_core.messages.HumanMessage",
    "langchain_core.messages.SystemMessage",
    "langchain.schema.HumanMessage",
    "langchain.schema.SystemMessage",
    "PromptTemplate",
    "ChatPromptTemplate.from_template",
    "ChatPromptTemplate.from_messages",
    "langchain_core.prompts.PromptTemplate",
    "langchain_core.prompts.ChatPromptTemplate.from_template",
    "langchain_core.prompts.ChatPromptTemplate.from_messages",
    "langchain.prompts.PromptTemplate",
    "langchain.prompts.ChatPromptTemplate.from_template",
}
_PROMPT_KWARGS = {
    "messages",
    "prompt",
    "input",
    "contents",
    "content",
    "system",
    "instructions",
    "system_prompt",
    "template",
    "text",
    "query",
}
_RESPONSE_NAMES = {
    "flask.jsonify",
    "jsonify",
    "fastapi.responses.JSONResponse",
    "JSONResponse",
    "flask.Response",
    "Response",
    "django.http.HttpResponse",
    "HttpResponse",
    "django.http.JsonResponse",
    "JsonResponse",
    "flask.make_response",
    "make_response",
}
DESTRUCTIVE_CALL = re.compile(
    r"(?i)(delete|remove|drop|truncate|destroy|purge|wipe|send_email|send_mail|sendmail|"
    r"send_message|transfer|payment|charge|refund|withdraw|deploy|kill|terminate|shutdown|"
    r"reboot|chmod|chown|rmtree|unlink|grant|revoke|write|update|insert|create_user|"
    r"set_password|reset_password|publish|post_|upload|overwrite|format_disk)"
)
IGNORED_PARAMS = {
    "self",
    "cls",
    "ctx",
    "context",
    "config",
    "run_manager",
    "callbacks",
    "request_context",
}


# --------------------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------------------


def analyze_module(module: PythonModule) -> DataflowResult:
    """Run taint analysis over every function in ``module``."""
    analyzer = _ModuleAnalyzer(module)
    return analyzer.run()


class _ModuleAnalyzer:
    def __init__(self, module: PythonModule) -> None:
        self.module = module
        self.functions: list[FunctionInfo] = []
        self.flows: list[TaintFlow] = []
        self.calls: list[CallInfo] = []
        self.mcp_instances: set[str] = set()
        self.app_instances: set[str] = set()
        self.registered_tools: set[str] = set()
        self.tool_names: set[str] = set()
        self.module_markers: set[str] = set()
        self.imports_mcp = any(
            imp == "mcp" or imp.startswith(("mcp.", "fastmcp")) for imp in module.imports
        )
        self.imports_web = any(
            imp.split(".")[0] in {"flask", "fastapi", "django", "starlette"}
            for imp in module.imports
        )
        self.imports_django = any(imp.split(".")[0] == "django" for imp in module.imports)

    def run(self) -> DataflowResult:
        self._prepass()
        module_info = FunctionInfo(name="<module>", lineno=1, role=FunctionRole.MODULE)
        self.functions.append(module_info)
        state = _FunctionAnalyzer(self, module_info, {}).visit_body(self.module.tree.body)
        for func in self._all_functions(self.module.tree):
            info = self._function_info(func)
            self.functions.append(info)
            _FunctionAnalyzer(self, info, dict(state)).analyze_function(func)
        return DataflowResult(
            module=self.module,
            functions=self.functions,
            flows=self.flows,
            calls=self.calls,
            module_markers=self.module_markers,
            mcp_instances=self.mcp_instances,
            app_instances=self.app_instances,
        )

    def _prepass(self) -> None:
        """Find MCP/app instances, registered tool functions and module-level markers."""
        tree = self.module.tree
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                for decorator in decorator_names(node, self.module):
                    tail = decorator.rsplit(".", 1)[-1]
                    if tail in TOOL_DECORATOR_TAILS or tail in MCP_DECORATOR_TAILS:
                        self.tool_names.add(node.name)
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                name = self.module.call_name(node.value) or ""
                class_name = name.rsplit(".", 1)[-1]
                for target in node.targets:
                    if not isinstance(target, ast.Name):
                        continue
                    if name in MCP_FACTORIES and (
                        self.imports_mcp or name.startswith(("mcp.", "fastmcp"))
                    ):
                        self.mcp_instances.add(target.id)
                    elif name in APP_FACTORIES:
                        self.app_instances.add(target.id)
                    elif class_name.endswith(("Tool", "Toolkit", "REPL")) or class_name in {
                        "BashProcess",
                        "LocalPythonExecutor",
                    }:
                        self.tool_names.add(target.id)
            if isinstance(node, ast.Call):
                name = self.module.call_name(node) or ""
                tail = attribute_tail(node.func) or ""
                if name in TOOL_REGISTRATION_CALLS or tail in {"from_function", "from_defaults"}:
                    for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                        if isinstance(arg, ast.Name):
                            self.registered_tools.add(arg.id)
                for keyword in node.keywords:
                    if keyword.arg in TOOL_LIST_KEYWORDS and isinstance(
                        keyword.value, ast.List | ast.Tuple
                    ):
                        for elt in keyword.value.elts:
                            if isinstance(elt, ast.Name):
                                self.registered_tools.add(elt.id)
                    if keyword.arg and MODULE_APPROVAL_KEYWORDS.match(keyword.arg):
                        self.module_markers.add(keyword.arg)
                if MODULE_APPROVAL_NAMES.search(name):
                    self.module_markers.add(name)
            if isinstance(node, ast.Name) and MODULE_APPROVAL_NAMES.search(node.id):
                self.module_markers.add(node.id)

    def _all_functions(self, tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
        """Top-level functions and class methods (nested functions are handled inline)."""
        found: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                found.append(node)
            elif isinstance(node, ast.ClassDef):
                found.extend(
                    child
                    for child in node.body
                    if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
                )
            elif isinstance(node, ast.If | ast.Try | ast.With):
                found.extend(self._all_functions(node))
        return found

    def _function_info(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> FunctionInfo:
        decorators = decorator_names(func, self.module)
        role = FunctionRole.OTHER
        tool_name: str | None = None
        description = docstring_of(func)
        for decorator, raw in zip(decorators, func.decorator_list, strict=True):
            tail = decorator.rsplit(".", 1)[-1]
            receiver = decorator.rsplit(".", 1)[0] if "." in decorator else ""
            agent_framework_receiver = receiver.split(".")[0] in {
                "langchain",
                "langchain_core",
                "langchain_community",
                "crewai",
                "smolagents",
                "agents",
                "pydantic_ai",
                "semantic_kernel",
                "llama_index",
                "autogen",
                "autogen_core",
                "strands",
                "google",
            }
            if receiver in self.mcp_instances or (
                self.imports_mcp
                and tail in MCP_DECORATOR_TAILS
                and receiver
                and not agent_framework_receiver
            ):
                if tail == "call_tool":
                    role = FunctionRole.MCP_CALL_TOOL_HANDLER
                elif tail == "tool":
                    role = FunctionRole.MCP_TOOL
                else:
                    continue
            elif tail in TOOL_DECORATOR_TAILS:
                role = FunctionRole.TOOL
            elif tail in ROUTE_DECORATOR_TAILS and (
                receiver in self.app_instances or self.imports_web
            ):
                role = FunctionRole.ROUTE
            else:
                continue
            if isinstance(raw, ast.Call):
                name_kw = get_keyword(raw, "name")
                desc_kw = get_keyword(raw, "description")
                if isinstance(name_kw, ast.Constant) and isinstance(name_kw.value, str):
                    tool_name = name_kw.value
                if isinstance(desc_kw, ast.Constant) and isinstance(desc_kw.value, str):
                    description = desc_kw.value
        if role is FunctionRole.OTHER and func.name in self.registered_tools:
            role = FunctionRole.TOOL
        if (
            role is FunctionRole.OTHER
            and self.imports_django
            and func.args.args
            and func.args.args[0].arg == "request"
        ):
            role = FunctionRole.ROUTE
        params = [a.arg for a in [*func.args.posonlyargs, *func.args.args, *func.args.kwonlyargs]]
        info = FunctionInfo(
            name=func.name,
            lineno=func.lineno,
            role=role,
            node=func,
            decorators=decorators,
            params=params,
            docstring=docstring_of(func),
            tool_name=tool_name
            or (func.name if role in (FunctionRole.TOOL, FunctionRole.MCP_TOOL) else None),
            tool_description=description,
        )
        for decorator in decorators:
            if APPROVAL_PATTERN.search(decorator):
                info.approval_guards.append(Guard(f"decorator {decorator}", func.lineno))
            if AUTH_PATTERN.search(decorator):
                info.auth_guards.append(Guard(f"decorator {decorator}", func.lineno))
        return info


class _FunctionAnalyzer:
    """Statement-order taint tracking for one function body."""

    def __init__(
        self,
        owner: _ModuleAnalyzer,
        info: FunctionInfo,
        initial: dict[str, frozenset[Taint]],
    ) -> None:
        self.owner = owner
        self.module = owner.module
        self.info = info
        self.vars: dict[str, frozenset[Taint]] = dict(initial)
        self.guards: dict[str, list[Guard]] = {}

    # -- entry points --------------------------------------------------------------

    def analyze_function(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        kind: SourceKind | None = None
        if self.info.role is FunctionRole.TOOL:
            kind = SourceKind.TOOL_PARAM
        elif self.info.role in (FunctionRole.MCP_TOOL, FunctionRole.MCP_CALL_TOOL_HANDLER):
            kind = SourceKind.MCP_TOOL_PARAM
        elif self.info.role is FunctionRole.ROUTE:
            kind = SourceKind.USER_INPUT
        all_args = [*func.args.posonlyargs, *func.args.args, *func.args.kwonlyargs]
        if func.args.vararg:
            all_args.append(func.args.vararg)
        if func.args.kwarg:
            all_args.append(func.args.kwarg)
        for arg in all_args:
            if arg.arg in IGNORED_PARAMS or _is_context_annotation(arg):
                continue
            if kind is not None and _is_constrained_annotation(arg):
                # int/float/bool/Literal parameters are validated by the framework schema and
                # cannot carry injected strings.
                self.vars.pop(arg.arg, None)
                continue
            if kind is not None:
                taint = Taint(
                    kind,
                    f"parameter '{arg.arg}' of {self.info.name}",
                    arg.lineno,
                    arg.col_offset + 1,
                )
                self.vars[arg.arg] = frozenset({taint.through(arg.arg)})
                self.info.tainted_params[arg.arg] = kind
            elif is_secret_name(arg.arg):
                taint = Taint(
                    SourceKind.SECRET_VALUE,
                    f"parameter '{arg.arg}'",
                    arg.lineno,
                    arg.col_offset + 1,
                    name_based=True,
                )
                self.vars[arg.arg] = frozenset({taint.through(arg.arg)})
            else:
                self.vars.pop(arg.arg, None)
        self.visit_body(func.body)

    def visit_body(self, body: list[ast.stmt]) -> dict[str, frozenset[Taint]]:
        for stmt in body:
            self.visit_stmt(stmt)
        return self.vars

    # -- statements ----------------------------------------------------------------

    def visit_stmt(self, stmt: ast.stmt) -> None:
        if isinstance(stmt, ast.Assign):
            taints = self.eval(stmt.value)
            literal = constant_value(stmt.value)
            if (
                isinstance(literal, str)
                and len(literal) >= 8
                and any(isinstance(t, ast.Name) and is_secret_name(t.id) for t in stmt.targets)
                and not _is_placeholder_literal(literal)
            ):
                taints = taints | {
                    Taint(
                        SourceKind.SECRET_VALUE,
                        "hard-coded literal",
                        stmt.lineno,
                        stmt.col_offset + 1,
                    )
                }
            for target in stmt.targets:
                self.assign(target, taints)
        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self.assign(stmt.target, self.eval(stmt.value))
        elif isinstance(stmt, ast.AugAssign):
            taints = self.eval(stmt.value) | self.eval(stmt.target)
            self.assign(stmt.target, taints)
        elif isinstance(stmt, ast.Expr):
            self.eval(stmt.value)
        elif isinstance(stmt, ast.Return):
            if stmt.value is not None:
                taints = self.eval(stmt.value)
                if self.info.role is FunctionRole.ROUTE and taints:
                    sink = SinkMatch(
                        SinkKind.HTTP_RESPONSE,
                        "return",
                        stmt,
                        stmt.lineno,
                        stmt.col_offset + 1,
                        "return value",
                        function=self.info,
                    )
                    self.info.sinks.append(sink)
                    self._record_flows(sink, taints)
        elif isinstance(stmt, ast.If | ast.While):
            self.note_guards(stmt.test)
            self.eval(stmt.test)
            self.visit_body(stmt.body)
            self.visit_body(stmt.orelse)
        elif isinstance(stmt, ast.For | ast.AsyncFor):
            self.assign(stmt.target, self.eval(stmt.iter))
            self.visit_body(stmt.body)
            self.visit_body(stmt.orelse)
        elif isinstance(stmt, ast.With | ast.AsyncWith):
            for item in stmt.items:
                taints = self.eval(item.context_expr)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, taints)
            self.visit_body(stmt.body)
        elif isinstance(stmt, ast.Try):
            self.visit_body(stmt.body)
            for handler in stmt.handlers:
                self.visit_body(handler.body)
            self.visit_body(stmt.orelse)
            self.visit_body(stmt.finalbody)
        elif isinstance(stmt, ast.Assert):
            self.note_guards(stmt.test)
            self.eval(stmt.test)
        elif isinstance(stmt, ast.Raise):
            if stmt.exc is not None:
                self.eval(stmt.exc)
        elif isinstance(stmt, ast.Match):
            self.note_guards(stmt.subject)
            self.eval(stmt.subject)
            for case in stmt.cases:
                self.visit_body(case.body)
        elif isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
            if self.info.role is not FunctionRole.MODULE:
                nested = self.owner._function_info(stmt)
                self.owner.functions.append(nested)
                _FunctionAnalyzer(self.owner, nested, dict(self.vars)).analyze_function(stmt)
            else:
                # Evaluate decorators for module-level functions (handled later as functions).
                for decorator in stmt.decorator_list:
                    self.eval(decorator)
        elif isinstance(stmt, ast.ClassDef):
            if self.info.role is not FunctionRole.MODULE:
                for child in stmt.body:
                    if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                        nested = self.owner._function_info(child)
                        self.owner.functions.append(nested)
                        _FunctionAnalyzer(self.owner, nested, dict(self.vars)).analyze_function(
                            child
                        )
            else:
                for child in stmt.body:
                    if isinstance(child, ast.Assign | ast.AnnAssign | ast.Expr):
                        self.visit_stmt(child)
        elif isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    self.vars.pop(target.id, None)
        # Import, Global, Nonlocal, Pass, Break, Continue: nothing to track.

    def assign(self, target: ast.expr, taints: frozenset[Taint]) -> None:
        if isinstance(target, ast.Name):
            self._set(target.id, taints)
        elif isinstance(target, ast.Attribute):
            name = dotted_name(target)
            if name:
                self._set(name, taints)
        elif isinstance(target, ast.Subscript):
            name = dotted_name(target.value)
            if name:
                existing = self.vars.get(name, frozenset())
                self._set(name, existing | taints)
        elif isinstance(target, ast.Tuple | ast.List):
            for elt in target.elts:
                self.assign(elt, taints)
        elif isinstance(target, ast.Starred):
            self.assign(target.value, taints)

    def _set(self, name: str, taints: frozenset[Taint]) -> None:
        if taints:
            self.vars[name] = frozenset(t.through(name) for t in taints)
        else:
            self.vars.pop(name, None)

    # -- guards --------------------------------------------------------------------

    def note_guards(self, test: ast.expr) -> None:
        """Record validation-looking checks that reference tainted names."""
        for node in ast.walk(test):
            description: str | None = None
            names: set[str] = set()
            strong_names: set[str] = set()
            if isinstance(node, ast.Compare):
                if any(isinstance(op, ast.In | ast.NotIn) for op in node.ops):
                    # ``value in ALLOWED`` is an allow-list check on the value itself (strong);
                    # ``"rm" in value`` is a substring/deny-list check (weak).
                    description = "membership check"
                    strong_names = _names_in(node.left)
                elif any(isinstance(op, ast.Eq | ast.NotEq) for op in node.ops):
                    description = "equality check"
                    strong_names = _names_in(node)
                else:
                    description = "comparison"
                names = _names_in(node)
            elif isinstance(node, ast.Call):
                callee = self.module.call_name(node) or ""
                tail = attribute_tail(node.func) or ""
                if callee in {"isinstance", "len", "type"}:
                    description = f"{callee}() check"
                elif GUARD_CALL.search(callee) or GUARD_CALL.search(tail):
                    description = f"validation call {callee or tail}()"
                if description:
                    names = _names_in(node)
                    if AUTH_PATTERN.search(callee):
                        self.info.auth_guards.append(Guard(f"call {callee}()", node.lineno))
                    if APPROVAL_PATTERN.search(callee):
                        self.info.approval_guards.append(Guard(f"call {callee}()", node.lineno))
            elif isinstance(node, ast.Attribute | ast.Name):
                dotted = dotted_name(node)
                if AUTH_PATTERN.search(dotted):
                    self.info.auth_guards.append(Guard(f"check {dotted}", node.lineno))
                if APPROVAL_PATTERN.search(dotted):
                    self.info.approval_guards.append(Guard(f"check {dotted}", node.lineno))
            if description is None:
                continue
            for name in names:
                if name in self.vars:
                    guard = Guard(
                        description, getattr(node, "lineno", 0), strong=name in strong_names
                    )
                    self.guards.setdefault(name, []).append(guard)
                    self.info.validation_guards.append(guard)

    def guards_for(self, taints: frozenset[Taint]) -> list[Guard]:
        found: list[Guard] = []
        seen: set[tuple[str, int]] = set()
        for taint in taints:
            for name in taint.via:
                for guard in self.guards.get(name, []):
                    key = (guard.description, guard.line)
                    if key not in seen:
                        seen.add(key)
                        found.append(guard)
        return found

    # -- expressions ---------------------------------------------------------------

    def eval(self, node: ast.expr | None) -> frozenset[Taint]:
        if node is None:
            return frozenset()
        if isinstance(node, ast.Name):
            taints = self.vars.get(node.id)
            if taints:
                return taints
            if is_secret_name(node.id):
                return frozenset(
                    {
                        Taint(
                            SourceKind.SECRET_VALUE,
                            f"variable '{node.id}'",
                            node.lineno,
                            node.col_offset + 1,
                            via=(node.id,),
                            name_based=True,
                        )
                    }
                )
            return frozenset()
        if isinstance(node, ast.Constant):
            return frozenset()
        if isinstance(node, ast.Attribute):
            return self.eval_attribute(node)
        if isinstance(node, ast.Subscript):
            return self.eval_subscript(node)
        if isinstance(node, ast.Call):
            return self.eval_call(node)
        if isinstance(node, ast.JoinedStr):
            result: frozenset[Taint] = frozenset()
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    result |= self.eval(value.value)
            return result
        if isinstance(node, ast.FormattedValue):
            return self.eval(node.value)
        if isinstance(node, ast.BinOp):
            return self.eval(node.left) | self.eval(node.right)
        if isinstance(node, ast.BoolOp):
            result = frozenset()
            for value in node.values:
                result |= self.eval(value)
            return result
        if isinstance(node, ast.UnaryOp):
            return self.eval(node.operand)
        if isinstance(node, ast.Compare):
            self.eval(node.left)
            for comparator in node.comparators:
                self.eval(comparator)
            return frozenset()
        if isinstance(node, ast.IfExp):
            self.note_guards(node.test)
            self.eval(node.test)
            return self.eval(node.body) | self.eval(node.orelse)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            result = frozenset()
            for elt in node.elts:
                result |= self.eval(elt)
            return result
        if isinstance(node, ast.Dict):
            result = frozenset()
            for key, value in zip(node.keys, node.values, strict=True):
                if key is not None:
                    result |= self.eval(key)
                result |= self.eval(value)
            return result
        if isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp):
            return self.eval_comprehension(node)
        if isinstance(node, ast.Await):
            return self.eval(node.value)
        if isinstance(node, ast.Starred):
            return self.eval(node.value)
        if isinstance(node, ast.NamedExpr):
            taints = self.eval(node.value)
            self.assign(node.target, taints)
            return taints
        if isinstance(node, ast.Lambda):
            return frozenset()
        if isinstance(node, ast.Yield | ast.YieldFrom):
            return self.eval(node.value) if node.value is not None else frozenset()
        if isinstance(node, ast.Slice):
            return self.eval(node.lower) | self.eval(node.upper) | self.eval(node.step)
        return frozenset()

    def eval_comprehension(
        self, node: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp
    ) -> frozenset[Taint]:
        saved = dict(self.vars)
        for generator in node.generators:
            iter_taints = self.eval(generator.iter)
            self.assign(generator.target, iter_taints)
            for condition in generator.ifs:
                self.note_guards(condition)
                self.eval(condition)
        if isinstance(node, ast.DictComp):
            result = self.eval(node.key) | self.eval(node.value)
        else:
            result = self.eval(node.elt)
        self.vars = saved
        return result

    def eval_attribute(self, node: ast.Attribute) -> frozenset[Taint]:
        base = self.eval(node.value)
        dotted = self.module.resolve(dotted_name(node))
        if base:
            return frozenset(t.through(f".{node.attr}") for t in base)
        # Flask/Django/FastAPI request objects and CLI inputs.
        parts = dotted.split(".")
        if (
            len(parts) >= 2
            and parts[-1] in USER_INPUT_ATTRS
            and (parts[-2] == "request" or parts[0] in {"request", "flask", "self", "req"})
        ):
            return frozenset(
                {Taint(SourceKind.USER_INPUT, dotted, node.lineno, node.col_offset + 1)}
            )
        if dotted in {"sys.argv", "sys.stdin"}:
            return frozenset(
                {Taint(SourceKind.USER_INPUT, dotted, node.lineno, node.col_offset + 1)}
            )
        if dotted.endswith(("update.message.text", "message.text")):
            return frozenset(
                {Taint(SourceKind.USER_INPUT, dotted, node.lineno, node.col_offset + 1)}
            )
        if is_secret_name(node.attr) and dotted != node.attr:
            return frozenset(
                {
                    Taint(
                        SourceKind.SECRET_VALUE,
                        dotted,
                        node.lineno,
                        node.col_offset + 1,
                        name_based=True,
                    )
                }
            )
        return frozenset()

    def eval_subscript(self, node: ast.Subscript) -> frozenset[Taint]:
        base = self.eval(node.value)
        self.eval(node.slice)
        dotted = self.module.resolve(dotted_name(node.value))
        key = constant_value(node.slice)
        if base:
            if isinstance(key, str):
                return frozenset(t.through(f".{key}") for t in base)
            return base
        if isinstance(key, str):
            if dotted in {"os.environ", "environ"} and is_secret_name(key):
                return frozenset(
                    {
                        Taint(
                            SourceKind.SECRET_VALUE,
                            f'os.environ["{key}"]',
                            node.lineno,
                            node.col_offset + 1,
                        )
                    }
                )
            if is_secret_name(key) and CONFIG_RECEIVERS.search(dotted or ""):
                return frozenset(
                    {
                        Taint(
                            SourceKind.SECRET_VALUE,
                            f'{dotted}["{key}"]',
                            node.lineno,
                            node.col_offset + 1,
                            name_based=True,
                        )
                    }
                )
            if dotted in {
                "request.args",
                "request.form",
                "request.json",
                "request.GET",
                "request.POST",
                "request.values",
                "request.cookies",
                "request.headers",
            }:
                return frozenset(
                    {Taint(SourceKind.USER_INPUT, dotted, node.lineno, node.col_offset + 1)}
                )
        # A lookup into an untainted container yields an untainted value even if the key is
        # tainted (e.g. ``ALLOWED[action]``); dynamic dispatch on the key is handled in eval_call.
        return frozenset()

    def eval_call(self, node: ast.Call) -> frozenset[Taint]:
        name = self.module.call_name(node) or ""
        tail = attribute_tail(node.func) or ""
        receiver = receiver_name(node.func)
        resolved_receiver = self.module.resolve(receiver) if receiver else None

        # Evaluate arguments first so sinks see the taint of each argument.
        arg_taints: list[tuple[str, ast.expr, frozenset[Taint]]] = []
        for index, arg in enumerate(node.args):
            arg_taints.append((f"arg{index}", arg, self.eval(arg)))
        for keyword in node.keywords:
            label = keyword.arg or "**kwargs"
            arg_taints.append((label, keyword.value, self.eval(keyword.value)))
        all_taints: frozenset[Taint] = frozenset()
        for _, _, taints in arg_taints:
            all_taints |= taints

        receiver_taints: frozenset[Taint] = frozenset()
        if isinstance(node.func, ast.Attribute):
            receiver_taints = self.eval(node.func.value)
        elif isinstance(node.func, ast.Subscript):
            receiver_taints = self.eval(node.func.value)
            dispatch_taints = self.eval(node.func.slice)
            if dispatch_taints:
                sink = self._sink(
                    SinkKind.DYNAMIC_DISPATCH,
                    f"{dotted_name(node.func.value)}[...]",
                    node,
                    "subscript key",
                )
                self._record_flows(sink, dispatch_taints)
        elif isinstance(node.func, ast.Call):
            inner = node.func
            inner_tail = attribute_tail(inner.func) or ""
            if inner_tail == "get" and inner.args:
                key_taints = self.eval(inner.args[0])
                if key_taints:
                    sink = self._sink(
                        SinkKind.DYNAMIC_DISPATCH,
                        f"{dotted_name(inner.func)}(...)",
                        node,
                        "lookup key",
                    )
                    self._record_flows(sink, key_taints)
            receiver_taints = self.eval(node.func)

        self.info.calls.append(CallInfo(name, tail, resolved_receiver, node, self.info))
        self.owner.calls.append(self.info.calls[-1])
        self._note_call_markers(name, tail, node)

        # Sanitizers return clean values.
        if (
            name in SANITIZER_NAMES
            or (tail in SANITIZER_NAMES and not receiver)
            or SANITIZER_PREFIX.match(tail)
        ):
            for _, _, taints in arg_taints:
                for taint in taints:
                    for via in taint.via:
                        self.guards.setdefault(via, []).append(
                            Guard(f"sanitized by {name or tail}()", node.lineno)
                        )
            return frozenset()

        self._check_sinks(node, name, tail, resolved_receiver, arg_taints, receiver_taints)

        source = self._match_source_call(node, name, tail, resolved_receiver, arg_taints)
        if source is not None:
            return frozenset({source})

        if tail == "get" and isinstance(node.func, ast.Attribute) and not receiver_taints:
            # ``TABLE.get(key)`` yields a value from an untainted container.
            return frozenset()
        return receiver_taints | all_taints

    # -- sources -------------------------------------------------------------------

    def _match_source_call(
        self,
        node: ast.Call,
        name: str,
        tail: str,
        receiver: str | None,
        arg_taints: list[tuple[str, ast.expr, frozenset[Taint]]],
    ) -> Taint | None:
        line, col = node.lineno, node.col_offset + 1
        if name in USER_INPUT_CALLS or (
            tail in {"text_input", "chat_input", "text_area"} and receiver in {"st", "streamlit"}
        ):
            return Taint(SourceKind.USER_INPUT, name or tail, line, col)
        if name in ENV_READERS or (
            tail in {"get", "getenv"} and receiver in {"os.environ", "environ", "os"}
        ):
            key = constant_value(node.args[0]) if node.args else None
            if isinstance(key, str) and is_secret_name(key):
                return Taint(SourceKind.SECRET_VALUE, f'{name or tail}("{key}")', line, col)
            return None
        if name in SECRET_CALLS or tail in SECRET_CALL_TAILS:
            return Taint(SourceKind.SECRET_VALUE, name or tail, line, col)
        if is_secret_name(tail) and tail.startswith(("get_", "load_", "read_", "fetch_")):
            return Taint(SourceKind.SECRET_VALUE, name or tail, line, col, name_based=True)
        if self._is_llm_call(name, tail, receiver):
            return Taint(SourceKind.LLM_OUTPUT, name or tail, line, col)
        if self._is_retrieval_call(name, tail, receiver):
            return Taint(SourceKind.RETRIEVED_CONTENT, name or tail, line, col)
        if self._is_tool_invocation(name, tail, receiver):
            return Taint(SourceKind.TOOL_OUTPUT, name or tail, line, col)
        return None

    @staticmethod
    def _is_llm_call(name: str, tail: str, receiver: str | None) -> bool:
        if name in LLM_CALL_NAMES:
            return True
        if LLM_CREATE_CHAIN.search(name):
            return True
        if tail in LLM_GENERATE_TAILS:
            return True
        if receiver and tail in LLM_TAILS and RECV_LLM.search(receiver):
            # Retrieval-looking receivers (index/collection) are handled as retrieval.
            if (
                RECV_RETRIEVAL.search(receiver)
                and tail in {"query", "search", "get", "retrieve"}
                and not re.search(r"(?i)(engine|chat)", receiver)
            ):
                return False
            return not (
                RECV_TOOL.search(receiver)
                and not re.search(r"(?i)(agent|executor|llm|model|chain)", receiver)
            )
        return False

    @staticmethod
    def _is_retrieval_call(name: str, tail: str, receiver: str | None) -> bool:
        if name in RETRIEVAL_FUNCTIONS or tail in RETRIEVAL_FUNCTIONS:
            return True
        if receiver and tail in RETRIEVAL_TAILS and RECV_RETRIEVAL.search(receiver):
            return not (
                tail in {"get", "fetch"}
                and not re.search(
                    r"(?i)(collection|index|vector|store|retriev|kb|knowledge)", receiver
                )
            )
        return bool(
            receiver and tail in {"invoke", "ainvoke"} and re.search(r"(?i)retriev", receiver)
        )

    def _is_tool_invocation(self, name: str, tail: str, receiver: str | None) -> bool:
        if name in TOOL_INVOKE_NAMES or tail in TOOL_INVOKE_NAMES:
            return True
        if not receiver or tail not in TOOL_INVOKE_TAILS:
            return False
        head = receiver.split(".")[0]
        if receiver in self.owner.tool_names or head in self.owner.tool_names:
            return True
        if RECV_TOOL.search(receiver):
            return (
                not re.search(r"(?i)(agent|executor_agent)", receiver) or "tool" in receiver.lower()
            )
        return False

    # -- sinks ---------------------------------------------------------------------

    def _sink(
        self,
        kind: SinkKind,
        callee: str,
        node: ast.AST,
        argument: str,
        *,
        shell: bool = False,
        arg_form: str = "unknown",
    ) -> SinkMatch:
        sink = SinkMatch(
            kind,
            callee,
            node,
            getattr(node, "lineno", 1),
            getattr(node, "col_offset", 0) + 1,
            argument,
            shell=shell,
            arg_form=arg_form,
            function=self.info,
        )
        self.info.sinks.append(sink)
        return sink

    def _record_flows(self, sink: SinkMatch, taints: frozenset[Taint]) -> None:
        guards = self.guards_for(taints)
        snippet = self.module.snippet(sink.node)
        seen: set[tuple[SourceKind, str]] = set()
        for taint in sorted(taints, key=lambda t: (t.kind.value, t.label, t.line)):
            key = (taint.kind, taint.label)
            if key in seen:
                continue
            seen.add(key)
            self.owner.flows.append(TaintFlow(taint, sink, self.info, guards, snippet))

    def _check_sinks(
        self,
        node: ast.Call,
        name: str,
        tail: str,
        receiver: str | None,
        arg_taints: list[tuple[str, ast.expr, frozenset[Taint]]],
        receiver_taints: frozenset[Taint],
    ) -> None:
        def selected(labels: tuple[str, ...]) -> list[tuple[str, ast.expr, frozenset[Taint]]]:
            return [(label, expr, taints) for label, expr, taints in arg_taints if label in labels]

        def all_args() -> list[tuple[str, ast.expr, frozenset[Taint]]]:
            return list(arg_taints)

        def report(
            kind: SinkKind,
            items: list[tuple[str, ast.expr, frozenset[Taint]]],
            *,
            shell: bool = False,
            callee: str | None = None,
        ) -> None:
            for label, expr, taints in items:
                arg_form = _arg_form(expr, self)
                sink = self._sink(
                    kind, callee or name or tail, node, label, shell=shell, arg_form=arg_form
                )
                if taints:
                    self._record_flows(sink, taints)

        shell_flag = is_truthy_constant(get_keyword(node, "shell"))
        if name in _SHELL_NAMES or tail in _SHELL_TAILS:
            report(
                SinkKind.SHELL_EXEC,
                selected(("arg0", "args", "cmd", "command")),
                shell=shell_flag
                or name
                in {
                    "os.system",
                    "os.popen",
                    "subprocess.getoutput",
                    "subprocess.getstatusoutput",
                    "asyncio.create_subprocess_shell",
                    "commands.getoutput",
                },
            )
        elif (
            name in _CODE_NAMES
            or tail in _CODE_TAILS
            or (
                receiver
                and _REPL_RECV.search(receiver)
                and tail in {"run", "exec", "execute", "run_code"}
            )
        ):
            report(SinkKind.CODE_EXEC, selected(("arg0", "source", "code", "name", "command")))
        elif name in _DESER_NAMES:
            if name == "yaml.load":
                loader = get_keyword(node, "Loader")
                if loader is None and len(node.args) > 1:
                    loader = node.args[1]
                loader_name = dotted_name(loader) if loader is not None else ""
                if "Safe" in loader_name or "safe" in loader_name:
                    return
            report(SinkKind.DESERIALIZATION, selected(("arg0", "data", "stream", "file", "f")))
        elif (
            name in _SQL_NAMES
            or (tail in _SQL_TAILS and receiver and _SQL_RECV.search(receiver))
            or tail in {"executescript", "executemany"}
        ):
            report(SinkKind.SQL_EXEC, selected(("arg0", "sql", "query", "statement", "text")))
        elif name in _FILE_NAMES or (tail in _FILE_TAILS and receiver_taints):
            if tail in _FILE_TAILS and receiver_taints:
                sink = self._sink(
                    SinkKind.FILE_PATH,
                    f"{receiver}.{tail}" if receiver else tail,
                    node,
                    "path receiver",
                )
                self._record_flows(sink, receiver_taints)
            else:
                items = selected(
                    (
                        "arg0",
                        "path",
                        "file",
                        "filename",
                        "src",
                        "dst",
                        "name",
                        "filename_or_fp",
                        "path_or_file",
                    )
                )
                if name == "os.path.join":
                    items = all_args()
                report(SinkKind.FILE_PATH, items)
        elif name in _NETWORK_NAMES or (
            tail in _NETWORK_TAILS
            and receiver
            and _NETWORK_RECV.search(receiver)
            and not RECV_RETRIEVAL.search(receiver)
        ):
            report(SinkKind.NETWORK_REQUEST, selected(("arg0", "url")))
        elif name == "getattr" or name == "builtins.getattr":
            report(SinkKind.DYNAMIC_DISPATCH, selected(("arg1", "name")))
        elif name in {"globals", "locals", "vars"}:
            pass
        elif (
            name in _HTML_NAMES
            or tail in _HTML_TAILS
            or (
                tail == "markdown"
                and receiver in {"st", "streamlit"}
                and is_truthy_constant(get_keyword(node, "unsafe_allow_html"))
            )
        ):
            if name in {"HTML", "Template"} and not self.module.imports & {
                "IPython",
                "IPython.display",
                "jinja2",
            }:
                pass
            else:
                report(
                    SinkKind.HTML_RENDER, selected(("arg0", "content", "source", "body", "html"))
                )
        elif name in _REDIRECT_NAMES:
            report(SinkKind.REDIRECT, selected(("arg0", "url", "location")))
        elif (
            name in _LOG_NAMES
            or (tail in _LOG_TAILS and receiver and _LOG_RECV.search(receiver))
            or (receiver is None and tail in {"print"})
        ):
            report(SinkKind.LOGGING, all_args())
        elif (
            self._is_llm_call(name, tail, receiver)
            or name in _PROMPT_MESSAGE_NAMES
            or tail in {"from_template", "from_messages", "format_prompt"}
        ):
            prompt_args = [
                (label, expr, taints)
                for label, expr, taints in arg_taints
                if label in _PROMPT_KWARGS or label.startswith("arg")
            ]
            report(SinkKind.PROMPT, prompt_args)
        elif self._is_tool_invocation(name, tail, receiver):
            report(SinkKind.TOOL_INVOCATION, all_args())
        elif name in _RESPONSE_NAMES or tail in {"jsonify", "JSONResponse", "make_response"}:
            report(SinkKind.HTTP_RESPONSE, all_args())
        elif name in {"Path", "pathlib.Path"}:
            report(SinkKind.FILE_PATH, all_args())

    def _note_call_markers(self, name: str, tail: str, node: ast.Call) -> None:
        if AUTH_PATTERN.search(name) or AUTH_PATTERN.search(tail):
            self.info.auth_guards.append(Guard(f"call {name or tail}()", node.lineno))
        if APPROVAL_PATTERN.search(name) or APPROVAL_PATTERN.search(tail):
            self.info.approval_guards.append(Guard(f"call {name or tail}()", node.lineno))
        for keyword in node.keywords:
            if keyword.arg and APPROVAL_PATTERN.search(keyword.arg):
                self.info.approval_guards.append(Guard(f"argument {keyword.arg}=", node.lineno))


def _is_placeholder_literal(value: str) -> bool:
    from aegisai.utils.redaction import is_placeholder

    return is_placeholder(value)


def _names_in(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
        elif isinstance(child, ast.Attribute):
            dotted = dotted_name(child)
            if dotted:
                names.add(dotted)
    return names


def _is_context_annotation(arg: ast.arg) -> bool:
    if arg.annotation is None:
        return False
    name = dotted_name(arg.annotation).rsplit(".", 1)[-1]
    return name in {"Context", "RunContext", "ToolContext", "RunContextWrapper"}


def _is_constrained_annotation(arg: ast.arg) -> bool:
    """True for int/float/bool/Literal[...] annotations (and Optional/Annotated wrappers)."""
    annotation = arg.annotation
    if annotation is None:
        return False
    while isinstance(annotation, ast.Subscript):
        outer = dotted_name(annotation.value).rsplit(".", 1)[-1]
        if outer == "Literal":
            return True
        if outer in {"Optional", "Annotated"} and isinstance(
            annotation.slice, ast.Tuple | ast.Name | ast.Attribute | ast.Subscript | ast.Constant
        ):
            annotation = (
                annotation.slice.elts[0]
                if isinstance(annotation.slice, ast.Tuple)
                else annotation.slice
            )
            continue
        return False
    if isinstance(annotation, ast.BinOp):  # ``int | None``
        return _is_constrained_annotation(ast.arg(arg=arg.arg, annotation=annotation.left))
    name = dotted_name(annotation).rsplit(".", 1)[-1]
    return name in {"int", "float", "bool"}


def _arg_form(expr: ast.expr, analyzer: _FunctionAnalyzer) -> str:
    """Describe how the tainted value appears in a command argument."""
    if isinstance(expr, ast.List | ast.Tuple):
        if not expr.elts:
            return "list_empty"
        first = analyzer.eval(expr.elts[0])
        if first:
            return "list_first"
        return "list_other"
    if isinstance(expr, ast.Constant):
        return "constant"
    if isinstance(expr, ast.JoinedStr | ast.BinOp):
        return "string_concat"
    if string_value(expr) is not None:
        return "string"
    return "expression"


def function_is_high_impact(info: FunctionInfo) -> tuple[bool, str]:
    """Heuristic: does a tool function perform a high-impact action?"""
    dangerous = {
        s.kind.value
        for s in info.sinks
        if s.kind in {SinkKind.CODE_EXEC, SinkKind.SQL_EXEC, SinkKind.DESERIALIZATION}
        # A fixed program with list arguments (``["systemctl", "status", x]``) is not generic execution.
        or (
            s.kind is SinkKind.SHELL_EXEC
            and (s.shell or s.arg_form not in {"list_other", "constant", "list_empty"})
        )
    }
    if dangerous:
        return True, "performs " + ", ".join(sorted(dangerous))
    for call in info.calls:
        if DESTRUCTIVE_CALL.search(call.tail) and call.tail not in {
            "update",
            "insert",
            "write",
            "upload",
            "publish",
        }:
            return True, f"calls {call.name or call.tail}()"
    impactful = {
        s.kind.value
        for s in info.sinks
        if s.kind is SinkKind.FILE_PATH
        or (
            s.kind is SinkKind.NETWORK_REQUEST
            and s.callee.rsplit(".", 1)[-1]
            not in {"get", "head", "options", "urlopen", "fetch", "Request"}
        )
    }
    if impactful:
        return True, "performs " + ", ".join(sorted(impactful))
    text = f"{info.tool_name or ''} {info.tool_description}"
    match = DESTRUCTIVE_CALL.search(text)
    if match and match.group(0).lower() not in {
        "write",
        "update",
        "insert",
        "post_",
        "upload",
        "publish",
    }:
        return True, f"name/description mentions '{match.group(0)}'"
    return False, ""
