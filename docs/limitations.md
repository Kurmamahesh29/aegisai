# Limitations and known issues

AegisAI finds specific, documented weakness patterns. A clean scan is not proof of security.
This page lists what the 0.1.0 release cannot do, what it gets wrong, and how it was measured.

## Analysis scope

- **Intra-procedural only.** Taint is tracked within one function. Calls to local helpers
  propagate taint from arguments to the return value conservatively, but a sink inside a helper
  is not connected to the caller's sources. Cross-file flows are not tracked.
- **Single pass over loops**; no fixpoint iteration.
- **Class state is not modelled.** `self.x` assigned in `__init__` and used in another method
  is not tracked.
- **Entry points are recognised by convention.** Flask/FastAPI/Django routes, LangChain /
  OpenAI Agents / CrewAI / pydantic-ai / Semantic Kernel / smolagents tool decorators,
  `tools=[...]` registrations, and FastMCP / low-level MCP decorators are recognised. A tool
  registered through an unknown mechanism is treated as a plain function (false negative).
  Server instances imported from other modules (`from .server import mcp`) are recognised only
  when the module also imports `mcp`/`fastmcp`.
- **Guards are name based.** `validate_*`, `is_safe`, `in ALLOWED` and similar patterns are
  recognised; a custom check with an unrelated name is not. Unrecognised checks lower nothing,
  so expect some false positives in defensively written code; recognised but ineffective checks
  lower confidence although the code may still be vulnerable.
- **Strong guards suppress injection findings.** An allow-list membership or equality check on
  the tainted value makes injection rules skip the flow. A badly constructed allow-list
  (e.g. `cmd in [user_supplied_list]`) is not detected.
- **Typed parameters.** Tool parameters annotated `int`, `float`, `bool` or `Literal[...]` are
  treated as safe because the frameworks validate them; frameworks that do not validate
  annotations would produce false negatives.
- **Sanitizers are trusted by name.** `shlex.quote`, `html.escape`, `int()` and functions named
  `validate_*`/`sanitize_*` clear taint even if their implementation is wrong.
- **JavaScript/TypeScript** support is limited to regex heuristics for MCP SDK servers
  (MCP001, MCP005) and generic secret detection; no taint analysis.
- **Prompt injection itself is not detected.** AegisAI cannot tell whether a prompt is
  injectable or whether a guardrail works; it reports what happens with model output.
- **Authorization rules (AGT002, MCP004, RAG001, RAG002) are heuristics.** They report missing
  *evidence* of a boundary, not proof that one is absent. Expect false positives when the
  boundary lives in middleware or another module.

## Rule-specific notes

| Rule | Known false positives | Known false negatives |
|------|-----------------------|-----------------------|
| SEC001 | High-entropy non-secret strings assigned to secret-named variables (e.g. hashes in tests); unquoted YAML/.env values that are long identifiers | Secrets split across lines or built by concatenation; formats not in the known-token list (Gitleaks covers more) |
| SEC002 / LLM003 | Variables named like secrets that hold non-secret data (e.g. `token` for a parser token) | Secrets reached through container attribute access on objects not named like config |
| SEC003 | `shell=True` with a dynamic command built only from trusted constants is reported at low confidence | User input reaching a helper that executes it |
| CFG001 | Debug flags in test configuration files | Settings loaded from environment with unsafe defaults |
| LLM001 | Model output used as a key into a validated table is not reported; output passed to a helper that executes it is missed | see analysis scope |
| LLM002 | Benign tools invoked with user text (search tools) are reported at medium confidence with review required | Tools whose variable names do not contain "tool" and are not recognised classes |
| AGT003 | Dangerous tools created but never given to an agent | Custom tool classes wrapping shells |
| RAG001 | Collections that are already per-tenant; identifiers that merely exist in scope | Tenant filters applied through unknown keyword names |
| RAG004 | Metadata keys that are sensitive by name but not in practice (`email` of a public contact) | PII in keys not on the list |
| MCP002 | Config files for internal, trusted-only servers | Permissions expressed in client-specific keys not on the list |
| MCP004 | Servers authenticated by a reverse proxy | Tools whose impact is not recognisable from calls or names |
| MCP005 | Containers that must bind 0.0.0.0 behind a network policy | Bindings configured through environment variables |
| DEP001 | Advisory severity may be missing (reported medium, review required) | Manifests OSV-Scanner does not support (`pyproject.toml`, `Pipfile`, `package.json` without a lockfile); these are listed as warnings |

## Measured detection on the fixture corpus (0.1.0)

`python scripts/measure_detection.py` on `examples/` with built-in rules only:

| Example | Findings | Rules fired | Expected rules missing |
|---------|----------|-------------|------------------------|
| vulnerable-llm-app | 9 | CFG001, LLM001, LLM003, LLM004 (3), SEC001, SEC002, SEC003 | none |
| vulnerable-rag-app | 8 | RAG001, RAG002, RAG003 (2), RAG004 (4) | none |
| vulnerable-agent-app | 13 | AGT001 (4), AGT002 (3), AGT003 (4), AGT004, LLM002 | none |
| vulnerable-mcp-server | 18 | MCP001 (3), MCP002 (6), MCP003 (3), MCP004 (3), MCP005 (3) | none |
| secure-examples | 0 | - | 0 false positives |

The corpus is small and written by the same people who wrote the rules; it demonstrates the
patterns each rule targets and guards against regressions. It is not a benchmark of real-world
precision or recall. Five false positives found during development (four on the secure
examples, one on this repository's own `package-lock.json`) were fixed and are locked in
`tests/regression/test_false_positives.py`.

## Measured on open-source repositories (0.1.2)

Shallow clones of six public AI repositories were scanned with built-in rules only
(`--no-integrations`), before and after the precision work in 0.1.2. "Before" is 0.1.1.

| Repository | Files | Findings before | Findings after | Notes on what remains |
|------------|-------|-----------------|----------------|-----------------------|
| modelcontextprotocol/servers | 325 | 1 | 0 | TypeScript servers; only regex heuristics apply |
| openai/openai-agents-python | 1660 | 351 | 141 | 99 x AGT003 for the SDK's own `ShellTool`/`CodeInterpreterTool` examples (downgraded to medium), docs placeholders, one real SEC003 in `examples/tools/shell.py` |
| jlowin/fastmcp | 1127 | 410 | 160 | mostly MCP004/MCP005 review items on example servers, SEC001 in tests (medium, `context:test`), AGT004 in client tests |
| langchain-ai/langgraph | 616 | 18 | 25 | SEC001 on documentation connection strings; AGT002 informational in tests |
| crewAIInc/crewAI | 2402 | 112 | 31 | SEC001 on `.env.test` and CLI label maps |
| mem0ai/mem0 | 1342 | 139 | 50 | SEC001 on demo keys in docs/integrations, RAG004 review items |

Observations that drove the 0.1.2 changes: over 90% of 0.1.1 SEC001 findings were fixture
values in tests; `get_context()` and key/value `.get()` were mis-classified as retrieval;
`Path(x)` construction and `get_stream_writer` were mis-classified as sinks/destructive calls;
custom YAML loaders were flagged. The remaining findings are dominated by review-required
heuristics (AGT002, MCP004, MCP005, AGT004) on example code, which is accurate but noisy; a
future release will let a profile exclude heuristic rules.

Precision was judged by reading samples, not by a labelled ground truth; treat the numbers as
indicative.

## Platform and tooling

- Python 3.12+ is required (uses `tomllib`, `StrEnum`, PEP 604 unions).
- External scanners are optional; without them SEC001 relies on the built-in detector and
  DEP001/SMG001 do not run (reported under `skipped_rules`, never as a clean result).
- OSV-Scanner v1 and v2 command-line syntaxes are both attempted; other versions may fail
  (reported as `failed`).
- Gitleaks is invoked with `detect --no-git`; Gitleaks releases that remove this command would
  be reported as `failed` until the integration is updated.
- Symlink tests are skipped on Windows hosts where symlink creation is not permitted.
- The VS Code extension cancels a scan by terminating the CLI process; external scanner
  child processes may outlive it briefly.
- The VS Code extension's UI layer has no automated integration tests yet; the model layer is
  unit-tested.

## Not implemented (see ROADMAP.md)

Inter-procedural analysis, JS/TS parsing, AI review providers, scan-on-save, quick fixes,
centralized service and dashboard, dynamic testing.
