# Architecture

AegisAI is a monorepo with one scanning engine and several thin integrations around it.

```
apps/vscode-extension   TypeScript; spawns the CLI, renders findings. No rules.
packages/scanner        Python engine + CLI (package `aegisai`).
rules/semgrep           Reviewed local Semgrep rules (opt-in integration input).
examples/               Vulnerable fixtures + secure counterparts (regression corpus).
.github/workflows       CI for this repo and a reusable scan workflow for consumers.
```

## Engine pipeline

`aegisai.engine.runner.run_scan(ScanOptions) -> ScanResult` executes the documented pipeline:

1. **Configuration** - `aegisai.config` loads `.aegisai.yaml` into the strictly validated
   `ScanConfiguration` (Pydantic, `extra="forbid"`). CLI flags override per-scan values.
2. **Root validation** - `utils.paths.resolve_root` resolves symlinks and rejects non-directories.
3. **Discovery** - `discovery.files.discover_files` walks the tree deterministically, applies
   exclude/include globs, skips oversized files, enforces file-count and byte limits, never
   follows symlinks that escape the root and only follows in-root symlinks when enabled.
4. **Framework detection** - `discovery.frameworks` maps Python imports, JS/TS imports and
   manifest packages to known AI/web/vector-store frameworks (used for applicability and
   reporting; the engine never imports or executes scanned code).
5. **Rule selection** - `engine.filtering.select_rules` picks rules by profile -> rule pack,
   honours `rules.disabled` / overrides and records every skipped rule with a reason.
6. **Built-in analysis** - `engine.execution.execute_rules` builds a `FileContext` per file
   (lazy AST parse, lazy taint analysis, lazy JSON/YAML parse) and runs applicable rules.
   Rule exceptions are captured as `RuleExecutionError`, never swallowed.
7. **External analyzers** - `integrations.*` run Gitleaks, OSV-Scanner and Semgrep through
   `integrations.subprocess_runner` (argument arrays, absolute executables, timeouts, bounded
   output, minimal environment). Each returns an `AnalyzerResult` with an explicit status.
8. **Normalisation** - severity overrides, confidence floor, rule precedence (e.g. MCP003
   supersedes SEC001 at the same line), deduplication that merges analyzers' evidence.
9. **Suppressions** - inline directives and configured suppressions with mandatory reasons and
   optional expiry (`engine.suppression`).
10. **Baseline** - `engine.baseline` marks findings new/existing and lists resolved ones.
11. **Reporting filter** - `--severity` hides lower findings but records how many were hidden.
12. **Status + exit code** - `ScanStatus` and the exit-code contract (see README).
13. **Reports** - `reporters.terminal|json_report|sarif|html_report`.

## Data model (`aegisai.models`)

- `Finding` - the common schema (rule, severity, confidence, status, location, evidence,
  remediation, references, analyzer, fingerprint, CWE/OWASP, suppression info).
- `RuleMetadata` - static rule description; `Rule` subclasses expose it as `metadata`.
- `ScanResult` - metadata, summary, findings, analyzers, skipped rules, warnings, errors,
  baseline summary. Serialised verbatim as the JSON report; JSON Schema in `docs/schema/`.
- `ScanConfiguration` - the `.aegisai.yaml` model.

Fingerprints (`utils.hashing.fingerprint`) hash rule id + relative POSIX path + normalised
evidence material + occurrence index. They exclude line numbers, timestamps and absolute paths.

## Analyzers (`aegisai.analyzers`)

- `python_ast` - parse once per file; import alias resolution; dotted call names; helpers.
- `dataflow` - intra-procedural taint analysis. Sources: user input, LLM output, retrieved
  content, tool output, agent tool parameters, MCP tool parameters, secrets. Sinks: shell,
  code, SQL, file path, network, dynamic dispatch, HTML, redirect, deserialization, logging,
  prompt, tool invocation, HTTP response. Guards: allow-list membership / equality on the
  tainted value are *strong* (injection rules skip the flow); other validation-looking checks
  are *weak* (confidence lowered, `review_required`). Function roles (tool, MCP tool, route)
  are derived from decorators, registrations (`tools=[...]`, `Tool(func=...)`) and framework
  instances (`FastMCP(...)`, `Flask(...)`).
- `secrets` - regex detectors for known token formats and secret-looking assignments.
- `configuration` - MCP client/server config discovery in JSON/JSONC/YAML with line lookup.
- `javascript` - regex heuristics for MCP SDK servers (exec/spawn/eval, 0.0.0.0 bindings).

## Rules (`aegisai.rules`)

Each rule is a class with complete `RuleMetadata` and a `check(ctx) -> list[Finding]`. Rules
are grouped in packs (`code`, `secrets`, `dependencies`, `llm`, `agents`, `rag`, `mcp`) that
profiles select. `rules/common.py` turns taint flows into findings with evidence for the
source, propagation path, sink and guards. Integration-backed rules (`DEP001`, `SMG001`) hold
metadata only; their findings are produced by the integration and attributed to the rule.

## Integrations contract

`ExternalAnalyzer.run(project, settings, timeout) -> IntegrationOutcome`. Status values:
`completed`, `disabled`, `skipped` (nothing applicable), `unavailable` (binary missing),
`failed` (non-zero / unparseable), `timed_out`. `required: true` or `--strict` turns any of
the last three into `ScanStatus.INCOMPLETE` (exit 3); otherwise they are surfaced as warnings
and the status becomes `success_with_warnings`.

## VS Code extension

`scannerClient.ts` validates the executable path, spawns the CLI with `execFile` (no shell),
bounds stderr, supports cancellation and parses the JSON report (`model.ts`, unit-tested with
`node:test`). `findingsProvider.ts` renders severity -> category -> finding;
`diagnostics.ts` maps findings to `vscode.Diagnostic`; `detailPanel.ts` renders an escaped,
script-free webview.

## Developer workflow (without make)

```bash
pip install -e "packages/scanner[dev]"
cd packages/scanner && python -m pytest -q && python -m ruff check src tests && python -m mypy
python scripts/generate_rule_docs.py && aegisai schema --output-dir docs/schema
python scripts/measure_detection.py
cd apps/vscode-extension && npm ci && npm test && npm run package
```
