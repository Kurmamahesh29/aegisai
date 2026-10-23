# AegisAI

**Secure AI applications before they reach production.**

AegisAI is an open-source security scanner for applications built on large language models:
LLM-powered services, RAG pipelines, AI agents and their tools, and Model Context Protocol (MCP)
servers and configurations. It also covers the conventional ground those applications sit on:
hard-coded secrets, shell injection, unsafe configuration and vulnerable dependencies.

One scanning engine, multiple integrations, one findings format: the CLI, the VS Code
extension and the GitHub Actions workflow all run the same Python engine and the same rules.

> AegisAI is an independent open-source project. It is not affiliated with, endorsed by or
> certified by OWASP, GitHub, Anthropic, OpenAI, Google or any other organisation referenced in
> rule metadata. It finds specific, documented weakness patterns; it does not prove an
> application is secure.

## What it finds

| Pack | Rules | Examples |
|------|-------|----------|
| LLM | LLM001-LLM004 | model output executed as a command or rendered as HTML, secrets interpolated into prompts, user input passed straight into tools |
| Agents | AGT001-AGT004 | tool parameters reaching `subprocess`/`eval`/SQL, destructive tools without an approval boundary, `ShellTool`/`PythonREPLTool`/`allow_dangerous_code=True`, tool output executed |
| RAG | RAG001-RAG004 | retrieval without a tenant filter, authorization applied after retrieval, retrieved content reaching shell/SQL, PII stored as embedding metadata |
| MCP | MCP001-MCP005 | tool arguments reaching dangerous execution (Python and TS heuristics), filesystem servers rooted at `/`, auto-approved destructive tools, tokens in `claude_desktop_config.json`, `0.0.0.0` bindings and unauthenticated SSE/HTTP transports |
| Code / secrets / deps | SEC001-SEC003, CFG001, DEP001, SMG001 | hard-coded credentials (built-in + Gitleaks), secrets in logs, shell injection, debug/TLS/CORS misconfiguration, vulnerable dependencies (OSV-Scanner), local Semgrep rules |

The full catalogue with severities, confidence behaviour, CWE and OWASP references is in
[docs/supported-rules.md](docs/supported-rules.md). Rules that depend on naming conventions
are marked *heuristic* and their findings carry `review_required: true`.

## Quick start

Requirements: Python 3.12+. Optional: [Gitleaks](https://github.com/gitleaks/gitleaks),
[OSV-Scanner](https://github.com/google/osv-scanner), [Semgrep](https://semgrep.dev).

```bash
pip install aegisai                      # from PyPI once published; see below for source install
aegisai scan path/to/project             # terminal report, exit 1 on high/critical findings
aegisai scan . --profile mcp --format sarif --output aegisai.sarif
aegisai scan . --format json --output report.json --fail-on critical
aegisai rules list
aegisai rules show MCP001
aegisai config init                      # writes a documented .aegisai.yaml
aegisai doctor                           # shows which external scanners are available
```

From source:

```bash
git clone https://github.com/aegisai/aegisai
cd aegisai
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e "packages/scanner[dev]"
aegisai scan examples/vulnerable-mcp-server --no-integrations
```

### Sample output

Scanning the bundled `examples/vulnerable-llm-app` with built-in rules only (abridged,
`--format json` carries the full evidence):

```
AegisAI 0.1.0 - .../examples/vulnerable-llm-app
profiles: all | files: 3/3 | rules: 21 executed, 2 skipped | frameworks: flask, openai

 Severity  Rule    Location    Finding
 critical  LLM001  app.py:37   LLM output reaches shell/command execution
                               LLM output (client.chat.completions.create) reaches shell/command
                               execution subprocess.run() in ask()
 critical  SEC003  app.py:65   Untrusted input reaches shell execution
 high      SEC001  app.py:18   Potential hard-coded credential (OPENAI_API_KEY)
                               OPENAI_API_KEY = sk-p****[52 chars]
 high      LLM003  app.py:28   Secret value embedded in a prompt
 high      LLM004  app.py:39   LLM output reaches HTML rendering without validation
 high      SEC002  app.py:48   Secret value passed to a logging call
 high      CFG001  app.py:70   Unsafe configuration: debug=True in application run()
 medium    LLM004  app.py:50   LLM output reaches HTTP redirect without validation

Analyzers:
  builtin: completed
  gitleaks: disabled - disabled by configuration
  osv_scanner: disabled - disabled by configuration

status: success | findings: 9 [critical=2, high=6, medium=1] | fail-on: high | exit code: 1
```

Every finding records the source, the propagation path, the sink and any validation-looking
checks the analyzer saw, so you can judge it quickly. Secret values are always redacted.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | scan completed; no active finding at or above `--fail-on` |
| 1 | at least one active finding at or above `--fail-on` |
| 2 | scan failed (bad arguments, invalid configuration, unreadable root, internal error) |
| 3 | scan incomplete (timeout, file limits, or a required scanner unavailable) |
| 130 | cancelled |

A missing or failing external scanner never produces a silent clean result: it is listed in the
report's `analyzers` section, shown in the terminal, and with `--strict` (or
`integrations.<name>.required: true`) it turns the scan into exit code 3.

## Configuration

`aegisai config init` writes a commented `.aegisai.yaml`. Highlights:

```yaml
version: 1
scan:
  profiles: [all]
  exclude: [.git/**, .venv/**, node_modules/**, dist/**, build/**]
  max_file_size_kb: 1024
  timeout_seconds: 300
rules:
  disabled: []
  overrides: {}
ci:
  fail_on: high
  strict_integrations: false
integrations:
  gitleaks: {enabled: true, required: false}
  osv_scanner: {enabled: true, required: false}
  semgrep: {enabled: false, config: [rules/semgrep/python-ai-security.yaml]}
ai_review:
  enabled: false          # never sends code anywhere unless you enable it and consent
suppressions:
  - rule_id: SEC001
    path: tests/**
    reason: test fixtures with fake keys
    expires: 2027-01-01
```

Unknown keys are rejected. Inline suppressions need a reason:
`# aegisai: ignore[LLM001] reason="validated by schema below" expires=2026-12-31`.
See [docs/configuration.md](docs/configuration.md).

## Baselines

```bash
aegisai baseline create . --output aegis-baseline.json
aegisai scan . --baseline aegis-baseline.json      # only NEW findings count towards --fail-on
```

Fingerprints are stable across line shifts and checkout locations; resolved findings are
reported. A baseline never hides scan failures.

## VS Code extension

`apps/vscode-extension` provides the **AegisAI Security** extension: scan from the command
palette or status bar, findings tree grouped by severity and category, inline diagnostics,
click-to-navigate, a detail panel with remediation, severity filter, progress with
cancellation, and JSON/SARIF report opening. It drives the local CLI and contains no rules of
its own. See [docs/vscode.md](docs/vscode.md).

## CI/CD

A reusable workflow ([`.github/workflows/aegisai-scan.yml`](.github/workflows/aegisai-scan.yml))
installs AegisAI and the external scanners, runs the configured profile, uploads JSON and SARIF
reports as artifacts, optionally publishes SARIF to GitHub code scanning, and fails on the
configured threshold while clearly distinguishing vulnerabilities (exit 1) from scanner
infrastructure problems (exit 2/3). See [docs/ci-cd.md](docs/ci-cd.md).

## Architecture

```
discover files -> detect frameworks -> select rules (profile, config)
   -> Python AST + taint dataflow / structured config / JS heuristics
   -> external scanners (gitleaks, osv-scanner, semgrep) as argument-array subprocesses
   -> normalise -> precedence + dedupe -> suppressions -> baseline -> severity filter
   -> terminal / JSON / SARIF / HTML reports -> exit code
```

Details, data model and extension points: [docs/architecture.md](docs/architecture.md).
Threat model: [docs/threat-model.md](docs/threat-model.md).
Known limitations (please read): [docs/limitations.md](docs/limitations.md).

## Repository layout

```
apps/vscode-extension/   TypeScript extension (drives the CLI)
packages/scanner/        Python engine, CLI, rules, tests
rules/semgrep/           reviewed local Semgrep rules (opt-in)
examples/                intentionally vulnerable apps + secure counterparts (regression corpus)
docs/                    documentation and generated JSON schemas
scripts/                 rule-doc generator, fixture detection measurement
.github/workflows/       tests, lint, security self-scan, release, reusable scan
```

## Development

```bash
make install      # pip install -e packages/scanner[dev]
make test         # pytest
make lint         # ruff
make typecheck    # mypy --strict
make rules-doc    # regenerate docs/supported-rules.md and docs/schema
make test-ext     # compile + test the VS Code extension
```

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/adding-rules.md](docs/adding-rules.md). Security issues: [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. All runtime dependencies (Typer, Pydantic, PyYAML, Rich) are MIT or BSD
licensed; external scanners are invoked as separate processes under their own licenses.
