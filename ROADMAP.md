# Roadmap

This roadmap lists planned work. Nothing here is implemented yet unless it also appears in
`CHANGELOG.md`.

## 0.2 - detection depth

- Inter-procedural taint tracking within a module (follow calls to local helpers).
- Class attribute tracking (`self.x` assigned in `__init__`, used in methods).
- Framework-aware sources for Django class-based views, Starlette routes and WebSocket handlers.
- JavaScript/TypeScript parsing (tree-sitter) instead of regex heuristics for MCP servers and
  Vercel AI / LangChain.js applications.
- Semgrep rule pack for the AI patterns that are awkward to express in the AST analyzer.

## 0.3 - workflow integration

- Debounced incremental scanning in the VS Code extension (opt-in, tested on large repos).
- Quick fixes for a subset of rules (e.g. replace `shell=True`, add `Loader=SafeLoader`).
- `aegisai baseline update` and `aegisai suppress <fingerprint>` helpers.
- GitLab CI and Azure Pipelines templates.
- JetBrains plugin reusing the CLI JSON contract.

## 0.4 - optional AI-assisted review

- Reference providers for OpenAI-compatible, Anthropic and local (Ollama) endpoints behind the
  consent gate; explanations and false-positive triage surfaced in the extension.
- Finding prioritisation using repository context (reachability from entry points).

## Later

- FastAPI service and React dashboard for centralized scan history.
- Policy-as-code for enterprise rule overrides and mandatory suppression approvals.
- Opt-in dynamic testing of MCP servers in a disposable sandbox.

Ideas and votes are welcome in GitHub Discussions.
