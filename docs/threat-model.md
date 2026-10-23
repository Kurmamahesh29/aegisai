# Threat model

This document states what AegisAI tries to detect, what it protects against in its own
operation, and what is explicitly out of scope.

## Assets and actors in scanned applications

| Asset | Threat actors | How they reach it |
|-------|---------------|-------------------|
| Host running the application / agent / MCP server | end users, authors of indexed documents and web pages, other MCP clients, compromised model providers | prompt injection -> model output or tool arguments -> command/code execution |
| Data stores behind RAG | other tenants, document authors | missing tenant filters, SQL built from retrieved text, metadata leakage |
| Credentials | anyone with repo/config/log access, the model provider | hard-coded secrets, secrets in prompts, secrets in logs, MCP config tokens |
| Side-effecting tools (payments, deletion, email, deploy) | anyone who can influence the agent's context | tools without approval or authorization boundaries, auto-approved MCP tools |
| Network perimeter | remote attackers, browsers (DNS rebinding) | MCP servers bound to 0.0.0.0 or exposed over SSE/HTTP without authentication, cleartext transports |

### In scope (detected statically)

- Data flows from recognised untrusted sources (user input, LLM output, retrieved content,
  tool output, tool parameters) into recognised sensitive sinks within one function.
- Dangerous capabilities granted to agents (generic shell/Python/SQL tools, dangerous flags).
- Missing *recognisable* authorization/approval boundaries around high-impact tools
  (heuristic; see limitations).
- Secrets in source, env, YAML/JSON and MCP configuration; secrets flowing into prompts/logs.
- Unsafe security configuration (debug mode, TLS verification, CORS, unsafe YAML loading,
  privileged containers, write-all workflow permissions).
- MCP client configuration risk (root filesystem access, auto-approval, shell wrappers,
  dangerous flags, cleartext remote URLs) and MCP server transport/binding risk.
- Known-vulnerable dependency versions (via OSV-Scanner).

### Out of scope

- Proving that a prompt is injectable, that a guardrail works, or that a model will follow
  instructions. AegisAI does not evaluate prompts or model behaviour.
- Runtime exploitation, fuzzing or dynamic testing of MCP servers or agents.
- Interception of traffic to ChatGPT, Claude, Gemini or other hosted products.
- Inter-procedural and cross-file data flow (planned).
- Languages other than Python (full) and JavaScript/TypeScript (MCP heuristics only).
- Business-logic authorization correctness; AegisAI only checks for *evidence* of boundaries.

## Threats to AegisAI itself and mitigations

| Threat | Mitigation |
|--------|------------|
| Malicious repository causes code execution during a scan | Scanned code is never imported or executed; Python is parsed with `ast` only; JSON/YAML use safe loaders; Semgrep rules must be local files; no `shell=True` anywhere. |
| Path traversal / symlink escape | Root is resolved; symlinks are skipped by default and, when following is enabled, targets must resolve inside the root; names with control characters or traversal components are skipped. |
| Resource exhaustion (huge files, deep trees, zip bombs) | Per-file size limit, total byte limit, file-count limit, overall timeout, analyzer timeouts, bounded subprocess output, visited-inode set against directory loops. |
| Secret leakage through reports/logs | Evidence is redacted at finding creation; JSON logging applies a redacting formatter; Gitleaks secrets are masked; AI review never sends unredacted snippets. |
| Executing an unintended binary | External scanners are resolved explicitly; configured executable paths must be absolute files; the VS Code extension refuses relative executable paths; `execFile`/`Popen` with argument arrays only. |
| Supply chain of AegisAI | Pinned dependency ranges, Dependabot, OSV self-scan in CI, pinned GitHub Actions by commit SHA. |
| Silent false clean result | Analyzer statuses are always reported; `required`/`--strict` turn unavailability into exit 3; baselines cannot hide failures; rule exceptions are recorded. |
| Telemetry/data exfiltration | No telemetry. Only enabled integrations make network calls (OSV-Scanner queries osv.dev); AI review is off by default and consent-gated. |

## Residual risks

- Heuristic rules can produce false positives and false negatives; see `docs/limitations.md`.
- External scanners run with the user's privileges; keep them updated.
- A compromised AegisAI configuration file could disable rules or add suppressions; review
  `.aegisai.yaml` changes in code review like any other security-relevant file.
