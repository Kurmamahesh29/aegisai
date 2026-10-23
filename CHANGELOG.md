# Changelog

All notable changes to AegisAI are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-10-23

### Fixed
- SEC002/LLM003 false positives: a secret passed to a request, query, command or arbitrary
  helper no longer taints the call's result (e.g. logging `resp.status_code` after
  `requests.post(data={"password": ...})`). Encoding/formatting calls still propagate.
- Descriptive names such as `token_url`, `password_field` or `api_key_header` are no longer
  treated as secret values by the dataflow analyzer.
- External scanner findings (Gitleaks, Semgrep) now honour `scan.exclude`.
- `pyproject.toml` is no longer passed to OSV-Scanner as a lockfile (it has no extractor).
- SARIF rule tags are deduplicated; GitHub code scanning rejected duplicates.
- Path-like values (`bin/secretlint.js`) are no longer reported as hard-coded secrets.
- AGT003 description findings anchor to the function signature instead of the whole body.

### Changed
- `github/codeql-action/upload-sarif` pinned to v4 in the workflows.

## [0.1.0] - 2026-10-23

Initial MVP release.

### Added
- Python scanning engine with safe file discovery (root containment, symlink policy,
  size and count limits, deterministic ordering).
- Intra-procedural taint analysis for Python (sources: user input, LLM output, retrieved
  content, tool output, agent/MCP tool parameters, secrets; sinks: shell, code, SQL, file,
  network, deserialization, dynamic dispatch, HTML, redirect, logging, prompt, tool
  invocation, HTTP response) with guard detection.
- 21 built-in deterministic rules across code, secrets, LLM, agent, RAG and MCP packs, plus
  two integration-backed rules (DEP001 via OSV-Scanner, SMG001 via local Semgrep rules).
- Gitleaks, OSV-Scanner and Semgrep integrations with argument-array subprocess execution,
  timeouts, bounded output and explicit unavailable/failed/timed-out status reporting.
- Terminal, JSON, SARIF 2.1.0 and HTML reporters; JSON Schema export (`aegisai schema`).
- Baselines (`aegisai baseline create`, `--baseline`), inline and configured suppressions
  with mandatory reasons and optional expiry.
- `.aegisai.yaml` configuration with strict validation and `aegisai config init`.
- Documented exit-code contract (0 clean, 1 threshold, 2 failed, 3 incomplete, 130 cancelled).
- VS Code extension "AegisAI Security" that drives the local CLI: findings tree, inline
  diagnostics, navigation, detail panel, severity filter, progress/cancellation, report
  opening and configuration.
- GitHub Actions workflows for tests, lint, self-scan and release, plus a reusable scan
  workflow with SARIF upload.
- Intentionally vulnerable example applications (LLM, RAG, agent, MCP) and secure
  counterparts used as the regression corpus.
- Optional AI-assisted review provider interface (disabled by default, consent-gated,
  schema-validated; no network provider shipped).
