# Configuration

AegisAI reads `.aegisai.yaml` from the scan root or the nearest parent directory (override
with `--config PATH`, ignore with `--no-config`). `aegisai config init` writes a commented
default. Unknown keys and invalid values are **rejected** (exit code 2) so typos cannot
silently disable checks.

## Full reference

```yaml
version: 1                       # required, must be 1

scan:
  profiles: [all]                # all | ai | llm | agents | rag | mcp | code | secrets | dependencies
  exclude:                       # gitignore-like globs; unanchored patterns match at any depth,
    - .git/**                    # prefix with "/" to anchor to the root
    - node_modules/**
  include: []                    # optional allow-list of globs (empty = everything)
  max_file_size_kb: 1024         # larger files are skipped and counted
  max_files: 50000               # scan becomes "incomplete" (exit 3) when exceeded
  max_total_size_mb: 512
  timeout_seconds: 300           # whole scan; remaining files are skipped and reported
  follow_symlinks: false         # in-root symlinks only; escaping links are never followed
  min_confidence: low            # discard findings below this confidence
  downgrade_test_paths: true     # tests/, fixtures/, examples/, docs/, test_*.py, *.test.ts ...:
                                 # severity lowered one step, review_required, tag context:test
  test_path_patterns: []         # extra globs treated as test paths

rules:
  disabled: [RAG002]             # rule ids
  overrides:
    SEC001:
      severity: critical         # critical | high | medium | low | informational
      enabled: true

report:
  formats: [terminal, json]      # terminal | json | sarif | html (CLI --format overrides)
  output_dir: .aegisai-reports
  min_severity: informational    # only report findings at/above (CLI --severity overrides)

ci:
  fail_on: high                  # exit 1 threshold; "null"/none disables
  strict_integrations: false     # true: enabled-but-unavailable scanner => exit 3

integrations:
  gitleaks:
    enabled: true
    required: false              # true => unavailable/failed scanner makes the scan incomplete
    executable: null             # absolute path; default: PATH lookup
    timeout_seconds: 180
    extra_args: []
  osv_scanner:
    enabled: true                # NOTE: queries the OSV.dev API over the network
    required: false
  semgrep:
    enabled: false
    config:                      # local rule files/directories only; p/..., auto, URLs are refused
      - rules/semgrep/python-ai-security.yaml

ai_review:
  enabled: false                 # requires provider; nothing is sent unless enabled
  provider: null
  model: null
  require_explicit_consent: true
  redact_secrets: true
  send_source_code: false

suppressions:
  - fingerprint: 3fb02e95bb27...  # exact finding
    reason: "sandboxed execution, reviewed 2026-10"
    expires: 2027-03-31
  - rule_id: SEC001
    path: tests/**                # glob relative to the root
    reason: "fixtures contain fake keys"
    created_by: security-team
```

Suppressions must target a fingerprint, or a rule id **and** a path; matching on title or
message text is intentionally unsupported. Expired suppressions are ignored and reported with
a warning.

## Inline suppressions

```python
subprocess.run(cmd, shell=True)  # aegisai: ignore[SEC003] reason="cmd validated above" expires=2026-12-31
```

- The directive may be on the same line or the line above.
- `reason="..."` is mandatory; a directive without it is ignored and produces a warning.
- `ignore` without a rule list suppresses every rule on that line.
- Suppressed findings stay in JSON/SARIF reports with `status: suppressed` and the reason.

## CLI overrides

| Flag | Effect |
|------|--------|
| `--profile`, `-p` | overrides `scan.profiles` (repeatable or comma-separated) |
| `--severity`, `-s` | overrides `report.min_severity` |
| `--fail-on` | overrides `ci.fail_on` (`none` disables) |
| `--exclude`, `--exclude-file` | adds to `scan.exclude` |
| `--disable-rule` | adds to `rules.disabled` |
| `--timeout`, `--max-file-size-kb` | override the scan limits |
| `--no-integrations` | runs built-in rules only |
| `--strict` | sets `ci.strict_integrations: true` |
| `--baseline FILE` | only new findings count towards `--fail-on` |
| `--format`, `--output` | report formats; the i-th `--output` pairs with the i-th non-terminal format, remaining formats go to stdout (terminal output then moves to stderr) |
| `--quiet`, `--verbose`, `--no-color`, `--no-progress` | output control |

## Profiles -> rule packs

| Profile | Packs |
|---------|-------|
| all | code, secrets, dependencies, llm, agents, rag, mcp |
| ai | llm, agents, rag, mcp |
| llm / agents / rag / mcp | the single pack |
| code | code, secrets, dependencies |
| secrets / dependencies | the single pack |

Rules outside the selected packs are listed under `skipped_rules` in the JSON report.
