# Privacy

## What AegisAI reads

- Files under the scan root that match the discovery rules (source, configuration,
  manifests, env files). Files are read, parsed and discarded; nothing is uploaded.
- `.aegisai.yaml` and an optional baseline file.

## What AegisAI writes

- Reports where you tell it to (`--output`, the VS Code extension's temporary directory).
- Nothing else. The scanner does not modify scanned files and does not execute them.

## Network activity

AegisAI makes **no network calls by itself** and has **no telemetry**. Network access only
occurs through integrations you enable:

| Integration | Default | Network behaviour |
|-------------|---------|-------------------|
| Built-in rules | on | none |
| Gitleaks | enabled if installed | none (local scan) |
| OSV-Scanner | enabled if installed | queries the OSV.dev API with package names/versions from your manifests |
| Semgrep | off | none with local rule files; registry rules are refused by AegisAI |
| AI review | off | would send finding metadata (and, only with `send_source_code: true` plus explicit consent, redacted snippets) to the configured provider. No provider ships in 0.1.0. |

Disable OSV-Scanner (`integrations.osv_scanner.enabled: false` or `--no-integrations`) in
air-gapped or confidentiality-sensitive environments.

## Secrets

- Secret values detected by SEC001/MCP003/Gitleaks are masked before they enter a finding
  (`sk-p****[52 chars]`), including in evidence snippets, titles and summaries.
- A redaction pass runs over every evidence string and log line to catch known token formats
  and `key=value` assignments.
- Logs go to stderr; with `--verbose` they may include file paths but never secret values.
- Reports still include file paths and code snippets around findings. Treat them as sensitive
  artifacts and restrict access in CI.

## Data retention

AegisAI keeps no state between runs except files you create explicitly (baselines, reports).
