# AegisAI Security (VS Code extension)

Runs the local `aegisai` CLI against your workspace and shows LLM, RAG, agent, MCP, secret and
code findings as a tree view and inline diagnostics. The extension contains **no detection
logic of its own**: every rule lives in the Python engine, so the IDE, CLI and CI always agree.

## Requirements

- VS Code 1.85 or newer.
- The AegisAI CLI on your PATH: `pip install aegisai` (Python 3.12+), or set
  `aegisai.executablePath` / `aegisai.pythonPath`.
- Optional: `gitleaks` and `osv-scanner` on PATH for secret and dependency scanning.

## Usage

1. Open the AegisAI view in the activity bar (shield icon) or run **AegisAI: Scan Workspace**
   from the command palette.
2. Findings are grouped by severity and category. Click one to jump to the exact location and
   open the detail panel with evidence, impact, remediation and references.
3. Inline diagnostics (Problems panel) are created for every active finding.
4. Use the filter button to hide lower severities, **Cancel Scan** to stop a running scan,
   and **Open JSON/SARIF Report** to inspect the raw reports.
5. Missing integrations and incomplete scans are reported explicitly in a notification and in
   the first tree node; they are never silently treated as "clean".

Scans run only when you trigger them (command, status-bar item, or the play button). There is no
scan-on-type.

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `aegisai.executablePath` | `aegisai` | Bare name resolved on PATH, or an absolute path to the executable. Relative paths are refused. |
| `aegisai.pythonPath` | `""` | When set, runs `<python> -m aegisai.cli` instead. |
| `aegisai.profile` | `all` | Scan profile. |
| `aegisai.severityThreshold` | `informational` | Only report findings at or above this severity. |
| `aegisai.exclude` | `[]` | Extra glob patterns to exclude. |
| `aegisai.noIntegrations` | `false` | Skip gitleaks / osv-scanner / semgrep. |
| `aegisai.timeoutSeconds` | `300` | Overall scan timeout. |
| `aegisai.extraArgs` | `[]` | Extra CLI arguments (advanced). |
| `aegisai.showSuppressedFindings` | `false` | Show suppressed findings in the tree. |

Project-level configuration (`.aegisai.yaml`) is picked up by the CLI automatically.

## Security notes

- The scanner is spawned with an argument array (`execFile`), never through a shell.
- Executable paths containing separators must be absolute and exist; this prevents running an
  unintended binary from the workspace.
- Reports are written to a per-scan temporary directory; secrets are redacted by the engine.
- Scanner stderr is captured with a 1 MiB bound and shown in the "AegisAI" output channel.

## Development

```bash
cd apps/vscode-extension
npm ci
npm run compile
npm test            # node:test suite for the pure model (no VS Code host needed)
npm run package     # produces aegisai-security-<version>.vsix
```

Press F5 in VS Code with this folder open to launch an Extension Development Host.
