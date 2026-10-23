# VS Code extension

The **AegisAI Security** extension (`apps/vscode-extension`) runs the local `aegisai` CLI
and renders its JSON report. It contains no rules; the CLI is the single source of truth.

## Installation

1. Install the scanner: `pip install aegisai` (Python 3.12+). Verify with `aegisai version`.
   Optionally install `gitleaks` and `osv-scanner` on your PATH (`aegisai doctor` lists them).
2. Install the extension:
   - From a VSIX: `code --install-extension aegisai-security-0.1.0.vsix`
     (build it with `cd apps/vscode-extension && npm ci && npm run package`).
   - From source for development: open `apps/vscode-extension` in VS Code, `npm ci`, press F5.
3. If `aegisai` is not on VS Code's PATH, set **Settings > AegisAI > Executable Path** to the
   absolute path of the executable (for example `.../.venv/bin/aegisai` or
   `...\.venv\Scripts\aegisai.exe`), or set **Python Path** to an interpreter that has the
   package installed; the extension then runs `python -m aegisai.cli`.

## Using it

| Action | How |
|--------|-----|
| Scan the workspace | Command palette "AegisAI: Scan Workspace", the play button in the AegisAI view, or the status-bar item |
| Scan another folder | "AegisAI: Scan Folder..." |
| Cancel | The stop button in the view or the notification's cancel |
| Navigate | Click a finding: the file opens at the exact range and the detail panel shows evidence, impact, remediation, references and fingerprint |
| Filter | Funnel button -> minimum severity |
| Rerun after changes | Run the scan command again (there is no scan-on-type; a debounced mode is on the roadmap) |
| Last scan time | First node of the tree and the status-bar tooltip |
| Scanner errors / missing integrations | Notification + first tree nodes + "AegisAI: Show Scanner Output" |
| Reports | "AegisAI: Open JSON Report" / "Open SARIF Report" |

Diagnostics appear in the Problems panel with source `AegisAI` and the rule id as code
(clickable to the first reference). Suppressed findings are never shown as diagnostics; enable
**Show Suppressed Findings** to list them in the tree.

## Settings

See the table in `apps/vscode-extension/README.md`. All settings map to CLI flags; the
project's `.aegisai.yaml` is honoured by the CLI as usual.

## Security behaviour

- Argument-array spawning (`execFile`), no shell interpolation.
- Executable paths with separators must be absolute and exist.
- Scanner stderr is captured with a 1 MiB bound.
- Reports are written to a fresh temporary directory per scan.
- The detail panel is a webview without scripts and with a restrictive CSP; all content is
  HTML-escaped.

## Testing

`npm test` compiles the extension and runs `node:test` unit tests for the pure model
(grouping, range conversion, argument building, report validation, exit-code handling).
UI behaviour (tree, diagnostics, navigation) is exercised manually through the Extension
Development Host; an `@vscode/test-electron` integration suite is planned (see ROADMAP.md).
