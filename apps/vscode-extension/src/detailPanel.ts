import * as vscode from "vscode";
import { Finding } from "./model";

function escapeHtml(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

export class DetailPanel {
  private panel: vscode.WebviewPanel | undefined;

  show(finding: Finding, root: string): void {
    if (!this.panel) {
      this.panel = vscode.window.createWebviewPanel("aegisai.finding", "AegisAI finding", { viewColumn: vscode.ViewColumn.Beside, preserveFocus: true }, { enableScripts: false });
      this.panel.onDidDispose(() => {
        this.panel = undefined;
      });
    }
    this.panel.title = `${finding.rule_id} ${finding.title}`;
    this.panel.webview.html = render(finding, root);
    this.panel.reveal(vscode.ViewColumn.Beside, true);
  }

  dispose(): void {
    this.panel?.dispose();
  }
}

function render(finding: Finding, root: string): string {
  const evidence = finding.evidence
    .map((e) => `<li><strong>${escapeHtml(e.kind)}</strong> ${escapeHtml(e.description)}${e.line ? ` (line ${e.line})` : ""}${e.snippet ? `<pre>${escapeHtml(e.snippet)}</pre>` : ""}</li>`)
    .join("");
  const references = finding.references
    .filter((r) => r.startsWith("https://"))
    .map((r) => `<li><a href="${escapeHtml(r)}">${escapeHtml(r)}</a></li>`)
    .join("");
  const suppression = finding.suppression ? `<p><strong>Suppressed</strong> (${escapeHtml(finding.suppression.source)}): ${escapeHtml(finding.suppression.reason)}</p>` : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<style>
body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 0 1rem; }
pre { background: var(--vscode-textCodeBlock-background); padding: .5rem; overflow-x: auto; }
.badge { display: inline-block; padding: .1rem .5rem; border-radius: 4px; background: var(--vscode-badge-background); color: var(--vscode-badge-foreground); margin-right: .4rem; }
dt { font-weight: 600; margin-top: .6rem; }
</style>
</head>
<body>
<h2>${escapeHtml(finding.rule_id)}: ${escapeHtml(finding.title)}</h2>
<p><span class="badge">${escapeHtml(finding.severity)}</span><span class="badge">confidence ${escapeHtml(finding.confidence)}</span>${finding.review_required ? '<span class="badge">review required</span>' : ""}<span class="badge">${escapeHtml(finding.status)}</span></p>
<p><code>${escapeHtml(finding.location.file_path)}:${finding.location.start_line}:${finding.location.start_column}</code> in <code>${escapeHtml(root)}</code></p>
${suppression}
<dl>
<dt>Description</dt><dd>${escapeHtml(finding.description)}</dd>
<dt>Evidence</dt><dd>${escapeHtml(finding.evidence_summary)}<ul>${evidence}</ul></dd>
<dt>Impact</dt><dd>${escapeHtml(finding.impact)}</dd>
<dt>Remediation</dt><dd>${escapeHtml(finding.remediation)}</dd>
<dt>References</dt><dd><ul>${references || "<li>none</li>"}</ul>${finding.cwe_ids.length ? `<p>CWE: ${escapeHtml(finding.cwe_ids.join(", "))}</p>` : ""}${finding.owasp_references.length ? `<p>OWASP: ${escapeHtml(finding.owasp_references.join(", "))}</p>` : ""}</dd>
<dt>Fingerprint</dt><dd><code>${escapeHtml(finding.fingerprint)}</code> (analyzer ${escapeHtml(finding.analyzer)}, rule v${escapeHtml(finding.rule_version)})</dd>
</dl>
</body>
</html>`;
}
