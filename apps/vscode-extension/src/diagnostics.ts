import * as path from "node:path";
import * as vscode from "vscode";
import { Finding, formatDiagnosticMessage, Severity, toZeroBasedRange } from "./model";

const SEVERITY_MAP: Record<Severity, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  informational: vscode.DiagnosticSeverity.Hint,
};

export function findingUri(root: string, finding: Finding): vscode.Uri {
  return vscode.Uri.file(path.join(root, ...finding.location.file_path.split("/")));
}

export function findingRange(finding: Finding): vscode.Range {
  const r = toZeroBasedRange(finding.location);
  return new vscode.Range(r.startLine, r.startCharacter, r.endLine, r.endCharacter);
}

export class DiagnosticsManager implements vscode.Disposable {
  private readonly collection = vscode.languages.createDiagnosticCollection("aegisai");

  update(root: string, findings: Finding[]): void {
    this.collection.clear();
    const byFile = new Map<string, vscode.Diagnostic[]>();
    for (const finding of findings) {
      if (finding.status === "suppressed") {
        continue;
      }
      const uri = findingUri(root, finding);
      const diagnostic = new vscode.Diagnostic(findingRange(finding), formatDiagnosticMessage(finding), SEVERITY_MAP[finding.severity]);
      diagnostic.source = "AegisAI";
      const reference = finding.references.find((r) => r.startsWith("https://"));
      diagnostic.code = reference ? { value: finding.rule_id, target: vscode.Uri.parse(reference) } : finding.rule_id;
      const key = uri.toString();
      const list = byFile.get(key) ?? [];
      list.push(diagnostic);
      byFile.set(key, list);
    }
    for (const [key, list] of byFile) {
      this.collection.set(vscode.Uri.parse(key), list);
    }
  }

  clear(): void {
    this.collection.clear();
  }

  dispose(): void {
    this.collection.dispose();
  }
}
