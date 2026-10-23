import * as vscode from "vscode";
import { ScanController } from "./commands";
import { DiagnosticsManager } from "./diagnostics";
import { FindingsProvider } from "./findingsProvider";

export function activate(context: vscode.ExtensionContext): void {
  const provider = new FindingsProvider();
  const diagnostics = new DiagnosticsManager();
  const controller = new ScanController(provider, diagnostics);
  const tree = vscode.window.createTreeView("aegisai.findings", { treeDataProvider: provider, showCollapseAll: true });
  context.subscriptions.push(tree, diagnostics);
  controller.register(context);
  void vscode.commands.executeCommand("setContext", "aegisai.scanning", false);
}

export function deactivate(): void {
  // Disposables registered on the extension context are cleaned up by VS Code.
}
