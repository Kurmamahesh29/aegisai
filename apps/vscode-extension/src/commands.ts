import * as path from "node:path";
import * as vscode from "vscode";
import { readSettings } from "./configuration";
import { DetailPanel } from "./detailPanel";
import { DiagnosticsManager, findingRange, findingUri } from "./diagnostics";
import { FindingsProvider } from "./findingsProvider";
import { analyzerProblems, buildScanArgs, Finding, SEVERITY_ORDER, Severity, summaryLine } from "./model";
import { createReportDir, runScanner, ScannerError, ScanRun } from "./scannerClient";

export class ScanController implements vscode.Disposable {
  private readonly output = vscode.window.createOutputChannel("AegisAI");
  private readonly status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  private readonly detail = new DetailPanel();
  private current: vscode.CancellationTokenSource | undefined;
  private lastRun: ScanRun | undefined;
  private lastRoot: string | undefined;

  constructor(
    private readonly provider: FindingsProvider,
    private readonly diagnostics: DiagnosticsManager,
  ) {
    this.status.command = "aegisai.scanWorkspace";
    this.status.text = "$(shield) AegisAI";
    this.status.tooltip = "Run an AegisAI scan of the workspace";
    this.status.show();
  }

  register(context: vscode.ExtensionContext): void {
    context.subscriptions.push(
      vscode.commands.registerCommand("aegisai.scanWorkspace", () => this.scanWorkspace()),
      vscode.commands.registerCommand("aegisai.scanFolder", () => this.scanFolder()),
      vscode.commands.registerCommand("aegisai.cancelScan", () => this.cancel()),
      vscode.commands.registerCommand("aegisai.filterSeverity", () => this.pickFilter()),
      vscode.commands.registerCommand("aegisai.clearFindings", () => this.clear()),
      vscode.commands.registerCommand("aegisai.openJsonReport", () => this.openReport("json")),
      vscode.commands.registerCommand("aegisai.openSarifReport", () => this.openReport("sarif")),
      vscode.commands.registerCommand("aegisai.showOutput", () => this.output.show(true)),
      vscode.commands.registerCommand("aegisai.showFinding", (finding: Finding) => this.showFinding(finding)),
      this,
    );
  }

  private async scanWorkspace(): Promise<void> {
    const folders = vscode.workspace.workspaceFolders ?? [];
    if (folders.length === 0) {
      void vscode.window.showWarningMessage("AegisAI: open a folder or workspace to scan.");
      return;
    }
    let folder = folders[0];
    if (folders.length > 1) {
      const picked = await vscode.window.showWorkspaceFolderPick({ placeHolder: "Workspace folder to scan" });
      if (!picked) {
        return;
      }
      folder = picked;
    }
    await this.scan(folder.uri.fsPath);
  }

  private async scanFolder(): Promise<void> {
    const picked = await vscode.window.showOpenDialog({ canSelectFiles: false, canSelectFolders: true, canSelectMany: false, openLabel: "Scan" });
    if (picked && picked[0]) {
      await this.scan(picked[0].fsPath);
    }
  }

  async scan(root: string): Promise<void> {
    if (this.current) {
      void vscode.window.showInformationMessage("AegisAI: a scan is already running.");
      return;
    }
    const settings = readSettings(vscode.Uri.file(root));
    const reportDir = await createReportDir();
    const jsonPath = path.join(reportDir, "report.json");
    const sarifPath = path.join(reportDir, "report.sarif");
    const args = buildScanArgs(settings, root, jsonPath, sarifPath);
    const source = new vscode.CancellationTokenSource();
    this.current = source;
    await vscode.commands.executeCommand("setContext", "aegisai.scanning", true);
    this.status.text = "$(sync~spin) AegisAI: scanning...";
    this.output.appendLine(`--- scan started ${new Date().toISOString()} root=${root}`);
    try {
      const run = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: "AegisAI scan", cancellable: true },
        async (progress, token) => {
          token.onCancellationRequested(() => source.cancel());
          progress.report({ message: path.basename(root) });
          return runScanner(
            { pythonPath: settings.pythonPath, executablePath: settings.executablePath, args, cwd: root, onLog: (line) => this.output.append(line.endsWith("\n") ? line : `${line}\n`) },
            source.token,
            jsonPath,
            sarifPath,
          );
        },
      );
      this.applyRun(run, root, settings.showSuppressedFindings);
    } catch (error) {
      const message = error instanceof ScannerError ? error.message : `${(error as Error).message}`;
      this.output.appendLine(`error: ${message}`);
      this.status.text = "$(shield) AegisAI: scan failed";
      if (!message.startsWith("scan cancelled")) {
        const choice = await vscode.window.showErrorMessage(`AegisAI: ${message.split("\n")[0]}`, "Show Output", "Open Settings");
        if (choice === "Show Output") {
          this.output.show(true);
        } else if (choice === "Open Settings") {
          await vscode.commands.executeCommand("workbench.action.openSettings", "aegisai");
        }
      } else {
        this.status.text = "$(shield) AegisAI: cancelled";
      }
    } finally {
      this.current = undefined;
      source.dispose();
      await vscode.commands.executeCommand("setContext", "aegisai.scanning", false);
    }
  }

  private applyRun(run: ScanRun, root: string, showSuppressed: boolean): void {
    this.lastRun = run;
    this.lastRoot = root;
    this.provider.setIncludeSuppressed(showSuppressed);
    this.provider.setResult(run.result);
    this.diagnostics.update(root, run.result.findings);
    const line = summaryLine(run.result);
    const time = new Date(run.result.metadata.finished_at).toLocaleTimeString();
    this.status.text = `$(shield) AegisAI: ${run.result.summary.active_findings} (${time})`;
    this.status.tooltip = `${line}\nClick to rescan`;
    this.output.appendLine(`--- scan finished: ${line} (exit ${run.exitCode})`);
    const problems = analyzerProblems(run.result);
    if (run.result.status === "incomplete") {
      void vscode.window.showWarningMessage(`AegisAI: scan incomplete - ${run.result.status_reason ?? "see output"}`, "Show Output").then((c) => c && this.output.show(true));
    } else if (problems.length > 0) {
      const names = problems.map((p) => `${p.name} (${p.status})`).join(", ");
      void vscode.window.showWarningMessage(`AegisAI: ${line}. Integrations not run: ${names}.`);
    } else {
      void vscode.window.showInformationMessage(`AegisAI: ${line}`);
    }
    if (run.result.errors.length > 0) {
      this.output.appendLine(`${run.result.errors.length} rule error(s):`);
      for (const err of run.result.errors) {
        this.output.appendLine(`  ${err.rule_id} ${err.file_path}: ${err.error}`);
      }
    }
    for (const warning of run.result.warnings) {
      this.output.appendLine(`warning ${warning.code}: ${warning.message}${warning.file_path ? ` [${warning.file_path}]` : ""}`);
    }
  }

  private cancel(): void {
    this.current?.cancel();
  }

  private async pickFilter(): Promise<void> {
    const picked = await vscode.window.showQuickPick(
      SEVERITY_ORDER.map((s) => ({ label: s, description: s === "informational" ? "show everything" : `${s} and above`, picked: s === this.provider.minSeverity })),
      { placeHolder: "Minimum severity to show" },
    );
    if (picked) {
      this.provider.setFilter(picked.label as Severity);
    }
  }

  private clear(): void {
    this.provider.setResult(undefined);
    this.diagnostics.clear();
    this.lastRun = undefined;
    this.status.text = "$(shield) AegisAI";
  }

  private async openReport(kind: "json" | "sarif"): Promise<void> {
    if (!this.lastRun) {
      void vscode.window.showInformationMessage("AegisAI: run a scan first.");
      return;
    }
    const file = kind === "json" ? this.lastRun.jsonPath : this.lastRun.sarifPath;
    const document = await vscode.workspace.openTextDocument(vscode.Uri.file(file));
    await vscode.window.showTextDocument(document, { preview: true });
  }

  private async showFinding(finding: Finding): Promise<void> {
    const root = this.lastRoot ?? vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? "";
    this.detail.show(finding, root);
    try {
      const document = await vscode.workspace.openTextDocument(findingUri(root, finding));
      const editor = await vscode.window.showTextDocument(document, { preview: true, viewColumn: vscode.ViewColumn.One });
      const range = document.validateRange(findingRange(finding));
      editor.selection = new vscode.Selection(range.start, range.end);
      editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
    } catch (error) {
      void vscode.window.showWarningMessage(`AegisAI: cannot open ${finding.location.file_path}: ${(error as Error).message}`);
    }
  }

  dispose(): void {
    this.current?.cancel();
    this.output.dispose();
    this.status.dispose();
    this.detail.dispose();
  }
}
