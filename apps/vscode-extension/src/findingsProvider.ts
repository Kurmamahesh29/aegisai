import * as vscode from "vscode";
import { analyzerProblems, Finding, groupFindings, ScanResult, Severity, SeverityGroup } from "./model";

type NodeKind = "info" | "severity" | "category" | "finding";

export class FindingNode extends vscode.TreeItem {
  constructor(
    public readonly kind: NodeKind,
    label: string,
    collapsible: vscode.TreeItemCollapsibleState,
    public readonly severity?: Severity,
    public readonly category?: string,
    public readonly finding?: Finding,
  ) {
    super(label, collapsible);
  }
}

const SEVERITY_ICON: Record<Severity, vscode.ThemeIcon> = {
  critical: new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground")),
  high: new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground")),
  medium: new vscode.ThemeIcon("warning", new vscode.ThemeColor("editorWarning.foreground")),
  low: new vscode.ThemeIcon("info", new vscode.ThemeColor("editorInfo.foreground")),
  informational: new vscode.ThemeIcon("circle-outline"),
};

export class FindingsProvider implements vscode.TreeDataProvider<FindingNode> {
  private readonly emitter = new vscode.EventEmitter<FindingNode | undefined>();
  readonly onDidChangeTreeData = this.emitter.event;
  private result: ScanResult | undefined;
  private groups: SeverityGroup[] = [];
  minSeverity: Severity = "informational";
  includeSuppressed = false;

  setResult(result: ScanResult | undefined): void {
    this.result = result;
    this.rebuild();
  }

  setFilter(minSeverity: Severity): void {
    this.minSeverity = minSeverity;
    this.rebuild();
  }

  setIncludeSuppressed(value: boolean): void {
    this.includeSuppressed = value;
    this.rebuild();
  }

  get currentResult(): ScanResult | undefined {
    return this.result;
  }

  private rebuild(): void {
    this.groups = this.result
      ? groupFindings(this.result.findings, { minSeverity: this.minSeverity, includeSuppressed: this.includeSuppressed })
      : [];
    this.emitter.fire(undefined);
  }

  getTreeItem(element: FindingNode): vscode.TreeItem {
    return element;
  }

  getChildren(element?: FindingNode): FindingNode[] {
    if (!this.result) {
      return [];
    }
    if (!element) {
      return [...this.infoNodes(), ...this.groups.map((g) => this.severityNode(g))];
    }
    if (element.kind === "severity") {
      const group = this.groups.find((g) => g.severity === element.severity);
      return group ? group.categories.map((c) => this.categoryNode(group.severity, c.category, c.findings.length)) : [];
    }
    if (element.kind === "category") {
      const group = this.groups.find((g) => g.severity === element.severity);
      const category = group?.categories.find((c) => c.category === element.category);
      return category ? category.findings.map((f) => this.findingNode(f)) : [];
    }
    return [];
  }

  private infoNodes(): FindingNode[] {
    if (!this.result) {
      return [];
    }
    const finished = new Date(this.result.metadata.finished_at);
    const nodes: FindingNode[] = [];
    const summary = new FindingNode(
      "info",
      `Last scan ${finished.toLocaleString()} - ${this.result.summary.active_findings} finding(s), ${this.result.summary.files_scanned} file(s), status ${this.result.status}`,
      vscode.TreeItemCollapsibleState.None,
    );
    summary.iconPath = new vscode.ThemeIcon(this.result.status === "success" ? "check" : "warning");
    summary.tooltip = `profiles: ${this.result.metadata.profiles.join(", ")}\nframeworks: ${this.result.metadata.frameworks.join(", ") || "none"}\n${this.result.status_reason ?? ""}`;
    nodes.push(summary);
    for (const analyzer of analyzerProblems(this.result)) {
      const node = new FindingNode(
        "info",
        `${analyzer.name}: ${analyzer.status}${analyzer.required ? " (required)" : ""}${analyzer.message ? ` - ${analyzer.message}` : ""}`,
        vscode.TreeItemCollapsibleState.None,
      );
      node.iconPath = new vscode.ThemeIcon("plug", new vscode.ThemeColor("editorWarning.foreground"));
      nodes.push(node);
    }
    if (this.minSeverity !== "informational") {
      const node = new FindingNode("info", `Filter: ${this.minSeverity} and above`, vscode.TreeItemCollapsibleState.None);
      node.iconPath = new vscode.ThemeIcon("filter");
      node.command = { command: "aegisai.filterSeverity", title: "Change filter" };
      nodes.push(node);
    }
    return nodes;
  }

  private severityNode(group: SeverityGroup): FindingNode {
    const node = new FindingNode("severity", `${group.severity} (${group.count})`, vscode.TreeItemCollapsibleState.Expanded, group.severity);
    node.iconPath = SEVERITY_ICON[group.severity];
    node.contextValue = "severity";
    return node;
  }

  private categoryNode(severity: Severity, category: string, count: number): FindingNode {
    const node = new FindingNode("category", `${category} (${count})`, vscode.TreeItemCollapsibleState.Expanded, severity, category);
    node.iconPath = new vscode.ThemeIcon("folder");
    return node;
  }

  private findingNode(finding: Finding): FindingNode {
    const node = new FindingNode("finding", `${finding.rule_id} ${finding.title}`, vscode.TreeItemCollapsibleState.None, finding.severity, finding.category, finding);
    node.description = `${finding.location.file_path}:${finding.location.start_line}${finding.status === "suppressed" ? " (suppressed)" : ""}`;
    node.tooltip = new vscode.MarkdownString(
      `**${finding.rule_id}** ${finding.title}\n\n${finding.evidence_summary}\n\n*confidence: ${finding.confidence}${finding.review_required ? ", review required" : ""}*`,
    );
    node.iconPath = SEVERITY_ICON[finding.severity];
    node.contextValue = "finding";
    node.command = { command: "aegisai.showFinding", title: "Show finding", arguments: [finding] };
    return node;
  }
}
