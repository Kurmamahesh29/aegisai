/**
 * Pure data model and helpers shared by the extension. This module must not import
 * `vscode` so it can be unit-tested with plain Node.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type Confidence = "high" | "medium" | "low";
export type FindingStatus = "new" | "existing" | "suppressed";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "informational"];

export interface Location {
  file_path: string;
  start_line: number;
  start_column: number;
  end_line: number;
  end_column: number;
}

export interface Evidence {
  kind: string;
  description: string;
  snippet?: string | null;
  line?: number | null;
  column?: number | null;
}

export interface Finding {
  finding_id: string;
  rule_id: string;
  rule_version: string;
  title: string;
  description: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  location: Location;
  evidence: Evidence[];
  evidence_summary: string;
  impact: string;
  remediation: string;
  references: string[];
  analyzer: string;
  fingerprint: string;
  cwe_ids: string[];
  owasp_references: string[];
  review_required: boolean;
  suppression?: { source: string; reason: string } | null;
}

export interface AnalyzerResult {
  name: string;
  status: string;
  required: boolean;
  message?: string | null;
  findings_count: number;
}

export interface ScanWarning {
  code: string;
  message: string;
  file_path?: string | null;
}

export interface ScanResult {
  schema_version: string;
  status: "success" | "success_with_warnings" | "incomplete" | "failed" | "cancelled";
  status_reason?: string | null;
  metadata: {
    tool_version: string;
    started_at: string;
    finished_at: string;
    root: string;
    profiles: string[];
    frameworks: string[];
  };
  summary: {
    total_findings: number;
    active_findings: number;
    suppressed_findings: number;
    files_scanned: number;
    files_discovered: number;
    rules_executed: number;
    exit_code: number;
  };
  findings: Finding[];
  analyzers: AnalyzerResult[];
  warnings: ScanWarning[];
  errors: { rule_id: string; file_path: string; error: string }[];
}

export class ScanResultError extends Error {}

/** Validate the shape of a JSON report produced by `aegisai scan --format json`. */
export function parseScanResult(text: string): ScanResult {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    throw new ScanResultError(`report is not valid JSON: ${(error as Error).message}`);
  }
  if (typeof raw !== "object" || raw === null) {
    throw new ScanResultError("report is not an object");
  }
  const result = raw as Partial<ScanResult>;
  if (typeof result.schema_version !== "string" || !result.schema_version.startsWith("1.")) {
    throw new ScanResultError(`unsupported report schema version: ${String(result.schema_version)}`);
  }
  if (!Array.isArray(result.findings) || typeof result.summary !== "object" || !result.metadata) {
    throw new ScanResultError("report is missing findings, summary or metadata");
  }
  for (const finding of result.findings) {
    if (!finding.location || typeof finding.location.file_path !== "string" || typeof finding.location.start_line !== "number") {
      throw new ScanResultError(`finding ${String(finding.rule_id)} has an invalid location`);
    }
  }
  return result as ScanResult;
}

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.length - SEVERITY_ORDER.indexOf(severity);
}

export function severityAtLeast(severity: Severity, threshold: Severity): boolean {
  return severityRank(severity) >= severityRank(threshold);
}

export interface CategoryGroup {
  category: string;
  findings: Finding[];
}

export interface SeverityGroup {
  severity: Severity;
  count: number;
  categories: CategoryGroup[];
}

export interface GroupOptions {
  minSeverity?: Severity;
  includeSuppressed?: boolean;
}

/** Group findings by severity then category, sorted by file and line inside each category. */
export function groupFindings(findings: Finding[], options: GroupOptions = {}): SeverityGroup[] {
  const min = options.minSeverity ?? "informational";
  const groups: SeverityGroup[] = [];
  for (const severity of SEVERITY_ORDER) {
    if (!severityAtLeast(severity, min)) {
      continue;
    }
    const matching = findings.filter(
      (f) => f.severity === severity && (options.includeSuppressed || f.status !== "suppressed"),
    );
    if (matching.length === 0) {
      continue;
    }
    const byCategory = new Map<string, Finding[]>();
    for (const finding of matching) {
      const bucket = byCategory.get(finding.category) ?? [];
      bucket.push(finding);
      byCategory.set(finding.category, bucket);
    }
    const categories = [...byCategory.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([category, items]) => ({
        category,
        findings: items.sort(
          (a, b) =>
            a.location.file_path.localeCompare(b.location.file_path) ||
            a.location.start_line - b.location.start_line ||
            a.rule_id.localeCompare(b.rule_id),
        ),
      }));
    groups.push({ severity, count: matching.length, categories });
  }
  return groups;
}

export interface ZeroBasedRange {
  startLine: number;
  startCharacter: number;
  endLine: number;
  endCharacter: number;
}

/** Convert the 1-based inclusive location of a finding into a 0-based, end-exclusive range. */
export function toZeroBasedRange(location: Location): ZeroBasedRange {
  const startLine = Math.max(0, location.start_line - 1);
  const startCharacter = Math.max(0, location.start_column - 1);
  let endLine = Math.max(startLine, location.end_line - 1);
  let endCharacter = Math.max(0, location.end_column - 1);
  if (endLine === startLine && endCharacter <= startCharacter) {
    // Zero-width locations: highlight the rest of the line (VS Code trims to line length).
    endCharacter = Number.MAX_SAFE_INTEGER;
  }
  if (endLine < startLine) {
    endLine = startLine;
  }
  return { startLine, startCharacter, endLine, endCharacter };
}

export interface ScanSettings {
  profile: string;
  severityThreshold: Severity;
  exclude: string[];
  noIntegrations: boolean;
  timeoutSeconds: number;
  extraArgs: string[];
}

/** Build the CLI argument array for a scan. Never joined into a shell string. */
export function buildScanArgs(settings: ScanSettings, targetPath: string, jsonOutput: string, sarifOutput: string): string[] {
  const args = [
    "scan",
    targetPath,
    "--profile",
    settings.profile,
    "--format",
    "json",
    "--output",
    jsonOutput,
    "--format",
    "sarif",
    "--output",
    sarifOutput,
    "--fail-on",
    "none",
    "--quiet",
    "--no-progress",
    "--no-color",
    "--timeout",
    String(Math.max(1, Math.floor(settings.timeoutSeconds))),
  ];
  if (settings.severityThreshold && settings.severityThreshold !== "informational") {
    args.push("--severity", settings.severityThreshold);
  }
  for (const pattern of settings.exclude) {
    if (pattern.trim()) {
      args.push("--exclude", pattern.trim());
    }
  }
  if (settings.noIntegrations) {
    args.push("--no-integrations");
  }
  for (const extra of settings.extraArgs) {
    if (extra.trim()) {
      args.push(extra.trim());
    }
  }
  return args;
}

export function formatDiagnosticMessage(finding: Finding): string {
  const review = finding.review_required ? " (review required)" : "";
  return `${finding.title}${review}\n${finding.evidence_summary}\nRemediation: ${finding.remediation}`;
}

export function summaryLine(result: ScanResult): string {
  const counts = SEVERITY_ORDER.map((sev) => {
    const n = result.findings.filter((f) => f.severity === sev && f.status !== "suppressed").length;
    return n ? `${n} ${sev}` : null;
  })
    .filter((x): x is string => x !== null)
    .join(", ");
  return `${result.summary.active_findings} finding(s)${counts ? ` (${counts})` : ""}, status ${result.status}`;
}

/** Analyzer problems worth surfacing to the user (unavailable / failed / timed out). */
export function analyzerProblems(result: ScanResult): AnalyzerResult[] {
  return result.analyzers.filter((a) => ["unavailable", "failed", "timed_out"].includes(a.status));
}

/** Interpret the CLI exit code. Returns null when the report should be parsed. */
export function describeExitCode(code: number | null): string | null {
  switch (code) {
    case 0:
    case 1:
    case 3:
      return null;
    case 2:
      return "scan failed (configuration or internal error)";
    case 130:
      return "scan cancelled";
    default:
      return `scanner exited with unexpected code ${String(code)}`;
  }
}
