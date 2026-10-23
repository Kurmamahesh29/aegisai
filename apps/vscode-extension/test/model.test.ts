import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  analyzerProblems,
  buildScanArgs,
  describeExitCode,
  Finding,
  groupFindings,
  parseScanResult,
  ScanResult,
  ScanResultError,
  severityAtLeast,
  summaryLine,
  toZeroBasedRange,
} from "../src/model";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    finding_id: "id",
    rule_id: "LLM001",
    rule_version: "1.0.0",
    title: "t",
    description: "d",
    category: "llm",
    severity: "high",
    confidence: "high",
    status: "new",
    location: { file_path: "app.py", start_line: 10, start_column: 5, end_line: 10, end_column: 20 },
    evidence: [],
    evidence_summary: "s",
    impact: "i",
    remediation: "r",
    references: [],
    analyzer: "dataflow",
    fingerprint: "f".repeat(64),
    cwe_ids: [],
    owasp_references: [],
    review_required: false,
    ...overrides,
  };
}

function result(findings: Finding[]): ScanResult {
  return {
    schema_version: "1.0.0",
    status: "success",
    metadata: { tool_version: "0.1.0", started_at: "2026-01-01T00:00:00Z", finished_at: "2026-01-01T00:00:01Z", root: "/r", profiles: ["all"], frameworks: [] },
    summary: { total_findings: findings.length, active_findings: findings.filter((f) => f.status !== "suppressed").length, suppressed_findings: 0, files_scanned: 1, files_discovered: 1, rules_executed: 21, exit_code: 0 },
    findings,
    analyzers: [{ name: "gitleaks", status: "unavailable", required: false, message: "missing", findings_count: 0 }],
    warnings: [],
    errors: [],
  };
}

describe("groupFindings", () => {
  it("groups by severity then category and sorts by location", () => {
    const groups = groupFindings([
      finding({ severity: "medium", category: "rag", location: { file_path: "b.py", start_line: 3, start_column: 1, end_line: 3, end_column: 1 } }),
      finding({ severity: "critical", category: "mcp" }),
      finding({ severity: "medium", category: "agents" }),
      finding({ severity: "medium", category: "rag", location: { file_path: "a.py", start_line: 9, start_column: 1, end_line: 9, end_column: 1 } }),
      finding({ severity: "low", status: "suppressed" }),
    ]);
    assert.deepEqual(groups.map((g) => [g.severity, g.count]), [["critical", 1], ["medium", 3]]);
    const medium = groups[1];
    assert.deepEqual(medium.categories.map((c) => c.category), ["agents", "rag"]);
    assert.deepEqual(medium.categories[1].findings.map((f) => f.location.file_path), ["a.py", "b.py"]);
  });

  it("applies the severity filter and suppressed toggle", () => {
    const items = [finding({ severity: "low" }), finding({ severity: "high" }), finding({ severity: "critical", status: "suppressed" })];
    assert.deepEqual(groupFindings(items, { minSeverity: "high" }).map((g) => g.severity), ["high"]);
    assert.deepEqual(groupFindings(items, { includeSuppressed: true }).map((g) => g.severity), ["critical", "high", "low"]);
  });
});

describe("ranges", () => {
  it("converts 1-based inclusive locations to 0-based ranges", () => {
    assert.deepEqual(toZeroBasedRange({ file_path: "a", start_line: 10, start_column: 5, end_line: 10, end_column: 20 }), { startLine: 9, startCharacter: 4, endLine: 9, endCharacter: 19 });
  });
  it("extends zero-width locations to the end of the line", () => {
    const r = toZeroBasedRange({ file_path: "a", start_line: 1, start_column: 1, end_line: 1, end_column: 1 });
    assert.equal(r.startLine, 0);
    assert.ok(r.endCharacter > 1000);
  });
});

describe("buildScanArgs", () => {
  it("builds an argument array without a shell and honours settings", () => {
    const args = buildScanArgs(
      { profile: "mcp", severityThreshold: "medium", exclude: ["vendor/**", " "], noIntegrations: true, timeoutSeconds: 42.9, extraArgs: ["--verbose"] },
      "C:\\proj",
      "C:\\tmp\\r.json",
      "C:\\tmp\\r.sarif",
    );
    assert.equal(args[0], "scan");
    assert.equal(args[1], "C:\\proj");
    assert.ok(args.includes("--no-integrations"));
    assert.deepEqual(args.slice(args.indexOf("--severity"), args.indexOf("--severity") + 2), ["--severity", "medium"]);
    assert.deepEqual(args.slice(args.indexOf("--exclude"), args.indexOf("--exclude") + 2), ["--exclude", "vendor/**"]);
    assert.equal(args.filter((a) => a === "--exclude").length, 1);
    assert.deepEqual(args.slice(args.indexOf("--timeout"), args.indexOf("--timeout") + 2), ["--timeout", "42"]);
    assert.ok(args.includes("--fail-on") && args[args.indexOf("--fail-on") + 1] === "none");
    assert.equal(args[args.length - 1], "--verbose");
  });
  it("omits the severity flag for informational", () => {
    const args = buildScanArgs({ profile: "all", severityThreshold: "informational", exclude: [], noIntegrations: false, timeoutSeconds: 300, extraArgs: [] }, "/p", "/o.json", "/o.sarif");
    assert.ok(!args.includes("--severity"));
    assert.ok(!args.includes("--no-integrations"));
  });
});

describe("parseScanResult", () => {
  it("accepts a valid report and rejects bad ones", () => {
    const parsed = parseScanResult(JSON.stringify(result([finding()])));
    assert.equal(parsed.findings.length, 1);
    assert.throws(() => parseScanResult("not json"), ScanResultError);
    assert.throws(() => parseScanResult(JSON.stringify({ schema_version: "9.0.0", findings: [], summary: {}, metadata: {} })), /schema version/);
    assert.throws(() => parseScanResult(JSON.stringify({ ...result([]), findings: [{ rule_id: "X" }] })), /invalid location/);
  });
});

describe("helpers", () => {
  it("summarises and reports analyzer problems", () => {
    const r = result([finding(), finding({ severity: "low" })]);
    assert.equal(summaryLine(r), "2 finding(s) (1 high, 1 low), status success");
    assert.deepEqual(analyzerProblems(r).map((a) => a.name), ["gitleaks"]);
    assert.ok(severityAtLeast("critical", "high"));
    assert.ok(!severityAtLeast("low", "medium"));
  });
  it("describes exit codes", () => {
    assert.equal(describeExitCode(0), null);
    assert.equal(describeExitCode(1), null);
    assert.equal(describeExitCode(3), null);
    assert.match(describeExitCode(2) ?? "", /failed/);
    assert.match(describeExitCode(130) ?? "", /cancelled/);
    assert.match(describeExitCode(7) ?? "", /unexpected/);
  });
});
