"""Measure rule-level detection on the fixture corpus (examples/).

Prints, for each vulnerable example, the rules that fired and compares them with the rule ids
declared in each example's README table; also reports any finding in secure-examples as a
false positive. Exit code 1 when an expected rule is missing or a secure example has findings.

    python scripts/measure_detection.py [--json]
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "scanner" / "src"))

from aegisai.engine.runner import ScanOptions, run_scan  # noqa: E402
from aegisai.models.configuration import ScanConfiguration  # noqa: E402

EXAMPLES = ROOT / "examples"
RULE_IN_TABLE = re.compile(r"^\|\s*([A-Z]{3,4}[0-9]{3})\s*\|", re.MULTILINE)


def expected_rules(example: Path) -> set[str]:
    readme = example / "README.md"
    if not readme.exists():
        return set()
    return set(RULE_IN_TABLE.findall(readme.read_text(encoding="utf-8")))


def main() -> int:
    as_json = "--json" in sys.argv
    report: dict[str, object] = {}
    failed = False
    for example in sorted(p for p in EXAMPLES.iterdir() if p.is_dir()):
        result = run_scan(ScanOptions(root=example, config=ScanConfiguration(), no_integrations=True))
        fired = sorted({f.rule_id for f in result.findings})
        counts = {rid: sum(1 for f in result.findings if f.rule_id == rid) for rid in fired}
        expected = expected_rules(example)
        # DEP001 needs OSV-Scanner, which is not part of the deterministic corpus run.
        expected.discard("DEP001")
        missing = sorted(expected - set(fired))
        secure = example.name.startswith("secure")
        false_positives = counts if secure else {}
        entry = {
            "findings": len(result.findings),
            "rules_fired": counts,
            "expected_rules": sorted(expected),
            "missing_expected": missing,
            "false_positives": false_positives,
            "status": result.status.value,
        }
        report[example.name] = entry
        if missing or (secure and result.findings):
            failed = True
        if not as_json:
            print(f"== {example.name}: {len(result.findings)} finding(s), status {result.status.value}")
            for rid in fired:
                flag = "" if (rid in expected or secure) else "  (not listed in README)"
                print(f"   {rid}: {counts[rid]}{flag}")
            if missing:
                print(f"   MISSING expected: {', '.join(missing)}")
            if secure and result.findings:
                print("   FALSE POSITIVES:")
                for finding in result.findings:
                    print(f"     {finding.rule_id} {finding.short_location()} {finding.evidence_summary}")
    if as_json:
        print(json.dumps(report, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
