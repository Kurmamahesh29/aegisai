"""Path-context adjustments: findings in tests, fixtures, examples and docs are usually dummy.

Secrets in ``tests/``, ``verify=False`` in a test client, or a ``ShellTool`` in an SDK's own
examples are real patterns but rarely production risks. Instead of hiding them, AegisAI
lowers their severity by one step, marks them review-required and tags them with the context
so CI thresholds focus on shipped code while the findings stay visible and auditable.
"""

from __future__ import annotations

import re

from aegisai.models.configuration import ScanSection
from aegisai.models.finding import Finding, Severity
from aegisai.utils.paths import path_matches

# Directory names (any depth) and file-name shapes that denote non-production code.
_TEST_DIRS = re.compile(
    r"(?i)(?:^|/)(tests?|__tests__|testing|spec|specs|fixtures?|testdata|test_data|mocks?|"
    r"__mocks__|e2e|integration_tests?|conformance)/"
)
_TEST_FILES = re.compile(
    r"(?i)(?:^|/)(test_[^/]*\.py|[^/]*_test\.py|conftest\.py|[^/]*\.test\.[cm]?[jt]sx?|"
    r"[^/]*\.spec\.[cm]?[jt]sx?|\.env\.test|\.env\.testing)$"
)
_EXAMPLE_DIRS = re.compile(
    r"(?i)(?:^|/)(examples?|samples?|demos?|docs?|documentation|tutorials?|notebooks?|"
    r"playground)/"
)

_DOWNGRADE: dict[Severity, Severity] = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFORMATIONAL,
    Severity.INFORMATIONAL: Severity.INFORMATIONAL,
}


def classify_path(rel_path: str, extra_patterns: list[str] | None = None) -> str | None:
    """Return 'test', 'example' or None for a POSIX path relative to the scan root."""
    if _TEST_DIRS.search(rel_path) or _TEST_FILES.search(rel_path):
        return "test"
    if _EXAMPLE_DIRS.search(rel_path):
        return "example"
    for pattern in extra_patterns or []:
        if path_matches(rel_path, pattern):
            return "test"
    return None


def apply_context_adjustments(findings: list[Finding], scan: ScanSection) -> list[Finding]:
    """Downgrade findings located in test/example paths when enabled in configuration."""
    if not scan.downgrade_test_paths:
        return findings
    adjusted: list[Finding] = []
    for finding in findings:
        context = classify_path(finding.location.file_path, scan.test_path_patterns)
        if context is None:
            adjusted.append(finding)
            continue
        tags = list(dict.fromkeys([*finding.tags, f"context:{context}"]))
        adjusted.append(
            finding.model_copy(
                update={
                    "severity": _DOWNGRADE[finding.severity],
                    "review_required": True,
                    "tags": tags,
                }
            )
        )
    return adjusted
