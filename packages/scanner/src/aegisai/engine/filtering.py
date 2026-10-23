"""Rule selection and finding filtering (profiles, disabled rules, overrides, thresholds)."""

from __future__ import annotations

from dataclasses import dataclass, field

from aegisai.engine.registry import Rule, RuleRegistry
from aegisai.models.configuration import ScanConfiguration
from aegisai.models.finding import Confidence, Finding, Severity
from aegisai.models.scan import SkippedRule


@dataclass(slots=True)
class RuleSelection:
    rules: list[Rule]
    skipped: list[SkippedRule] = field(default_factory=list)


def select_rules(
    registry: RuleRegistry,
    config: ScanConfiguration,
    *,
    extra_disabled: list[str] | None = None,
    available_integrations: dict[str, bool] | None = None,
) -> RuleSelection:
    """Pick rules for the configured profiles and record every skipped rule with a reason."""
    packs = config.selected_packs
    disabled = set(config.rules.disabled) | set(extra_disabled or [])
    for rule_id, override in config.rules.overrides.items():
        if not override.enabled:
            disabled.add(rule_id)
    available = available_integrations or {}
    selection = RuleSelection(rules=[])
    for rule in registry:
        meta = rule.metadata
        if meta.pack not in packs:
            selection.skipped.append(
                SkippedRule(
                    rule_id=meta.rule_id, reason=f"pack '{meta.pack}' not in selected profiles"
                )
            )
            continue
        if meta.rule_id in disabled:
            selection.skipped.append(
                SkippedRule(rule_id=meta.rule_id, reason="disabled by configuration")
            )
            continue
        if meta.requires_integration and not available.get(meta.requires_integration, False):
            selection.skipped.append(
                SkippedRule(
                    rule_id=meta.rule_id,
                    reason=f"requires integration '{meta.requires_integration}' which is disabled or unavailable",
                )
            )
            continue
        selection.rules.append(rule)
    return selection


def apply_overrides(findings: list[Finding], config: ScanConfiguration) -> list[Finding]:
    """Apply configured severity overrides per rule."""
    overrides = {rid: o.severity for rid, o in config.rules.overrides.items() if o.severity}
    if not overrides:
        return findings
    return [
        f.model_copy(update={"severity": overrides[f.rule_id]}) if f.rule_id in overrides else f
        for f in findings
    ]


def filter_by_confidence(findings: list[Finding], minimum: Confidence) -> list[Finding]:
    return [f for f in findings if f.confidence.rank >= minimum.rank]


def split_by_severity(findings: list[Finding], minimum: Severity) -> tuple[list[Finding], int]:
    """Return findings at/above ``minimum`` and the number filtered out."""
    kept = [f for f in findings if f.severity.at_least(minimum)]
    return kept, len(findings) - len(kept)


def threshold_reached(
    findings: list[Finding], fail_on: Severity | None, *, new_only: bool = False
) -> bool:
    """True when an active finding meets the fail_on threshold."""
    if fail_on is None:
        return False
    for finding in findings:
        if not finding.is_active:
            continue
        if new_only and finding.status.value == "existing":
            continue
        if finding.severity.at_least(fail_on):
            return True
    return False
