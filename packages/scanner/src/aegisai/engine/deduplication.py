"""Deduplicate findings without discarding distinct evidence."""

from __future__ import annotations

from aegisai.models.finding import Finding


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Merge findings that share rule id, location and evidence summary.

    Two findings are duplicates only when the rule, file, start line and (redacted) evidence
    summary are identical. When duplicates come from different analyzers (e.g. the built-in
    secret detector and Gitleaks), the surviving finding keeps the highest severity and
    confidence, records every analyzer in ``tags``, and keeps the union of evidence.
    """
    merged: dict[tuple[str, str, int, str], Finding] = {}
    order: list[tuple[str, str, int, str]] = []
    for finding in findings:
        key = (
            finding.rule_id,
            finding.location.file_path,
            finding.location.start_line,
            finding.evidence_summary,
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            order.append(key)
            continue
        merged[key] = _merge(existing, finding)
    return [merged[key] for key in order]


def apply_precedence(
    findings: list[Finding], precedence: dict[str, frozenset[str]]
) -> list[Finding]:
    """Drop findings superseded by a more specific rule at the same file and line.

    ``precedence`` maps a winning rule id to the rule ids it supersedes. Only exact
    (file, start_line) collisions are affected so distinct evidence elsewhere is preserved.
    """
    winners: set[tuple[str, int, str]] = {
        (f.location.file_path, f.location.start_line, f.rule_id)
        for f in findings
        if f.rule_id in precedence
    }
    if not winners:
        return findings
    superseded_by: dict[str, set[str]] = {}
    for winner, losers in precedence.items():
        for loser in losers:
            superseded_by.setdefault(loser, set()).add(winner)
    kept: list[Finding] = []
    for finding in findings:
        winners_for = superseded_by.get(finding.rule_id)
        if winners_for and any(
            (finding.location.file_path, finding.location.start_line, winner) in winners
            for winner in winners_for
        ):
            continue
        kept.append(finding)
    return kept


def _merge(primary: Finding, other: Finding) -> Finding:
    severity = primary.severity if primary.severity.rank >= other.severity.rank else other.severity
    confidence = (
        primary.confidence if primary.confidence.rank >= other.confidence.rank else other.confidence
    )
    analyzers = {primary.analyzer, other.analyzer}
    tags = list(
        dict.fromkeys([*primary.tags, *other.tags, *(f"analyzer:{a}" for a in sorted(analyzers))])
    )
    evidence = list(primary.evidence)
    seen = {(e.kind, e.description, e.snippet, e.line) for e in evidence}
    for item in other.evidence:
        key = (item.kind, item.description, item.snippet, item.line)
        if key not in seen:
            seen.add(key)
            evidence.append(item)
    return primary.model_copy(
        update={
            "severity": severity,
            "confidence": confidence,
            "tags": tags,
            "evidence": evidence,
            "review_required": primary.review_required and other.review_required,
        }
    )
