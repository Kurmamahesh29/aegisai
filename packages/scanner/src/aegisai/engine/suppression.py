"""Inline and configured suppressions with mandatory reasons and optional expiry."""

from __future__ import annotations

from datetime import UTC, date, datetime

from aegisai.models.configuration import Suppression
from aegisai.models.finding import Finding, FindingStatus, SuppressionInfo
from aegisai.models.scan import ScanWarning
from aegisai.utils.paths import path_matches


def apply_suppressions(
    findings: list[Finding],
    *,
    configured: list[Suppression],
    inline_lookup: dict[str, object],
    today: date | None = None,
) -> tuple[list[Finding], list[ScanWarning]]:
    """Mark suppressed findings. Returns updated findings and warnings for bad directives.

    ``inline_lookup`` maps ``rel_path`` to a :class:`FileContext`-like object exposing
    ``inline_suppression(line)``. Findings are never removed; their status becomes
    ``suppressed`` so reports stay auditable.
    """
    today = today or datetime.now(UTC).date()
    warnings: list[ScanWarning] = []
    updated: list[Finding] = []
    for finding in findings:
        info = _match_configured(finding, configured, today, warnings)
        if info is None:
            info = _match_inline(finding, inline_lookup, warnings)
        if info is None or info.expired:
            if info is not None and info.expired:
                warnings.append(
                    ScanWarning(
                        code="suppression_expired",
                        message=(
                            f"suppression for {finding.rule_id} at {finding.short_location()} "
                            f"expired on {info.expires}; finding is visible again"
                        ),
                        file_path=finding.location.file_path,
                    )
                )
            updated.append(finding)
            continue
        updated.append(
            finding.model_copy(update={"status": FindingStatus.SUPPRESSED, "suppression": info})
        )
    return updated, warnings


def _match_configured(
    finding: Finding, configured: list[Suppression], today: date, warnings: list[ScanWarning]
) -> SuppressionInfo | None:
    for entry in configured:
        matched_by: str | None = None
        if entry.fingerprint and entry.fingerprint == finding.fingerprint:
            matched_by = "fingerprint"
        elif (
            entry.rule_id
            and entry.path
            and entry.rule_id == finding.rule_id
            and path_matches(finding.location.file_path, entry.path)
        ):
            matched_by = "rule_id+path"
        if matched_by is None:
            continue
        expired = entry.expires is not None and entry.expires < today
        return SuppressionInfo(
            source="config",
            reason=entry.reason,
            expires=entry.expires,
            expired=expired,
            matched_by=matched_by,
        )
    return None


def _match_inline(
    finding: Finding, inline_lookup: dict[str, object], warnings: list[ScanWarning]
) -> SuppressionInfo | None:
    ctx = inline_lookup.get(finding.location.file_path)
    if ctx is None:
        return None
    lookup = getattr(ctx, "inline_suppression", None)
    if lookup is None:
        return None
    directive = lookup(finding.location.start_line)
    if directive is None:
        return None
    rule_ids, reason = directive
    if rule_ids and finding.rule_id not in rule_ids:
        return None
    if not reason:
        warnings.append(
            ScanWarning(
                code="suppression_missing_reason",
                message=(
                    f'inline suppression at {finding.short_location()} has no reason="..." '
                    "and was ignored"
                ),
                file_path=finding.location.file_path,
            )
        )
        return None
    expires = _parse_expiry(ctx, finding.location.start_line)
    expired = expires is not None and expires < datetime.now(UTC).date()
    return SuppressionInfo(
        source="inline", reason=reason, expires=expires, expired=expired, matched_by="inline"
    )


def _parse_expiry(ctx: object, line_no: int) -> date | None:
    import re

    line_fn = getattr(ctx, "line", None)
    if line_fn is None:
        return None
    for candidate in (line_no, line_no - 1):
        text = line_fn(candidate)
        match = re.search(r"expires\s*=\s*(\d{4}-\d{2}-\d{2})", text)
        if match:
            try:
                return date.fromisoformat(match.group(1))
            except ValueError:
                return None
    return None
