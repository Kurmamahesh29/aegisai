"""Per-file rule execution with error capture, deadlines and cancellation."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from aegisai.discovery.project import ProjectContext
from aegisai.engine.registry import FileContext, Rule
from aegisai.exceptions import ScanCancelledError, ScanTimeoutError
from aegisai.models.finding import Finding
from aegisai.models.scan import RuleExecutionError, ScanWarning
from aegisai.utils.logging import get_logger

log = get_logger("execution")


class Deadline:
    """Monotonic deadline shared by the whole scan."""

    def __init__(self, timeout_seconds: float) -> None:
        self._end = time.monotonic() + timeout_seconds
        self.timeout_seconds = timeout_seconds

    def remaining(self) -> float:
        return max(0.0, self._end - time.monotonic())

    def expired(self) -> bool:
        return time.monotonic() >= self._end


@dataclass(slots=True)
class ExecutionOutcome:
    findings: list[Finding] = field(default_factory=list)
    errors: list[RuleExecutionError] = field(default_factory=list)
    warnings: list[ScanWarning] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    contexts: dict[str, FileContext] = field(default_factory=dict)
    timed_out: bool = False


def execute_rules(
    project: ProjectContext,
    rules: list[Rule],
    *,
    deadline: Deadline,
    should_cancel: Callable[[], bool] | None = None,
    progress: Callable[[int, int, str], None] | None = None,
) -> ExecutionOutcome:
    """Run every applicable rule on every discovered file.

    Rule exceptions are recorded as :class:`RuleExecutionError` and never swallowed silently.
    When the deadline expires the outcome is marked ``timed_out`` and remaining files are
    counted as skipped so the scan is reported as incomplete.
    """
    outcome = ExecutionOutcome()
    total = len(project.files)
    for index, discovered in enumerate(project.files, start=1):
        if should_cancel is not None and should_cancel():
            raise ScanCancelledError("scan cancelled")
        if deadline.expired():
            outcome.timed_out = True
            outcome.files_skipped = total - (index - 1)
            outcome.warnings.append(
                ScanWarning(
                    code="timeout",
                    message=(
                        f"scan timeout of {int(deadline.timeout_seconds)}s reached; "
                        f"{outcome.files_skipped} file(s) were not scanned"
                    ),
                )
            )
            break
        ctx = FileContext(file=discovered, project=project)
        outcome.contexts[discovered.rel_path] = ctx
        applicable = [rule for rule in rules if rule.applies_to(ctx)]
        if not applicable:
            continue
        outcome.files_scanned += 1
        if progress is not None:
            progress(index, total, discovered.rel_path)
        try:
            _ = ctx.text
        except OSError as exc:
            outcome.warnings.append(
                ScanWarning(code="unreadable", message=str(exc), file_path=discovered.rel_path)
            )
            continue
        for rule in applicable:
            try:
                findings = rule.check(ctx)
            except ScanTimeoutError:
                raise
            except Exception as exc:
                log.debug("rule %s failed on %s", rule.rule_id, discovered.rel_path, exc_info=True)
                outcome.errors.append(
                    RuleExecutionError(
                        rule_id=rule.rule_id,
                        file_path=discovered.rel_path,
                        error=f"{type(exc).__name__}: {exc}"[:500],
                    )
                )
                continue
            outcome.findings.extend(findings)
        if ctx.parse_error and discovered.artifact_type.value == "python":
            outcome.warnings.append(
                ScanWarning(
                    code="parse_error",
                    message=f"Python AST rules skipped: {ctx.parse_error}",
                    file_path=discovered.rel_path,
                )
            )
    return outcome
