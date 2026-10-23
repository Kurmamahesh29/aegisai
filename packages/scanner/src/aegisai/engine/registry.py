"""Rule base class, per-file context and the rule registry."""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

import yaml

from aegisai.discovery.files import DiscoveredFile
from aegisai.discovery.frameworks import Framework
from aegisai.discovery.project import ProjectContext
from aegisai.models.finding import (
    Category,
    Confidence,
    Evidence,
    Finding,
    Location,
    Severity,
)
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack
from aegisai.utils.hashing import fingerprint, short_id
from aegisai.utils.redaction import redact_text

if TYPE_CHECKING:
    from aegisai.analyzers.dataflow import DataflowResult
    from aegisai.analyzers.python_ast import PythonModule

_INLINE_SUPPRESSION = re.compile(
    r"#\s*aegisai:\s*ignore(?:\[(?P<rules>[A-Z0-9, ]+)\])?(?P<rest>.*)$"
)


@dataclass
class FileContext:
    """State shared by all rules analysing one file. Lazily parses sources once."""

    file: DiscoveredFile
    project: ProjectContext
    _text: str | None = field(default=None, repr=False)
    _lines: list[str] | None = field(default=None, repr=False)
    _module: PythonModule | None = field(default=None, repr=False)
    _module_error: str | None = field(default=None, repr=False)
    _dataflow: DataflowResult | None = field(default=None, repr=False)
    _structured: Any = field(default=None, repr=False)
    _structured_loaded: bool = field(default=False, repr=False)
    _occurrences: dict[tuple[str, str], int] = field(default_factory=dict, repr=False)

    @property
    def path(self) -> Path:
        return self.file.path

    @property
    def rel_path(self) -> str:
        return self.file.rel_path

    @property
    def artifact_type(self) -> ArtifactType:
        return self.file.artifact_type

    @property
    def text(self) -> str:
        if self._text is None:
            self._text = self.file.path.read_text(encoding="utf-8", errors="replace")
        return self._text

    @property
    def lines(self) -> list[str]:
        if self._lines is None:
            self._lines = self.text.splitlines()
        return self._lines

    def line(self, number: int) -> str:
        """1-based line access; returns '' when out of range."""
        if 1 <= number <= len(self.lines):
            return self.lines[number - 1]
        return ""

    @property
    def frameworks(self) -> set[str]:
        """Framework names detected in this file (falls back to project-level detection)."""
        own = self.project.file_frameworks.get(self.rel_path)
        if own:
            return own
        return set()

    def has_framework(self, *frameworks: Framework) -> bool:
        names = {f.value for f in frameworks}
        return bool(self.frameworks & names) or bool(
            {f.value for f in self.project.frameworks.frameworks} & names
        )

    @property
    def python_module(self) -> PythonModule | None:
        """Parsed Python module, or None if the file does not parse."""
        if self._module is None and self._module_error is None:
            from aegisai.analyzers.python_ast import parse_module

            try:
                self._module = parse_module(self.path, self.rel_path, self.text)
            except SyntaxError as exc:
                self._module_error = f"syntax error: {exc.msg} (line {exc.lineno})"
            except (ValueError, RecursionError) as exc:
                self._module_error = f"cannot parse: {exc}"
        return self._module

    @property
    def parse_error(self) -> str | None:
        _ = self.python_module
        return self._module_error

    @property
    def dataflow(self) -> DataflowResult | None:
        if self._dataflow is None and self.python_module is not None:
            from aegisai.analyzers.dataflow import analyze_module

            self._dataflow = analyze_module(self.python_module)
        return self._dataflow

    @property
    def structured(self) -> Any:
        """JSON/YAML content parsed with safe loaders, or None if unparseable."""
        if not self._structured_loaded:
            self._structured_loaded = True
            try:
                if self.artifact_type is ArtifactType.JSON:
                    self._structured = json.loads(_strip_json_comments(self.text))
                elif self.artifact_type is ArtifactType.YAML:
                    self._structured = yaml.safe_load(self.text)
            except (json.JSONDecodeError, yaml.YAMLError, ValueError, RecursionError):
                self._structured = None
        return self._structured

    def inline_suppression(self, line_no: int) -> tuple[set[str] | None, str | None] | None:
        """Parse ``# aegisai: ignore[RULE] reason="..."`` on the line or the line above.

        Returns None when no directive exists, otherwise ``(rule_ids or None, reason)``;
        an empty rule set means all rules.
        """
        for candidate in (line_no, line_no - 1):
            match = _INLINE_SUPPRESSION.search(self.line(candidate))
            if match:
                rules = match.group("rules")
                rule_ids = {r.strip() for r in rules.split(",") if r.strip()} if rules else set()
                reason_match = re.search(r"reason\s*=\s*\"([^\"]+)\"", match.group("rest") or "")
                reason = reason_match.group(1).strip() if reason_match else None
                return rule_ids, reason
        return None

    def new_finding(
        self,
        rule: Rule,
        *,
        line: int,
        column: int = 1,
        end_line: int | None = None,
        end_column: int | None = None,
        evidence: Iterable[Evidence] = (),
        evidence_summary: str,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        title: str | None = None,
        description: str | None = None,
        remediation: str | None = None,
        review_required: bool | None = None,
        tags: Iterable[str] = (),
        analyzer: str = "python_ast",
        fingerprint_material: str | None = None,
    ) -> Finding:
        """Create a validated, redacted finding anchored to this file."""
        meta = rule.metadata
        summary = redact_text(evidence_summary).strip()
        material = fingerprint_material if fingerprint_material is not None else summary
        key = (meta.rule_id, material)
        occurrence = self._occurrences.get(key, 0)
        self._occurrences[key] = occurrence + 1
        fp = fingerprint(meta.rule_id, self.rel_path, material, occurrence)
        redacted_evidence = [
            Evidence(
                kind=e.kind,
                description=redact_text(e.description),
                snippet=redact_text(e.snippet) if e.snippet else None,
                line=e.line,
                column=e.column,
            )
            for e in evidence
        ]
        return Finding(
            finding_id=short_id(fp, self.rel_path, str(line)),
            rule_id=meta.rule_id,
            rule_version=meta.version,
            title=title or meta.name,
            description=description or meta.description,
            category=meta.category,
            severity=severity or meta.default_severity,
            confidence=confidence or meta.default_confidence,
            location=Location(
                file_path=self.rel_path,
                start_line=line,
                start_column=max(1, column),
                end_line=end_line or line,
                end_column=max(1, end_column or column),
            ),
            evidence=redacted_evidence,
            evidence_summary=summary[:500],
            impact=meta.impact,
            remediation=remediation or meta.remediation,
            references=list(meta.references),
            analyzer=analyzer,
            fingerprint=fp,
            cwe_ids=list(meta.cwe_ids),
            owasp_references=list(meta.owasp_references),
            review_required=meta.heuristic if review_required is None else review_required,
            tags=list(tags) or list(meta.tags),
        )


def _strip_json_comments(text: str) -> str:
    """Remove // and /* */ comments so JSONC config files (VS Code, Cursor) parse."""
    if "//" not in text and "/*" not in text:
        return text
    out: list[str] = []
    in_string = False
    escape = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        out.append(ch)
        i += 1
    cleaned = "".join(out)
    # Trailing commas are common in JSONC.
    return re.sub(r",(\s*[}\]])", r"\1", cleaned)


class Rule(ABC):
    """Base class for all deterministic rules.

    Subclasses define ``metadata`` and implement :meth:`check`. Rules must be pure: they
    never execute scanned code, never write files, and never make network calls.
    """

    metadata: ClassVar[RuleMetadata]

    def applies_to(self, ctx: FileContext) -> bool:
        """Default applicability: artifact type match."""
        types = self.metadata.artifact_types
        return ArtifactType.ANY in types or ctx.artifact_type in types

    @abstractmethod
    def check(self, ctx: FileContext) -> list[Finding]:
        """Analyse one file and return findings (possibly empty)."""

    @property
    def rule_id(self) -> str:
        return self.metadata.rule_id

    @property
    def category(self) -> Category:
        return self.metadata.category


class RuleRegistry:
    """Versioned, ordered registry of rule instances."""

    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    def register(self, rule: Rule) -> None:
        rule_id = rule.metadata.rule_id
        if rule_id in self._rules:
            raise ValueError(f"duplicate rule id {rule_id}")
        self._rules[rule_id] = rule

    def get(self, rule_id: str) -> Rule | None:
        return self._rules.get(rule_id)

    def __iter__(self) -> Iterator[Rule]:
        return iter(sorted(self._rules.values(), key=lambda r: r.metadata.rule_id))

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, rule_id: str) -> bool:
        return rule_id in self._rules

    def by_pack(self, packs: Iterable[RulePack]) -> list[Rule]:
        wanted = set(packs)
        return [r for r in self if r.metadata.pack in wanted]

    def metadata(self) -> list[RuleMetadata]:
        return [r.metadata for r in self]


_default_registry: RuleRegistry | None = None


def default_registry() -> RuleRegistry:
    """Return the registry populated with all built-in rules (constructed once)."""
    global _default_registry
    if _default_registry is None:
        from aegisai.rules import builtin_rules

        registry = RuleRegistry()
        for rule in builtin_rules():
            registry.register(rule)
        _default_registry = registry
    return _default_registry
