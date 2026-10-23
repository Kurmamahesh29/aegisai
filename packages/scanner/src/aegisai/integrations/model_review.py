"""Optional AI-assisted review: provider interface, consent gate and schema validation.

This feature is disabled by default and never required for a deterministic scan. No network
provider ships in this release; :class:`ReviewProvider` is the extension point and
:class:`StaticReviewProvider` exists for tests. Model output is validated against
:class:`ReviewResponse` and treated as advisory data: it can never suppress a finding.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aegisai.exceptions import ConfigurationError
from aegisai.models.configuration import AIReviewSection
from aegisai.models.finding import Finding
from aegisai.utils.redaction import redact_text


class ReviewRequest(BaseModel):
    """What a provider receives. Snippets are redacted and only present with consent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    file_path: str
    line: int
    evidence_summary: str
    snippet: str | None = None


class ReviewResponse(BaseModel):
    """Validated, advisory output of a model review."""

    model_config = ConfigDict(extra="forbid")

    explanation: str = Field(max_length=4000)
    remediation_suggestion: str = Field(max_length=4000)
    likely_false_positive: bool = False
    rationale: str = Field(default="", max_length=2000)
    priority: int = Field(default=3, ge=1, le=5, description="1 = most urgent")


class ReviewProvider(ABC):
    """Provider abstraction (OpenAI, Anthropic, Google, local models...)."""

    name: str

    @abstractmethod
    def review(self, request: ReviewRequest) -> dict[str, object]:
        """Return raw provider output as a mapping; it is validated by the service."""


class StaticReviewProvider(ReviewProvider):
    """Deterministic provider used in tests and as a reference implementation."""

    name = "static"

    def __init__(self, responder: Callable[[ReviewRequest], dict[str, object]]) -> None:
        self._responder = responder

    def review(self, request: ReviewRequest) -> dict[str, object]:
        return self._responder(request)


@dataclass(slots=True)
class ReviewResult:
    finding_id: str
    response: ReviewResponse | None
    error: str | None = None


class ReviewService:
    """Applies consent, redaction and schema validation around a provider."""

    def __init__(
        self,
        settings: AIReviewSection,
        provider: ReviewProvider | None,
        *,
        consent_given: bool = False,
    ) -> None:
        self.settings = settings
        self.provider = provider
        self.consent_given = consent_given

    def enabled(self) -> bool:
        return self.settings.enabled and self.provider is not None

    def build_request(self, finding: Finding, snippet: str | None) -> ReviewRequest:
        include_snippet = self.settings.send_source_code and (
            self.consent_given or not self.settings.require_explicit_consent
        )
        safe_snippet = (
            redact_text(snippet)
            if (snippet and include_snippet and self.settings.redact_secrets)
            else (snippet if include_snippet else None)
        )
        return ReviewRequest(
            rule_id=finding.rule_id,
            title=finding.title,
            description=finding.description,
            severity=finding.severity.value,
            confidence=finding.confidence.value,
            file_path=finding.location.file_path,
            line=finding.location.start_line,
            evidence_summary=redact_text(finding.evidence_summary),
            snippet=safe_snippet,
        )

    def review(self, finding: Finding, snippet: str | None = None) -> ReviewResult:
        if not self.settings.enabled:
            raise ConfigurationError("ai_review is disabled")
        if self.provider is None:
            raise ConfigurationError("no AI review provider configured")
        if self.settings.require_explicit_consent and not self.consent_given:
            raise ConfigurationError("AI review requires explicit consent (--ai-review-consent)")
        request = self.build_request(finding, snippet)
        try:
            raw = self.provider.review(request)
        except Exception as exc:
            return ReviewResult(
                finding.finding_id, None, error=redact_text(f"{type(exc).__name__}: {exc}")[:300]
            )
        try:
            response = ReviewResponse.model_validate(raw)
        except ValidationError as exc:
            return ReviewResult(
                finding.finding_id,
                None,
                error=f"provider output failed schema validation: {exc.error_count()} error(s)",
            )
        response.explanation = redact_text(response.explanation)
        response.remediation_suggestion = redact_text(response.remediation_suggestion)
        response.rationale = redact_text(response.rationale)
        return ReviewResult(finding.finding_id, response)
