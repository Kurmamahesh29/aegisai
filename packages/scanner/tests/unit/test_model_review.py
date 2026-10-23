"""Optional AI review: consent, redaction and schema validation."""

from __future__ import annotations

import pytest

from aegisai.exceptions import ConfigurationError
from aegisai.integrations.model_review import ReviewRequest, ReviewService, StaticReviewProvider
from aegisai.models.configuration import AIReviewSection
from aegisai.models.finding import Category, Confidence, Finding, Location, Severity

FAKE_KEY = "sk-proj-FAKE0000000000000000000000000000000000000000"


def _finding() -> Finding:
    return Finding(
        finding_id="x",
        rule_id="LLM001",
        rule_version="1.0.0",
        title="t",
        description="d",
        category=Category.LLM,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(file_path="a.py", start_line=1, end_line=1),
        evidence_summary=f"key {FAKE_KEY} used",
        impact="i",
        remediation="r",
        analyzer="dataflow",
        fingerprint="f" * 64,
    )


def test_disabled_by_default_and_requires_consent() -> None:
    provider = StaticReviewProvider(lambda r: {"explanation": "e", "remediation_suggestion": "r"})
    with pytest.raises(ConfigurationError, match="disabled"):
        ReviewService(AIReviewSection(), provider).review(_finding())
    settings = AIReviewSection(enabled=True, provider="static")
    with pytest.raises(ConfigurationError, match="consent"):
        ReviewService(settings, provider, consent_given=False).review(_finding())


def test_source_code_is_not_sent_unless_enabled_and_secrets_redacted() -> None:
    captured: list[ReviewRequest] = []

    def responder(request: ReviewRequest) -> dict[str, object]:
        captured.append(request)
        return {
            "explanation": f"saw {FAKE_KEY}",
            "remediation_suggestion": "rotate",
            "likely_false_positive": False,
            "priority": 2,
        }

    settings = AIReviewSection(enabled=True, provider="static")
    service = ReviewService(settings, StaticReviewProvider(responder), consent_given=True)
    result = service.review(_finding(), snippet=f"api_key = '{FAKE_KEY}'")
    assert captured[0].snippet is None
    assert FAKE_KEY not in captured[0].evidence_summary
    assert result.response is not None and FAKE_KEY not in result.response.explanation

    with_code = AIReviewSection(enabled=True, provider="static", send_source_code=True)
    service = ReviewService(with_code, StaticReviewProvider(responder), consent_given=True)
    service.review(_finding(), snippet=f"api_key = '{FAKE_KEY}'")
    assert captured[1].snippet is not None and FAKE_KEY not in captured[1].snippet


def test_invalid_provider_output_is_rejected() -> None:
    settings = AIReviewSection(enabled=True, provider="static")
    service = ReviewService(
        settings,
        StaticReviewProvider(lambda r: {"explanation": "x", "suppress": True}),
        consent_given=True,
    )
    result = service.review(_finding())
    assert result.response is None and result.error and "schema" in result.error


def test_provider_exception_is_reported_not_raised() -> None:
    def boom(request: ReviewRequest) -> dict[str, object]:
        raise RuntimeError(f"token {FAKE_KEY} leaked")

    settings = AIReviewSection(enabled=True, provider="static")
    result = ReviewService(settings, StaticReviewProvider(boom), consent_given=True).review(
        _finding()
    )
    assert result.response is None and result.error and FAKE_KEY not in result.error
