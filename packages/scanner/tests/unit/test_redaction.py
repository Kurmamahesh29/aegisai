"""Secret redaction tests."""

from __future__ import annotations

from aegisai.analyzers.secrets import scan_text_for_secrets
from aegisai.utils.redaction import is_placeholder, mask_value, redact_known_value, redact_text

FAKE_OPENAI = "sk-proj-FAKE0000000000000000000000000000000000000000"
FAKE_AWS = "AKIAFAKEFAKEFAKEFAKE"


def test_known_tokens_are_masked() -> None:
    text = f"key={FAKE_OPENAI} aws={FAKE_AWS}"
    redacted = redact_text(text)
    assert FAKE_OPENAI not in redacted
    assert FAKE_AWS not in redacted
    assert "sk-p****" in redacted


def test_assignment_values_are_masked_but_placeholders_kept() -> None:
    assert "hunter2hunter2" not in redact_text('password = "hunter2hunter2"')
    assert redact_text('password = "${DB_PASSWORD}"') == 'password = "${DB_PASSWORD}"'
    assert redact_text("api_key = os.environ['X']") == "api_key = os.environ['X']"
    assert redact_text('token = "<your-token>"') == 'token = "<your-token>"'


def test_already_masked_values_are_not_double_masked() -> None:
    once = redact_text("GITHUB_TOKEN = ghp_FAKE000000000000000000000000000000ABCD")
    assert redact_text(once) == once


def test_url_credentials_and_bearer() -> None:
    assert redact_text("https://user:s3cretpassw0rd@host/db") == "https://user:****@host/db"
    assert "Bearer ****" in redact_text("Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123")


def test_mask_value_and_known_value() -> None:
    assert mask_value("short") == "****"
    assert mask_value("abcdefghijklmnop").startswith("abcd****")
    assert redact_known_value("x=abcdefghijklmnop", "abcdefghijklmnop") == "x=abcd****[16 chars]"


def test_placeholders() -> None:
    assert is_placeholder("changeme")
    assert is_placeholder("${TOKEN}")
    assert is_placeholder("xxxxxxxx")
    assert not is_placeholder("Zq9!kLm2p0Xy7Rt4")


def test_secret_scanner_detects_and_skips_placeholders() -> None:
    text = "\n".join(
        [
            f'OPENAI_API_KEY = "{FAKE_OPENAI}"',
            'db_password = "Zq9kLm2p0Xy7Rt4vB1"',
            'password = "changeme"',
            'api_key = os.environ["API_KEY"]',
            'token_url = "https://example.com/oauth/token"',
            "max_tokens = 1024",
        ]
    )
    matches = scan_text_for_secrets(text)
    lines = sorted(m.line for m in matches)
    assert lines == [1, 2]
    assert matches[0].key == "OPENAI_API_KEY"
    assert matches[0].confidence == "high"
