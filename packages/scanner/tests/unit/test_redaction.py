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


def test_secret_scanner_ignores_fixture_values_and_references() -> None:
    """Patterns observed on open-source repositories that are not credentials."""
    text = "\n".join(
        [
            'ANTHROPIC_API_KEY = "fake-anthropic-key-12345"',
            'access_token = "synthetic-access-token-1"',
            'access_token = "TOKEN_A_ORIGINAL"',
            'client_secret = "my-client-secret"',
            'jwt_signing_key = "replace-with-your-own-key"',
            'OPENAI_API_KEY = "fixture-openai"',
            'JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"',
            'OPENAI_API_KEY_SOURCE = "fixture-openai-source"',
            "# Tokens: `GITHUB_TOKEN` files and comments",
            'SUPABASE_PUBLIC_API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.abcdefghijklmnop"',
            'regex = """private_key = (?i)-----BEGIN [A-Z ]*PRIVATE KEY-----"""',
            'streaming-tokens-without-langchain = "https://docs.example.com/how-to/streaming-tokens"',
        ]
    )
    assert scan_text_for_secrets(text) == []


def test_secret_scanner_still_catches_real_shapes() -> None:
    text = "\n".join(
        [
            # Deliberately not shaped like a real provider token (GitHub push protection).
            'STAGING_SECRET_ACCESS_KEY = "Zq9kLm2p0Xy7Rt4vB1cE5hJ7.kM0oS"',
            'password = "Schr0dinger!Cat42"',
            'DATABASE_URL = "postgres://app:Zq9kLm2p0Xy7Rt4v@db.internal:5432/app"',
        ]
    )
    matches = scan_text_for_secrets(text)
    assert [m.line for m in matches] == [1, 2, 3]
    assert matches[2].detector == "url_credentials" and matches[2].value == "Zq9kLm2p0Xy7Rt4v"


def test_secret_scanner_labels_default_urls_and_public_keys() -> None:
    text = "\n".join(
        [
            '"ANTHROPIC_API_KEY": "Anthropic",',
            'DB = "postgresql://postgres:postgres@localhost:5432/db"',
            'DB2 = "postgresql://app:password@localhost:5432/db"',
            'POSTHOG_API_KEY = "phc_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJK"',
        ]
    )
    matches = scan_text_for_secrets(text)
    assert [(m.line, m.confidence) for m in matches] == [(4, "low")]
