"""Secret redaction helpers applied to every evidence snippet before it leaves the engine."""

from __future__ import annotations

import re

# Known token prefixes. Each pattern captures the whole token so it can be masked.
KNOWN_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{16,}")),
    ("anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b")),
    ("github", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("slack", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b")),
    ("google_api", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b")),
    ("stripe", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("huggingface", re.compile(r"\bhf_[A-Za-z0-9]{20,}\b")),
    ("groq", re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|-----BEGIN [A-Z ]*PRIVATE KEY-----"
        ),
    ),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.=]{16,}")),
    ("url_credentials", re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)([^:/\s@]+):([^@/\s]+)@")),
)

# key = "value" style assignments in code, config and env files.
_ASSIGNMENT = re.compile(
    r"(?i)(?P<key>[\"']?[A-Za-z0-9_.\-]*(?:api[_\-]?key|apikey|secret|passw(?:or)?d|passwd|token|credential|private[_\-]?key|auth)[A-Za-z0-9_.\-]*[\"']?\s*[:=]\s*)(?P<q>[\"'`]?)(?P<value>[^\"'`\s,;]{6,})(?P=q)"
)

_VALUE_LIKE_PLACEHOLDER = re.compile(
    r"(?i)^(?:\$\{?[a-z_]|<[^>]+>$|your[_\-]|xxx+|changeme|example|placeholder|dummy|test|none|null|redacted|\*{3,})"
)


def mask_value(value: str, keep: int = 4) -> str:
    """Mask a secret keeping a short, non-reversible prefix for recognisability."""
    if len(value) <= keep + 4:
        return "****"
    return f"{value[:keep]}****[{len(value)} chars]"


def redact_text(text: str) -> str:
    """Redact known token formats and key/value secret assignments in free text."""
    result = text
    for _name, pattern in KNOWN_TOKEN_PATTERNS:
        if _name == "url_credentials":
            result = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}:****@", result)
        elif _name == "bearer":
            result = pattern.sub(lambda m: m.group(0).split()[0] + " ****", result)
        else:
            result = pattern.sub(lambda m: mask_value(m.group(0)), result)

    def _assign(match: re.Match[str]) -> str:
        value = match.group("value")
        if (
            "****" in value
            or value.lower() in {"bearer", "basic", "token", "digest", "negotiate"}
            or _VALUE_LIKE_PLACEHOLDER.match(value)
            or value.startswith(("os.", "process.", "env.", "${", "$"))
        ):
            return match.group(0)
        quote = match.group("q")
        return f"{match.group('key')}{quote}{mask_value(value)}{quote}"

    return _ASSIGNMENT.sub(_assign, result)


def redact_known_value(text: str, secret: str) -> str:
    """Replace an exact known secret value inside ``text`` with its masked form."""
    if not secret or len(secret) < 4:
        return text
    return text.replace(secret, mask_value(secret))


def is_placeholder(value: str) -> bool:
    """True when a value is obviously not a real secret (templates, env refs, examples)."""
    stripped = value.strip().strip("\"'`")
    if not stripped:
        return True
    if _VALUE_LIKE_PLACEHOLDER.match(stripped):
        return True
    if stripped.startswith(("${", "$", "{{", "%(", "os.", "process.env", "env(", "<")):
        return True
    lowered = stripped.lower()
    if lowered in {"true", "false", "none", "null", "undefined", "changeme", "password", "secret"}:
        return True
    return bool(re.fullmatch(r"[x*#\-_.]{4,}", lowered))
