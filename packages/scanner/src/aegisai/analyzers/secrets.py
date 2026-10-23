"""Built-in, regex-based secret detection (complements Gitleaks when it is installed)."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from aegisai.utils.redaction import KNOWN_TOKEN_PATTERNS, is_placeholder

# Assignment of a secret-looking key to a quoted literal in code, config, env and YAML.
ASSIGNMENT_PATTERN = re.compile(
    r"""(?ix)
    (?P<key>
        [\"']?
        [A-Za-z0-9_.\-]*
        (?:api[_\-]?key|apikey|secret|passw(?:or)?d|passwd|private[_\-]?key|access[_\-]?token|
           auth[_\-]?token|refresh[_\-]?token|client[_\-]?secret|credentials?|signing[_\-]?key|
           encryption[_\-]?key|master[_\-]?key|service[_\-]?key|bearer|token)
        [A-Za-z0-9_.\-]*
        [\"']?
    )
    \s*[:=]\s*
    (?P<quote>[\"'`])
    (?P<value>[^\"'`\r\n]{8,})
    (?P=quote)
    """
)

_KEY_EXCLUDE = re.compile(
    r"(?i)(max_tokens|num_tokens|token_count|tokenizer|token_type|public_key|key_name|cache_key|"
    r"primary_key|foreign_key|secret_name|password_field|token_usage|key_id|key_file|"
    r"token_url|tokens_url|secret_arn|secret_id|_header$|_name$|_path$|_file$|_env$|"
    r"_var$|_field$|_param$|_url$|_endpoint$|_label$|_prefix$|_length$|_len$|_count$|_size$|"
    r"_ttl$|_expiry$|_expires$|_lifetime$|_format$|_version$|_type$|_source$|_grant$|"
    r"_mode$|_scope$|_scheme$|_method$|_kind$|_class$|public|tokens)"
)

# Tokens (split on - _ . : and whitespace) that mark a value as a fixture or description rather
# than a real credential: "fake-anthropic-key", "synthetic-token-1", "TOKEN_A", "my-client-secret".
_PLACEHOLDER_WORDS = frozenset(
    {
        "fake",
        "dummy",
        "test",
        "testing",
        "tests",
        "example",
        "examples",
        "sample",
        "placeholder",
        "replace",
        "your",
        "changeme",
        "mock",
        "mocked",
        "invalid",
        "redacted",
        "synthetic",
        "fixture",
        "stale",
        "fresh",
        "expired",
        "original",
        "changed",
        "wrong",
        "old",
        "new",
        "provider",
        "injected",
        "ephemeral",
        "unit",
        "my",
        "plaintext",
        "from",
        "scoped",
        "token",
        "tokens",
        "secret",
        "secrets",
        "password",
        "passwd",
        "key",
        "apikey",
        "dev",
        "local",
        "demo",
        "foo",
        "bar",
        "baz",
        "xxx",
        "abc",
        "abcd",
        "here",
        "value",
        "string",
        "insert",
        "todo",
        "tbd",
        "none",
        "null",
        "unset",
        "empty",
        "missing",
        "bogus",
        "phony",
        "random",
        "not",
        "real",
        "valid",
        "bad",
        "good",
        "some",
        "any",
        "other",
        "another",
        "first",
        "second",
        "initial",
        "updated",
        "rotated",
        "temp",
        "temporary",
        "default",
        "credential",
        "credentials",
        "signing",
    }
)
_CONSTANT_CASE = re.compile(r"^[A-Z][A-Z0-9_]{3,}$")
# A single dictionary-looking word ("Anthropic", "perplexity") is a label, not a credential.
_DICTIONARY_WORD = re.compile(r"^(?:[A-Z][a-z]{2,14}|[a-z]{3,14})$")
# Client-side keys that providers document as public; reported at low severity only.
_PUBLIC_KEY_PREFIXES = ("phc_", "pk_live_", "pk_test_", "pub_", "public_", "anon_")
# Default/demo credentials in connection strings ("postgres://postgres:postgres@localhost").
_DEFAULT_URL_PASSWORDS = frozenset(
    {
        "postgres",
        "password",
        "admin",
        "root",
        "guest",
        "mysql",
        "redis",
        "user",
        "secret",
        "pass",
        "test",
        "example",
    }
)
_SCHEME_VALUE = re.compile(r"^[a-z][a-z0-9+.\-]*:(?://)?[^\s]+$", re.IGNORECASE)
_REGEX_LIKE = re.compile(r"\(\?|\[A-Z|\[a-z|\[0-9|\\[bdws]|\{\d+,\d*\}|\|\^|\$$")


def _value_tokens(value: str) -> list[str]:
    return [t for t in re.split(r"[-_.:\s/]+", value) if t]


def _is_fixture_value(value: str) -> bool:
    """True when the value is clearly descriptive text rather than a credential."""
    tokens = _value_tokens(value)
    if len(tokens) >= 2 and any(t.lower() in _PLACEHOLDER_WORDS for t in tokens):
        return True
    return len(tokens) == 1 and value.lower() in _PLACEHOLDER_WORDS


_CODE_LIKE_VALUE = re.compile(
    r"(?i)^(?:os\.|process\.|env\.|config\.|settings\.|\$\{|\{\{|%\(|<|\$[A-Z_]|get_|load_|read_)"
)


@dataclass(slots=True)
class SecretMatch:
    """A detected secret literal. ``value`` must be redacted before reporting."""

    line: int
    column: int
    end_column: int
    key: str | None
    value: str
    detector: str
    confidence: str


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


_PATH_LIKE_VALUE = re.compile(
    r"^(?:\.{0,2}/|[A-Za-z]:\\|[\w.\-]+[/\\])[\w.\-/\\]*\.[A-Za-z0-9]{1,6}$"
)


def _looks_like_secret_value(value: str) -> bool:
    if is_placeholder(value) or _CODE_LIKE_VALUE.match(value):
        return False
    if _PATH_LIKE_VALUE.match(value):
        # File paths such as "bin/secretlint.js" or "./keys/public.pem" are not secrets.
        return False
    if _CONSTANT_CASE.match(value):
        # A reference to a variable name ("GITHUB_TOKEN"), not a value.
        return False
    if _SCHEME_VALUE.match(value):
        # URLs and URNs; credentials embedded in URLs are caught by the url_credentials detector.
        return False
    if _REGEX_LIKE.search(value):
        # Regular expressions in scanner configs (gitleaks.toml, semgrep rules).
        return False
    if _is_fixture_value(value):
        return False
    if _DICTIONARY_WORD.match(value):
        return False
    if " " in value.strip() and len(value) < 40:
        # Sentences and labels are not secrets ("Enter your password").
        return False
    if re.fullmatch(r"[A-Za-z]+", value) and value.lower() in {
        "password",
        "secret",
        "changeme",
        "example",
        "default",
        "undefined",
    }:
        return False
    if re.fullmatch(r"[a-z_]+", value):
        # snake_case identifiers (e.g. variable names used as string keys).
        return False
    return shannon_entropy(value) >= 3.0 or len(value) >= 20


UNQUOTED_ASSIGNMENT_PATTERN = re.compile(
    r"""(?ix)
    (?P<key>
        [A-Za-z0-9_.\-]*
        (?:api[_\-]?key|apikey|secret|passw(?:or)?d|passwd|private[_\-]?key|access[_\-]?token|
           auth[_\-]?token|refresh[_\-]?token|client[_\-]?secret|credentials?|signing[_\-]?key|
           encryption[_\-]?key|master[_\-]?key|service[_\-]?key|bearer|token)
        [A-Za-z0-9_.\-]*
    )
    \s*[:=]\s*
    (?P<quote>)
    (?P<value>[^\s"'`#,;]{8,})
    \s*(?:\#.*)?$
    """
)


def scan_text_for_secrets(text: str, *, allow_unquoted: bool = False) -> list[SecretMatch]:
    """Find secret literals line by line. Comments are not special-cased on purpose.

    ``allow_unquoted`` enables ``KEY=value`` / ``key: value`` detection for .env and YAML files
    where values are conventionally unquoted.
    """
    matches: list[SecretMatch] = []
    seen: set[tuple[int, int]] = set()
    for line_no, line in enumerate(text.splitlines(), start=1):
        if len(line) > 2000:
            continue
        assignment = ASSIGNMENT_PATTERN.search(line)
        if assignment is None and allow_unquoted:
            assignment = UNQUOTED_ASSIGNMENT_PATTERN.search(line)
        for detector, pattern in KNOWN_TOKEN_PATTERNS:
            if detector in {"bearer", "jwt"}:
                continue
            for match in pattern.finditer(line):
                value = match.group(3) if detector == "url_credentials" else match.group(0)
                if detector == "url_credentials" and (
                    len(value) < 6
                    or is_placeholder(value)
                    or _is_fixture_value(value)
                    or value.lower() in _DEFAULT_URL_PASSWORDS
                    or value.lower() == match.group(2).lower()
                ):
                    continue
                if detector == "private_key" or not is_placeholder(value):
                    position = (line_no, match.start())
                    if position in seen:
                        continue
                    seen.add(position)
                    label: str | None = None
                    if assignment and assignment.start("value") <= match.start() < assignment.end(
                        "value"
                    ):
                        label = assignment.group("key").strip("\"'")
                    matches.append(
                        SecretMatch(
                            line=line_no,
                            column=match.start() + 1,
                            end_column=match.end(),
                            key=label,
                            value=value,
                            detector=detector,
                            confidence="high",
                        )
                    )
        assignment_matches = list(ASSIGNMENT_PATTERN.finditer(line))
        if not assignment_matches and allow_unquoted:
            assignment_matches = list(UNQUOTED_ASSIGNMENT_PATTERN.finditer(line))
        for match in assignment_matches:
            key = match.group("key").strip("\"'")
            value = match.group("value")
            if _KEY_EXCLUDE.search(key):
                continue
            if not _looks_like_secret_value(value):
                continue
            start = match.start("value")
            if any(abs(start - col) < 3 and ln == line_no for ln, col in seen):
                continue
            seen.add((line_no, start))
            matches.append(
                SecretMatch(
                    line=line_no,
                    column=start + 1,
                    end_column=match.end("value"),
                    key=key,
                    value=value,
                    detector="assignment",
                    confidence=(
                        "low"
                        if value.lower().startswith(_PUBLIC_KEY_PREFIXES)
                        else ("medium" if shannon_entropy(value) < 3.5 else "high")
                    ),
                )
            )
    return matches
