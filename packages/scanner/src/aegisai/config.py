"""Loading, validating and rendering ``.aegisai.yaml`` configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from aegisai.exceptions import ConfigurationError
from aegisai.models.configuration import DEFAULT_CONFIG_FILENAME, ScanConfiguration

DEFAULT_CONFIG_TEMPLATE = """# AegisAI configuration. See docs/configuration.md for every option.
version: 1

scan:
  profiles:
    - all
  exclude:
    - .git/**
    - .venv/**
    - venv/**
    - node_modules/**
    - dist/**
    - build/**
    - __pycache__/**
  max_file_size_kb: 1024
  timeout_seconds: 300

rules:
  disabled: []
  overrides: {}

report:
  formats:
    - terminal
    - json
  output_dir: .aegisai-reports

ci:
  fail_on: high
  # When true, an enabled integration that is not installed makes the scan incomplete (exit 3).
  strict_integrations: false

integrations:
  gitleaks:
    enabled: true
    required: false
  osv_scanner:
    enabled: true
    required: false
  semgrep:
    enabled: false
    config: []   # explicit local rule files or directories only

# Optional, disabled by default. Source code is never transmitted without explicit consent.
ai_review:
  enabled: false
  provider: null
  require_explicit_consent: true
  redact_secrets: true

# Suppressions need a reason and target a fingerprint or a rule_id + path.
suppressions: []
"""


def find_config_file(start: Path) -> Path | None:
    """Return the nearest ``.aegisai.yaml`` at or above ``start``."""
    current = start.resolve()
    for candidate in [current, *current.parents]:
        path = candidate / DEFAULT_CONFIG_FILENAME
        if path.is_file():
            return path
    return None


def load_config(path: Path | None) -> ScanConfiguration:
    """Load configuration from ``path`` or return defaults when ``path`` is None."""
    if path is None:
        return ScanConfiguration()
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"cannot read configuration {path}: {exc}") from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"invalid YAML in {path}: {exc}") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigurationError(f"configuration root in {path} must be a mapping")
    return validate_config_dict(data, source=str(path))


def validate_config_dict(data: dict[str, Any], *, source: str = "<config>") -> ScanConfiguration:
    """Validate a raw mapping. Unknown keys are rejected to catch typos."""
    try:
        return ScanConfiguration.model_validate(data)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or '<root>'}: {err['msg']}"
            for err in exc.errors()
        )
        raise ConfigurationError(f"invalid configuration in {source}: {details}") from exc


def write_default_config(path: Path, *, force: bool = False) -> Path:
    """Write the documented default configuration. Refuses to overwrite unless ``force``."""
    if path.exists() and not force:
        raise ConfigurationError(f"{path} already exists; use --force to overwrite")
    # Validate the template so the shipped default can never be invalid.
    validate_config_dict(yaml.safe_load(DEFAULT_CONFIG_TEMPLATE), source="default template")
    path.write_text(DEFAULT_CONFIG_TEMPLATE, encoding="utf-8")
    return path
