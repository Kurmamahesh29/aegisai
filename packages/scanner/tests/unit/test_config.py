"""Configuration loading and validation tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisai.config import (
    DEFAULT_CONFIG_TEMPLATE,
    find_config_file,
    load_config,
    validate_config_dict,
    write_default_config,
)
from aegisai.exceptions import ConfigurationError
from aegisai.models.configuration import Profile, ScanConfiguration, packs_for_profiles
from aegisai.models.rule import RulePack


def test_defaults_are_safe() -> None:
    config = ScanConfiguration()
    assert config.ai_review.enabled is False
    assert config.ai_review.send_source_code is False
    assert config.integrations.semgrep.enabled is False
    assert config.ci.fail_on is not None


def test_unknown_keys_are_rejected() -> None:
    with pytest.raises(ConfigurationError, match="typo_key"):
        validate_config_dict({"version": 1, "scan": {"typo_key": 1}})


def test_unsupported_version_rejected() -> None:
    with pytest.raises(ConfigurationError, match="version"):
        validate_config_dict({"version": 99})


def test_suppression_requires_target_and_reason() -> None:
    with pytest.raises(ConfigurationError):
        validate_config_dict({"suppressions": [{"reason": "ok"}]})
    with pytest.raises(ConfigurationError):
        validate_config_dict({"suppressions": [{"fingerprint": "abc", "reason": ""}]})
    config = validate_config_dict(
        {"suppressions": [{"rule_id": "SEC001", "path": "tests/**", "reason": "test fixtures"}]}
    )
    assert config.suppressions[0].path == "tests/**"


def test_ai_review_requires_provider_when_enabled() -> None:
    with pytest.raises(ConfigurationError, match="provider"):
        validate_config_dict({"ai_review": {"enabled": True}})


def test_profiles_map_to_packs() -> None:
    assert packs_for_profiles([Profile.MCP]) == frozenset({RulePack.MCP})
    assert packs_for_profiles([Profile.CODE]) == frozenset(
        {RulePack.CODE, RulePack.SECRETS, RulePack.DEPENDENCIES}
    )
    assert packs_for_profiles([Profile.ALL]) == frozenset(RulePack)


def test_default_template_is_valid_and_written(tmp_path: Path) -> None:
    target = tmp_path / ".aegisai.yaml"
    write_default_config(target)
    assert target.read_text(encoding="utf-8") == DEFAULT_CONFIG_TEMPLATE
    config = load_config(target)
    assert config.ci.fail_on is not None and config.ci.fail_on.value == "high"
    with pytest.raises(ConfigurationError, match="already exists"):
        write_default_config(target)


def test_invalid_yaml_reports_error(tmp_path: Path) -> None:
    target = tmp_path / ".aegisai.yaml"
    target.write_text("scan: [unclosed", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="invalid YAML"):
        load_config(target)


def test_find_config_walks_up(tmp_path: Path) -> None:
    (tmp_path / ".aegisai.yaml").write_text("version: 1\n", encoding="utf-8")
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert find_config_file(nested) == tmp_path / ".aegisai.yaml"
    assert load_config(None).version == 1
