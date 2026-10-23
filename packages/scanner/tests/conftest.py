"""Shared pytest fixtures and helpers."""

from __future__ import annotations

import os
import stat
import sys
import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

from aegisai.engine.runner import ScanOptions, run_scan
from aegisai.models.configuration import Profile, ScanConfiguration
from aegisai.models.finding import Finding
from aegisai.models.scan import ScanResult

REPO_ROOT = Path(__file__).resolve().parents[3]
EXAMPLES = REPO_ROOT / "examples"


@pytest.fixture
def project(tmp_path: Path) -> Callable[[dict[str, str]], Path]:
    """Create files under a temporary project root and return the root."""

    def make(files: dict[str, str]) -> Path:
        for rel, content in files.items():
            target = tmp_path / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
        return tmp_path

    return make


def scan_dir(
    root: Path,
    *,
    profiles: list[Profile] | None = None,
    config: ScanConfiguration | None = None,
    no_integrations: bool = True,
    **overrides: object,
) -> ScanResult:
    options = ScanOptions(
        root=root,
        config=config or ScanConfiguration(),
        profiles=profiles,
        no_integrations=no_integrations,
    )
    for key, value in overrides.items():
        setattr(options, key, value)
    return run_scan(options)


def findings_for(result: ScanResult, rule_id: str) -> list[Finding]:
    return [f for f in result.findings if f.rule_id == rule_id]


def rule_ids(result: ScanResult) -> set[str]:
    return {f.rule_id for f in result.findings}


def scan_code(
    make_project: Callable[[dict[str, str]], Path],
    code: str,
    *,
    filename: str = "app.py",
    profiles: list[Profile] | None = None,
) -> ScanResult:
    root = make_project({filename: code})
    return scan_dir(root, profiles=profiles)


def make_fake_executable(directory: Path, name: str, python_source: str) -> Path:
    """Create a runnable fake scanner implemented in Python (cross-platform)."""
    script = directory / f"{name}_impl.py"
    script.write_text(textwrap.dedent(python_source).lstrip("\n"), encoding="utf-8")
    if sys.platform.startswith("win"):
        wrapper = directory / f"{name}.bat"
        wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
    else:
        wrapper = directory / name
        wrapper.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8"
        )
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return wrapper


def can_symlink(tmp_path: Path) -> bool:
    target = tmp_path / "_symlink_target"
    target.write_text("x", encoding="utf-8")
    link = tmp_path / "_symlink_probe"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        return False
    finally:
        if link.exists() or link.is_symlink():
            link.unlink()
        target.unlink()
    return True
