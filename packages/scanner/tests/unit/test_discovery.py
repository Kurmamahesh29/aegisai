"""File discovery safety tests: exclusions, size limits, symlinks, unsafe names, limits."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aegisai.discovery.files import discover_files
from aegisai.discovery.project import build_project_context
from aegisai.models.configuration import ScanSection
from aegisai.utils.paths import PathMatcher, path_matches
from conftest import can_symlink


def _discover(root: Path, **kw: object):
    defaults: dict[str, object] = {
        "exclude": [".git/**", "node_modules/**", "*.min.js"],
        "max_file_size_bytes": 1024,
        "max_files": 100,
        "max_total_bytes": 1 << 20,
    }
    defaults.update(kw)
    return discover_files(root, **defaults)  # type: ignore[arg-type]


def test_excludes_and_classification(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print(1)\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("x", encoding="utf-8")
    (tmp_path / "lib.min.js").write_text("x", encoding="utf-8")
    (tmp_path / "image.png").write_bytes(b"\x89PNG")
    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    files, stats = _discover(tmp_path)
    rel = {f.rel_path for f in files}
    assert rel == {"app.py", "requirements.txt"}
    assert stats.skipped_excluded >= 2
    assert stats.skipped_binary_or_unknown == 1
    manifest = next(f for f in files if f.rel_path == "requirements.txt")
    assert manifest.manifest_kind == "pip"


def test_oversized_files_are_skipped(tmp_path: Path) -> None:
    (tmp_path / "big.py").write_text("x" * 5000, encoding="utf-8")
    (tmp_path / "small.py").write_text("x", encoding="utf-8")
    files, stats = _discover(tmp_path)
    assert [f.rel_path for f in files] == ["small.py"]
    assert stats.skipped_too_large == 1


def test_max_files_limit_records_warning(tmp_path: Path) -> None:
    for i in range(5):
        (tmp_path / f"f{i}.py").write_text("x", encoding="utf-8")
    files, stats = _discover(tmp_path, max_files=2)
    assert len(files) == 2
    assert stats.skipped_limit == 3
    assert any("max_files" in w for w in stats.warnings)


def test_symlink_escaping_root_is_never_followed(tmp_path: Path) -> None:
    if not can_symlink(tmp_path):
        pytest.skip("symlinks not supported in this environment")
    outside = tmp_path.parent / f"{tmp_path.name}_outside"
    outside.mkdir(exist_ok=True)
    (outside / "secret.py").write_text("TOKEN = 'x'\n", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    (root / "inner.py").write_text("x", encoding="utf-8")
    os.symlink(outside, root / "escape", target_is_directory=True)
    os.symlink(outside / "secret.py", root / "escape.py")
    files, stats = _discover(root, follow_symlinks=True)
    assert {f.rel_path for f in files} == {"inner.py"}
    assert stats.skipped_symlink >= 2
    files_no_follow, _ = _discover(root, follow_symlinks=False)
    assert {f.rel_path for f in files_no_follow} == {"inner.py"}


def test_symlink_inside_root_followed_only_when_enabled(tmp_path: Path) -> None:
    if not can_symlink(tmp_path):
        pytest.skip("symlinks not supported in this environment")
    (tmp_path / "real.py").write_text("x", encoding="utf-8")
    os.symlink(tmp_path / "real.py", tmp_path / "link.py")
    files_default, _ = _discover(tmp_path)
    assert {f.rel_path for f in files_default} == {"real.py"}
    files_follow, _ = _discover(tmp_path, follow_symlinks=True)
    assert {f.rel_path for f in files_follow} == {"link.py", "real.py"}


def test_glob_matcher_semantics() -> None:
    matcher = PathMatcher(["node_modules/**", "*.min.js", "build/**", "/dist/**"])
    assert matcher.is_excluded("node_modules/a/b.js")
    assert matcher.is_excluded("pkg/node_modules/x.js")
    assert matcher.is_excluded("static/app.min.js")
    assert matcher.is_excluded("build", is_dir=True)
    assert matcher.is_excluded("dist/x.py")
    assert not matcher.is_excluded("src/dist_utils.py")
    assert not matcher.is_excluded("src/app.py")
    assert path_matches("tests/unit/test_x.py", "tests/**")
    assert not path_matches("src/x.py", "tests/**")


def test_project_context_detects_frameworks_and_languages(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import openai\nfrom langchain_core.tools import tool\n", encoding="utf-8"
    )
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n", encoding="utf-8"
    )
    (tmp_path / "package.json").write_text('{"dependencies": {"ai": "^3.0.0"}}', encoding="utf-8")
    context = build_project_context(tmp_path, ScanSection())
    names = context.frameworks.sorted_names()
    assert {"openai", "langchain", "mcp-typescript", "vercel-ai"} <= set(names)
    assert context.languages == {"python", "typescript"}
    assert context.frameworks.has_ai and context.frameworks.has_mcp
