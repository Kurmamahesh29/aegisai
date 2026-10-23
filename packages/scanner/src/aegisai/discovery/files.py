"""Safe file discovery with exclusions, size limits and symlink containment."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from aegisai.models.rule import ArtifactType
from aegisai.utils.logging import get_logger
from aegisai.utils.paths import PathMatcher, is_safe_filename, is_within, to_posix_relative

log = get_logger("discovery")

EXTENSION_TYPES: dict[str, ArtifactType] = {
    ".py": ArtifactType.PYTHON,
    ".pyi": ArtifactType.PYTHON,
    ".js": ArtifactType.JAVASCRIPT,
    ".mjs": ArtifactType.JAVASCRIPT,
    ".cjs": ArtifactType.JAVASCRIPT,
    ".jsx": ArtifactType.JAVASCRIPT,
    ".ts": ArtifactType.TYPESCRIPT,
    ".mts": ArtifactType.TYPESCRIPT,
    ".cts": ArtifactType.TYPESCRIPT,
    ".tsx": ArtifactType.TYPESCRIPT,
    ".json": ArtifactType.JSON,
    ".jsonc": ArtifactType.JSON,
    ".yaml": ArtifactType.YAML,
    ".yml": ArtifactType.YAML,
    ".toml": ArtifactType.TOML,
    ".env": ArtifactType.ENV,
    ".txt": ArtifactType.TEXT,
    ".md": ArtifactType.TEXT,
    ".cfg": ArtifactType.TEXT,
    ".ini": ArtifactType.TEXT,
    ".properties": ArtifactType.TEXT,
    ".sh": ArtifactType.TEXT,
    ".ps1": ArtifactType.TEXT,
}

MANIFEST_NAMES: dict[str, str] = {
    "requirements.txt": "pip",
    "requirements-dev.txt": "pip",
    "requirements.lock": "pip",
    "pyproject.toml": "pyproject",
    "poetry.lock": "poetry",
    "Pipfile": "pipenv",
    "Pipfile.lock": "pipenv",
    "uv.lock": "uv",
    "pdm.lock": "pdm",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "go.mod": "go",
    "Cargo.lock": "cargo",
    "Gemfile.lock": "bundler",
    "pom.xml": "maven",
    "composer.lock": "composer",
}

ENV_FILE_NAMES = {".env", ".env.local", ".env.development", ".env.production", ".env.example"}


@dataclass(slots=True)
class DiscoveredFile:
    """A file selected for scanning."""

    path: Path
    rel_path: str
    size: int
    artifact_type: ArtifactType
    manifest_kind: str | None = None


@dataclass(slots=True)
class DiscoveryStats:
    files_seen: int = 0
    files_selected: int = 0
    skipped_excluded: int = 0
    skipped_too_large: int = 0
    skipped_symlink: int = 0
    skipped_unsafe_name: int = 0
    skipped_limit: int = 0
    skipped_binary_or_unknown: int = 0
    total_bytes: int = 0
    warnings: list[str] = field(default_factory=list)


def classify(path: Path) -> tuple[ArtifactType | None, str | None]:
    """Return (artifact type, manifest kind) for a file name, or (None, None) if ignored."""
    name = path.name
    manifest = MANIFEST_NAMES.get(name)
    if name in ENV_FILE_NAMES or name.startswith(".env."):
        return ArtifactType.ENV, manifest
    if name == "Dockerfile" or name.startswith("Dockerfile."):
        return ArtifactType.TEXT, manifest
    artifact = EXTENSION_TYPES.get(path.suffix.lower())
    if artifact is None and manifest is not None:
        artifact = ArtifactType.MANIFEST
    return artifact, manifest


def discover_files(
    root: Path,
    *,
    exclude: list[str],
    include: list[str] | None = None,
    max_file_size_bytes: int,
    max_files: int,
    max_total_bytes: int,
    follow_symlinks: bool = False,
    should_cancel: Callable[[], bool] | None = None,
) -> tuple[list[DiscoveredFile], DiscoveryStats]:
    """Walk ``root`` and return scannable files plus statistics.

    Safety properties:
    - Never leaves ``root`` (symlinks pointing outside are skipped).
    - Symlinks inside the root are followed only when ``follow_symlinks`` is True.
    - Files larger than ``max_file_size_bytes`` are skipped and counted.
    - Stops after ``max_files`` or ``max_total_bytes`` and records a warning.
    """
    matcher = PathMatcher(exclude, include)
    stats = DiscoveryStats()
    selected: list[DiscoveredFile] = []

    for entry in _walk(root, matcher, stats, follow_symlinks):
        if should_cancel is not None and should_cancel():
            stats.warnings.append("file discovery cancelled")
            break
        if len(selected) >= max_files:
            stats.skipped_limit += 1
            if len(stats.warnings) == 0 or "max_files" not in stats.warnings[-1]:
                stats.warnings.append(
                    f"max_files limit ({max_files}) reached; remaining files were not scanned"
                )
            continue
        stats.files_seen += 1
        artifact, manifest = classify(entry)
        if artifact is None:
            stats.skipped_binary_or_unknown += 1
            continue
        try:
            stat = entry.stat()
        except OSError as exc:
            stats.warnings.append(f"cannot stat {entry}: {exc}")
            continue
        if stat.st_size > max_file_size_bytes:
            stats.skipped_too_large += 1
            continue
        if stats.total_bytes + stat.st_size > max_total_bytes:
            stats.skipped_limit += 1
            if not stats.warnings or "max_total_size" not in stats.warnings[-1]:
                stats.warnings.append(
                    "max_total_size limit reached; remaining files were not scanned"
                )
            continue
        rel = to_posix_relative(root, entry)
        if not matcher.is_included(rel):
            stats.skipped_excluded += 1
            continue
        stats.total_bytes += stat.st_size
        selected.append(
            DiscoveredFile(
                path=entry,
                rel_path=rel,
                size=stat.st_size,
                artifact_type=artifact,
                manifest_kind=manifest,
            )
        )
    stats.files_selected = len(selected)
    selected.sort(key=lambda f: f.rel_path)
    return selected, stats


def _walk(
    root: Path, matcher: PathMatcher, stats: DiscoveryStats, follow_symlinks: bool
) -> Iterator[Path]:
    """Deterministic, containment-checked directory walk."""
    stack: list[Path] = [root]
    visited: set[tuple[int, int]] = set()
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda e: e.name, reverse=True)
        except PermissionError as exc:
            stats.warnings.append(f"permission denied: {directory} ({exc.strerror})")
            continue
        except OSError as exc:
            stats.warnings.append(f"cannot read directory {directory}: {exc}")
            continue
        for entry in entries:
            if not is_safe_filename(entry.name):
                stats.skipped_unsafe_name += 1
                continue
            path = Path(entry.path)
            rel = to_posix_relative(root, path)
            try:
                is_symlink = entry.is_symlink()
            except OSError:
                is_symlink = False
            if is_symlink:
                if not follow_symlinks:
                    stats.skipped_symlink += 1
                    continue
                try:
                    target = path.resolve(strict=True)
                except OSError:
                    stats.skipped_symlink += 1
                    continue
                if not is_within(root, target):
                    stats.skipped_symlink += 1
                    log.debug("skipping symlink escaping root: %s", rel)
                    continue
            try:
                is_dir = entry.is_dir(follow_symlinks=follow_symlinks)
            except OSError:
                continue
            if is_dir:
                if matcher.is_excluded(rel, is_dir=True) or matcher.is_excluded(rel + "/"):
                    stats.skipped_excluded += 1
                    continue
                try:
                    st = entry.stat(follow_symlinks=follow_symlinks)
                    key = (st.st_dev, st.st_ino)
                except OSError:
                    key = (0, 0)
                if key != (0, 0):
                    if key in visited:
                        continue
                    visited.add(key)
                stack.append(path)
                continue
            if matcher.is_excluded(rel):
                stats.skipped_excluded += 1
                continue
            if entry.is_file(follow_symlinks=follow_symlinks):
                yield path
