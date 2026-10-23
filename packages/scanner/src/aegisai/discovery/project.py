"""Project context: discovered files, manifests, languages and frameworks."""

from __future__ import annotations

import ast
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from aegisai.discovery.files import DiscoveredFile, DiscoveryStats, discover_files
from aegisai.discovery.frameworks import (
    FrameworkProfile,
    frameworks_from_js_source,
    frameworks_from_packages,
    frameworks_from_python_imports,
)
from aegisai.discovery.manifests import ManifestInfo, parse_manifest
from aegisai.models.configuration import ScanSection
from aegisai.models.rule import ArtifactType
from aegisai.utils.logging import get_logger

log = get_logger("project")


@dataclass(slots=True)
class ProjectContext:
    """Everything the engine knows about the scanned project before rules run."""

    root: Path
    files: list[DiscoveredFile]
    stats: DiscoveryStats
    manifests: list[ManifestInfo] = field(default_factory=list)
    languages: set[str] = field(default_factory=set)
    frameworks: FrameworkProfile = field(default_factory=FrameworkProfile)
    file_frameworks: dict[str, set[str]] = field(default_factory=dict)

    def files_of_type(self, *types: ArtifactType) -> list[DiscoveredFile]:
        wanted = set(types)
        return [f for f in self.files if f.artifact_type in wanted]


def build_project_context(
    root: Path,
    scan: ScanSection,
    *,
    extra_excludes: list[str] | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> ProjectContext:
    """Discover files and detect languages, manifests and frameworks."""
    excludes = list(scan.exclude) + list(extra_excludes or [])
    files, stats = discover_files(
        root,
        exclude=excludes,
        include=scan.include,
        max_file_size_bytes=scan.max_file_size_kb * 1024,
        max_files=scan.max_files,
        max_total_bytes=scan.max_total_size_mb * 1024 * 1024,
        follow_symlinks=scan.follow_symlinks,
        should_cancel=should_cancel,
    )
    context = ProjectContext(root=root, files=files, stats=stats)

    for discovered in files:
        if discovered.manifest_kind:
            info = parse_manifest(discovered.path, discovered.rel_path, discovered.manifest_kind)
            context.manifests.append(info)
            context.frameworks.frameworks |= frameworks_from_packages(info.packages)
        if discovered.artifact_type is ArtifactType.PYTHON:
            context.languages.add("python")
            modules = _python_imports(discovered.path)
            found = frameworks_from_python_imports(modules)
            if found:
                context.frameworks.frameworks |= found
                context.file_frameworks[discovered.rel_path] = {f.value for f in found}
        elif discovered.artifact_type in (ArtifactType.JAVASCRIPT, ArtifactType.TYPESCRIPT):
            context.languages.add(
                "typescript"
                if discovered.artifact_type is ArtifactType.TYPESCRIPT
                else "javascript"
            )
            try:
                text = discovered.path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            found = frameworks_from_js_source(text)
            if found:
                context.frameworks.frameworks |= found
                context.file_frameworks[discovered.rel_path] = {f.value for f in found}
    return context


def _python_imports(path: Path) -> set[str]:
    """Return imported module names without executing the file."""
    try:
        source = path.read_bytes()
    except OSError:
        return set()
    try:
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError, RecursionError):
        return set()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
    return modules
