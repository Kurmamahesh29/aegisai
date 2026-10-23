"""Dependency manifest parsing used for framework detection and OSV-Scanner selection."""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from aegisai.utils.logging import get_logger

log = get_logger("manifests")

# Lockfiles and manifests OSV-Scanner understands (subset; see docs/limitations.md).
OSV_SUPPORTED_MANIFESTS: frozenset[str] = frozenset(
    {
        "requirements.txt",
        "poetry.lock",
        "Pipfile.lock",
        "uv.lock",
        "pdm.lock",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "go.mod",
        "Cargo.lock",
        "Gemfile.lock",
        "pom.xml",
        "composer.lock",
        "pyproject.toml",
    }
)

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)")


@dataclass(slots=True)
class ManifestInfo:
    path: Path
    rel_path: str
    kind: str
    packages: set[str] = field(default_factory=set)
    osv_supported: bool = False


def parse_manifest(path: Path, rel_path: str, kind: str) -> ManifestInfo:
    """Extract declared package names. Parsing failures are logged and yield no packages."""
    info = ManifestInfo(
        path=path, rel_path=rel_path, kind=kind, osv_supported=path.name in OSV_SUPPORTED_MANIFESTS
    )
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.warning("cannot read manifest %s: %s", rel_path, exc)
        return info
    try:
        if path.name.startswith("requirements") and path.suffix in {".txt", ".lock"}:
            info.packages = _parse_requirements(text)
        elif path.name == "pyproject.toml":
            info.packages = _parse_pyproject(text)
        elif path.name == "package.json":
            info.packages = _parse_package_json(text)
        elif path.name == "Pipfile":
            info.packages = _parse_pipfile(text)
    except (ValueError, tomllib.TOMLDecodeError, json.JSONDecodeError) as exc:
        log.warning("cannot parse manifest %s: %s", rel_path, exc)
    return info


def _parse_requirements(text: str) -> set[str]:
    packages: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        match = _REQ_LINE.match(stripped)
        if match:
            packages.add(_normalize(match.group(1)))
    return packages


def _parse_pyproject(text: str) -> set[str]:
    data = tomllib.loads(text)
    packages: set[str] = set()
    project = data.get("project", {})
    for spec in project.get("dependencies", []) or []:
        match = _REQ_LINE.match(str(spec))
        if match:
            packages.add(_normalize(match.group(1)))
    for group in (project.get("optional-dependencies", {}) or {}).values():
        for spec in group or []:
            match = _REQ_LINE.match(str(spec))
            if match:
                packages.add(_normalize(match.group(1)))
    poetry = data.get("tool", {}).get("poetry", {})
    for name in poetry.get("dependencies", {}) or {}:
        if name.lower() != "python":
            packages.add(_normalize(name))
    return packages


def _parse_pipfile(text: str) -> set[str]:
    data = tomllib.loads(text)
    packages: set[str] = set()
    for section in ("packages", "dev-packages"):
        for name in data.get(section, {}) or {}:
            packages.add(_normalize(name))
    return packages


def _parse_package_json(text: str) -> set[str]:
    data = json.loads(text)
    packages: set[str] = set()
    if not isinstance(data, dict):
        return packages
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = data.get(section)
        if isinstance(deps, dict):
            packages.update(str(name).lower() for name in deps)
    return packages


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()
