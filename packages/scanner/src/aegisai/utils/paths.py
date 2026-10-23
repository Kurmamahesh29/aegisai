"""Safe path handling: root containment, symlink policy and glob matching."""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path

from aegisai.exceptions import ProjectRootError


def resolve_root(path: str | os.PathLike[str]) -> Path:
    """Resolve and validate a scan root.

    The root must exist and be a directory. Symlinked roots are resolved to their target so
    that containment checks are performed against the real location.
    """
    candidate = Path(path).expanduser()
    if not candidate.exists():
        raise ProjectRootError(f"scan root does not exist: {candidate}")
    resolved = candidate.resolve()
    if not resolved.is_dir():
        raise ProjectRootError(f"scan root is not a directory: {resolved}")
    return resolved


def is_within(root: Path, candidate: Path) -> bool:
    """True when ``candidate`` (already resolved) is inside ``root`` (already resolved)."""
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def to_posix_relative(root: Path, path: Path) -> str:
    """Return ``path`` relative to ``root`` using forward slashes."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = Path(os.path.relpath(path, root))
    return rel.as_posix()


_UNSAFE_NAME = re.compile(r"[\x00-\x1f\x7f]")


def is_safe_filename(name: str) -> bool:
    """Reject names containing control characters or traversal components."""
    if not name or name in {".", ".."}:
        return False
    if _UNSAFE_NAME.search(name):
        return False
    return "/" not in name and "\\" not in name


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a gitignore-like glob (supporting ``**``) into a regex over POSIX paths."""
    pattern = pattern.replace("\\", "/").strip()
    anchored = pattern.startswith("/")
    pattern = pattern.lstrip("/")
    parts = pattern.split("/")
    regex_parts: list[str] = []
    for index, part in enumerate(parts):
        last = index == len(parts) - 1
        if part == "**":
            regex_parts.append("(?:.*/)?" if not last else ".*")
            continue
        translated = fnmatch.translate(part)
        # fnmatch.translate wraps with (?s:...)\Z; strip the wrapper and keep the body.
        body = translated[4:-3] if translated.startswith("(?s:") else translated
        body = body.replace(".*", "[^/]*")
        regex_parts.append(body + ("" if last else "/"))
    regex = "".join(regex_parts)
    if not anchored and not pattern.startswith("**"):
        # Unanchored patterns ("node_modules/**", "*.min.js", "build/**") match at any depth.
        # Prefix a pattern with "/" to anchor it to the scan root.
        regex = "(?:.*/)?" + regex
    return re.compile("^" + regex + "$")


class PathMatcher:
    """Match POSIX relative paths against include and exclude glob lists."""

    def __init__(self, exclude: list[str], include: list[str] | None = None) -> None:
        self._exclude = [_glob_to_regex(p) for p in exclude]
        self._exclude_dirs = [_glob_to_regex(p.removesuffix("/**")) for p in exclude]
        self._include = [_glob_to_regex(p) for p in (include or [])]

    def is_excluded(self, rel_posix: str, is_dir: bool = False) -> bool:
        for regex in self._exclude:
            if regex.match(rel_posix):
                return True
        if is_dir:
            for regex in self._exclude_dirs:
                if regex.match(rel_posix):
                    return True
        return False

    def is_included(self, rel_posix: str) -> bool:
        if not self._include:
            return True
        return any(regex.match(rel_posix) for regex in self._include)


def path_matches(rel_posix: str, pattern: str) -> bool:
    """Public helper used by suppressions and rule overrides."""
    return _glob_to_regex(pattern).match(rel_posix) is not None
