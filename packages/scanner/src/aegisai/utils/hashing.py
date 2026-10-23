"""Stable fingerprints and ids for findings."""

from __future__ import annotations

import hashlib
import re

_WS = re.compile(r"\s+")


def normalize_snippet(snippet: str) -> str:
    """Collapse whitespace so that re-indentation does not change a fingerprint."""
    return _WS.sub(" ", snippet.strip())


def fingerprint(rule_id: str, rel_path: str, snippet: str, occurrence: int = 0) -> str:
    """Return a stable fingerprint.

    The fingerprint intentionally excludes line numbers, timestamps and absolute paths so
    that moving code within a file or scanning from a different checkout location keeps the
    same identity. ``occurrence`` disambiguates identical snippets within one file.
    """
    material = "\x1f".join(
        [
            "aegisai-fp-v1",
            rule_id,
            rel_path.replace("\\", "/"),
            normalize_snippet(snippet),
            str(occurrence),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def short_id(*parts: str, length: int = 12) -> str:
    """Short deterministic identifier derived from ``parts``."""
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return digest[:length]


def sha256_file(path: str, chunk_size: int = 1 << 16) -> str:
    """Hex digest of a file's contents."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()
