"""Helpers for structured configuration files (MCP client/server configs, app settings).

Values are located by walking parsed JSON/YAML; line numbers are recovered by searching the
source text for the key so that findings point at a real location.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

MCP_CONFIG_FILENAMES: frozenset[str] = frozenset(
    {
        "claude_desktop_config.json",
        ".mcp.json",
        "mcp.json",
        "mcp_config.json",
        "mcp-config.json",
        "mcp_servers.json",
        "mcp-servers.json",
        "servers.json",
        "mcp.yaml",
        "mcp.yml",
        "mcp_config.yaml",
        "mcp-config.yaml",
        "settings.json",
        "cline_mcp_settings.json",
        "continue.json",
        "config.yaml",
        "config.json",
    }
)

MCP_SERVER_KEYS: tuple[str, ...] = ("mcpServers", "mcp_servers", "servers", "mcp")


@dataclass(slots=True)
class ConfigValue:
    """A scalar located in a structured config document."""

    path: tuple[str, ...]
    value: Any
    line: int
    column: int

    @property
    def key(self) -> str:
        return self.path[-1] if self.path else ""

    @property
    def dotted(self) -> str:
        return ".".join(self.path)


def iter_scalars(data: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], Any]]:
    """Depth-first iteration of scalar values with their key path."""
    if isinstance(data, dict):
        for key, value in data.items():
            yield from iter_scalars(value, (*path, str(key)))
    elif isinstance(data, list):
        for index, value in enumerate(data):
            yield from iter_scalars(value, (*path, f"[{index}]"))
    else:
        yield path, data


def find_mcp_servers(data: Any) -> dict[str, dict[str, Any]]:
    """Return ``{server_name: server_config}`` for recognised MCP config shapes.

    Supports Claude Desktop / Cursor / Windsurf / VS Code ``mcpServers`` and ``servers`` maps,
    and lists of ``{"name": ..., ...}`` objects.
    """
    servers: dict[str, dict[str, Any]] = {}
    if not isinstance(data, dict):
        return servers

    def collect(container: Any, prefix: str) -> None:
        if isinstance(container, dict):
            for name, config in container.items():
                if isinstance(config, dict) and _looks_like_server(config):
                    servers[f"{prefix}{name}"] = config
        elif isinstance(container, list):
            for index, config in enumerate(container):
                if isinstance(config, dict) and _looks_like_server(config):
                    name = str(config.get("name", index))
                    servers[f"{prefix}{name}"] = config

    for key in MCP_SERVER_KEYS:
        if key in data:
            value = data[key]
            if key == "mcp" and isinstance(value, dict):
                for inner in MCP_SERVER_KEYS:
                    if inner in value:
                        collect(value[inner], "")
                continue
            collect(value, "")
    # VS Code settings.json nests under "mcp": {"servers": {...}} (handled) or top-level "servers".
    return servers


def _looks_like_server(config: dict[str, Any]) -> bool:
    return any(
        k in config
        for k in ("command", "url", "args", "transport", "type", "env", "headers", "serverUrl")
    )


_KEY_LINE_CACHE: dict[int, dict[str, list[int]]] = {}


def locate_key(text: str, key: str, after_line: int = 0) -> tuple[int, int]:
    """Best-effort (line, column) of ``key`` in ``text`` after ``after_line``.

    Returns (1, 1) when the key cannot be found (e.g. list indices).
    """
    if key.startswith("[") and key.endswith("]"):
        return (max(after_line, 1), 1)
    pattern = re.compile(r"(?m)^(?P<indent>[ \t]*)[\"']?" + re.escape(key) + r"[\"']?\s*:")
    for match in pattern.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        if line >= after_line:
            return line, len(match.group("indent")) + 1
    # Fallback: any occurrence.
    index = text.find(key)
    if index == -1:
        return (max(after_line, 1), 1)
    line = text.count("\n", 0, index) + 1
    return line, index - text.rfind("\n", 0, index)


def locate_path(text: str, path: tuple[str, ...]) -> tuple[int, int]:
    """Locate a nested key path by walking keys in order."""
    line = 0
    column = 1
    for key in path:
        if key.startswith("["):
            continue
        line, column = locate_key(text, key, after_line=line)
    return (max(line, 1), column)


def locate_value(text: str, value: str, after_line: int = 0) -> tuple[int, int] | None:
    """Locate a literal value to anchor a finding precisely (used for secrets)."""
    index = text.find(value)
    while index != -1:
        line = text.count("\n", 0, index) + 1
        if line >= after_line:
            return line, index - text.rfind("\n", 0, index)
        index = text.find(value, index + 1)
    return None
