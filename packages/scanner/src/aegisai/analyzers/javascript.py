"""Lightweight, regex-based heuristics for JavaScript/TypeScript MCP servers.

AegisAI does not ship a JS parser. These helpers find dangerous execution calls inside files
that import the MCP SDK so that MCP rules can emit medium-confidence, review-required findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MCP_SDK_IMPORT = re.compile(r"""(?:from\s+|require\(\s*)["']@modelcontextprotocol/sdk""")

TOOL_REGISTRATION = re.compile(
    r"""\.(?:tool|registerTool)\(\s*["'`](?P<name>[^"'`]+)["'`]|CallToolRequestSchema"""
)

DANGEROUS_EXEC = re.compile(
    r"""\b(?P<call>exec|execSync|execFile|execFileSync|spawn|spawnSync|eval|Function)\s*\(|new\s+Function\s*\("""
)

SHELL_OPTION = re.compile(r"shell\s*:\s*true")

NETWORK_BIND = re.compile(
    r"""\.listen\(\s*[^,)]+,\s*["']0\.0\.0\.0["']|host\s*:\s*["']0\.0\.0\.0["']|["']0\.0\.0\.0["']"""
)

TEMPLATE_INTERPOLATION = re.compile(r"\$\{[^}]+\}")


@dataclass(slots=True)
class JsExecMatch:
    line: int
    column: int
    call: str
    interpolated: bool
    shell: bool
    snippet: str


def imports_mcp_sdk(text: str) -> bool:
    return MCP_SDK_IMPORT.search(text) is not None


def registered_tool_names(text: str) -> list[str]:
    names: list[str] = []
    for match in TOOL_REGISTRATION.finditer(text):
        name = match.group("name")
        if name:
            names.append(name)
    return names


def find_dangerous_exec(text: str) -> list[JsExecMatch]:
    """Locate exec/spawn/eval calls, noting template interpolation and ``shell: true``."""
    results: list[JsExecMatch] = []
    lines = text.splitlines()
    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith(("//", "*", "/*")):
            continue
        for match in DANGEROUS_EXEC.finditer(line):
            call = match.group("call") or "Function"
            if call == "exec" and re.search(r"\b(?:regex|re|pattern|\w+Regex)\.exec\(", line):
                continue
            window = "\n".join(lines[line_no - 1 : min(len(lines), line_no + 3)])
            results.append(
                JsExecMatch(
                    line=line_no,
                    column=match.start() + 1,
                    call=call,
                    interpolated=bool(TEMPLATE_INTERPOLATION.search(window)) or "+" in line,
                    shell=bool(SHELL_OPTION.search(window)),
                    snippet=stripped[:200],
                )
            )
    return results


def find_network_binds(text: str) -> list[tuple[int, int, str]]:
    found: list[tuple[int, int, str]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        match = NETWORK_BIND.search(line)
        if match and not line.strip().startswith("//"):
            found.append((line_no, match.start() + 1, line.strip()[:200]))
    return found
