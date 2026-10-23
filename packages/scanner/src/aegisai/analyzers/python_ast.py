"""Python AST parsing helpers: import resolution, call naming, decorators and literals.

Nothing in this module executes scanned code; it only uses :mod:`ast`.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class PythonModule:
    """A parsed Python file plus import alias information."""

    path: Path
    rel_path: str
    source: str
    tree: ast.Module
    lines: list[str]
    imports: set[str] = field(default_factory=set)
    aliases: dict[str, str] = field(default_factory=dict)
    functions: list[ast.FunctionDef | ast.AsyncFunctionDef] = field(default_factory=list)
    classes: list[ast.ClassDef] = field(default_factory=list)

    def resolve(self, name: str) -> str:
        """Resolve a dotted name through import aliases (``sp.run`` -> ``subprocess.run``)."""
        if not name:
            return name
        head, _, rest = name.partition(".")
        target = self.aliases.get(head)
        if target is None:
            return name
        return f"{target}.{rest}" if rest else target

    def call_name(self, node: ast.AST) -> str | None:
        """Dotted callee name for a Call (``None`` for lambdas/subscripts)."""
        if isinstance(node, ast.Call):
            node = node.func
        name = dotted_name(node)
        return self.resolve(name) if name else None

    def line(self, number: int) -> str:
        if 1 <= number <= len(self.lines):
            return self.lines[number - 1]
        return ""

    def snippet(self, node: ast.AST, max_len: int = 200) -> str:
        """Source text of ``node`` on a single line (joined and truncated)."""
        try:
            segment = ast.get_source_segment(self.source, node)
        except (ValueError, TypeError):
            segment = None
        if not segment:
            segment = self.line(getattr(node, "lineno", 0)).strip()
        text = " ".join(segment.split())
        return text if len(text) <= max_len else text[: max_len - 3] + "..."


def parse_module(path: Path, rel_path: str, source: str) -> PythonModule:
    """Parse ``source`` and collect import aliases and top-level definitions."""
    tree = ast.parse(source, filename=rel_path)
    module = PythonModule(
        path=path, rel_path=rel_path, source=source, tree=tree, lines=source.splitlines()
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module.imports.add(alias.name)
                module.aliases[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            module.imports.add(node.module)
            for alias in node.names:
                if alias.name == "*":
                    continue
                module.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            module.functions.append(node)
        elif isinstance(node, ast.ClassDef):
            module.classes.append(node)
    return module


def dotted_name(node: ast.AST) -> str:
    """Return ``a.b.c`` for Name/Attribute chains; calls in the chain are stripped.

    ``client.chat.completions.create`` -> same; ``FastMCP("x").tool`` -> ``FastMCP.tool``.
    """
    parts: list[str] = []
    current: ast.AST = node
    while True:
        if isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        elif isinstance(current, ast.Call):
            current = current.func
        elif isinstance(current, ast.Name):
            parts.append(current.id)
            break
        elif isinstance(current, ast.Subscript | ast.Await):
            current = current.value
        else:
            break
    return ".".join(reversed(parts))


def receiver_name(node: ast.AST) -> str | None:
    """For ``x.y.method(...)`` return ``x.y``; for ``f(...)`` return None."""
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        name = dotted_name(node.value)
        return name or None
    return None


def attribute_tail(node: ast.AST) -> str | None:
    """Last attribute name of a call/attribute chain (``a.b.c`` -> ``c``)."""
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def decorator_names(
    func: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef, module: PythonModule
) -> list[str]:
    """Resolved dotted names of every decorator (``@mcp.tool()`` -> ``mcp.tool``)."""
    names: list[str] = []
    for decorator in func.decorator_list:
        name = dotted_name(decorator)
        if name:
            names.append(module.resolve(name))
    return names


def get_keyword(call: ast.Call, name: str) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def get_arg(call: ast.Call, index: int, keyword: str | None = None) -> ast.expr | None:
    """Positional argument ``index`` or the keyword alternative."""
    if len(call.args) > index and not isinstance(call.args[index], ast.Starred):
        return call.args[index]
    if keyword is not None:
        return get_keyword(call, keyword)
    return None


def constant_value(node: ast.AST | None) -> object:
    """Return the constant for ``ast.Constant`` nodes, otherwise ``None``."""
    if isinstance(node, ast.Constant):
        return node.value
    return None


def is_truthy_constant(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def string_value(node: ast.AST | None) -> str | None:
    """Return a string literal (including simple concatenations and f-strings without values)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                parts.append("{...}")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = string_value(node.left)
        right = string_value(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def is_dynamic(node: ast.AST | None) -> bool:
    """True when an expression is not a plain constant (i.e. may vary at runtime)."""
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, ast.List | ast.Tuple):
        return any(is_dynamic(elt) for elt in node.elts)
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    return True


def docstring_of(func: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> str:
    try:
        return ast.get_docstring(func) or ""
    except TypeError:
        return ""


def iter_calls(tree: ast.AST) -> list[ast.Call]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call)]


def enclosing_functions(tree: ast.Module) -> dict[int, ast.FunctionDef | ast.AsyncFunctionDef]:
    """Map every node id to the innermost function containing it."""
    mapping: dict[int, ast.FunctionDef | ast.AsyncFunctionDef] = {}

    def visit(node: ast.AST, current: ast.FunctionDef | ast.AsyncFunctionDef | None) -> None:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            current = node
        if current is not None:
            mapping[id(node)] = current
        for child in ast.iter_child_nodes(node):
            visit(child, current)

    visit(tree, None)
    return mapping


def node_end(node: ast.AST) -> tuple[int, int]:
    """(end_line, end_column) 1-based inclusive, defaulting to the start position."""
    raw_end = getattr(node, "end_lineno", None)
    end_line = int(raw_end) if raw_end is not None else int(getattr(node, "lineno", 1))
    raw_col = getattr(node, "end_col_offset", None)
    end_col = int(raw_col) if raw_col is not None else int(getattr(node, "col_offset", 0)) + 1
    return end_line, max(1, end_col)
