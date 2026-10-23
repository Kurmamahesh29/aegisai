"""Secure counterpart of vulnerable-mcp-server. Should produce no AegisAI findings."""

import sqlite3
from pathlib import Path

from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import Context, FastMCP

DATA_ROOT = Path("/srv/app/data").resolve()
ALLOWED_REPORTS = {"daily", "weekly", "monthly"}

mcp = FastMCP("reports", host="127.0.0.1", port=8000, auth=AuthSettings(issuer_url="https://auth.example.com", resource_server_url="https://mcp.example.com"))


@mcp.tool()
def read_report(name: str) -> str:
    """Read a named report from the data directory."""
    if name not in ALLOWED_REPORTS:
        raise ValueError("unknown report")
    target = (DATA_ROOT / f"{name}.txt").resolve()
    if not target.is_relative_to(DATA_ROOT):
        raise ValueError("invalid path")
    return target.read_text(encoding="utf-8")


@mcp.tool()
def archive_user(user_id: int, ctx: Context) -> str:
    """Archive a user after verifying the caller's permission."""
    if not ctx.session.client_params or not has_permission(ctx, "users:archive"):
        raise PermissionError("not authorized")
    conn = sqlite3.connect(str(DATA_ROOT / "users.db"))
    conn.execute("UPDATE users SET archived = 1 WHERE id = ?", (user_id,))
    conn.commit()
    return "archived"


def has_permission(ctx: Context, scope: str) -> bool:
    return scope in getattr(ctx.session, "scopes", ())


if __name__ == "__main__":
    mcp.run(transport="stdio")
