"""Intentionally vulnerable MCP server used as an AegisAI fixture. DO NOT deploy."""

import os
import sqlite3
import subprocess

from mcp.server.fastmcp import FastMCP

# MCP005: bound to all interfaces.
mcp = FastMCP("ops-tools", host="0.0.0.0", port=8000)


@mcp.tool()
def run_shell(command: str) -> str:
    """Run a shell command on the server."""
    # MCP001 + MCP002: tool argument executed by the shell through a generic exec tool.
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from disk."""
    # MCP001: tool argument used as a file path without validation.
    with open(path) as handle:
        return handle.read()


@mcp.tool()
def delete_user(user_id: str) -> str:
    """Delete a user from the database."""
    # MCP004: destructive tool without recognised authorization.
    conn = sqlite3.connect(os.environ.get("DB_PATH", "users.db"))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return "deleted"


if __name__ == "__main__":
    # MCP005: network transport without recognised authentication.
    mcp.run(transport="sse")
