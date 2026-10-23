# vulnerable-mcp-server

Intentionally insecure MCP server (Python FastMCP + TypeScript SDK) and client configuration.
**Do not deploy.** All tokens are fake.

Expected findings (`aegisai scan examples/vulnerable-mcp-server --no-integrations`):

| Rule | Location | Why |
|------|----------|-----|
| MCP001 | `server.py` `run_shell()`, `read_file()` | tool arguments reach `subprocess.run(shell=True)` / `open()` |
| MCP002 | `server.py` `run_shell()` | generic command-execution tool |
| MCP004 | `server.py` `run_shell()`, `read_file()`, `delete_user()` | high-impact tools without recognised authorization over SSE |
| MCP005 | `server.py` | `host="0.0.0.0"`, `transport="sse"` without auth |
| MCP001 | `server.ts` | `execSync` with interpolated input (heuristic) |
| MCP002 | `claude_desktop_config.json` | filesystem server rooted at `/`, auto-approved destructive tools, shell wrapper, `--dangerously-skip-permissions`, `alwaysAllow: ["*"]` |
| MCP003 | `claude_desktop_config.json` | GitHub token in `env`, bearer token in `headers`, API key in URL |
| MCP005 | `claude_desktop_config.json` | remote server over cleartext `http://` |
