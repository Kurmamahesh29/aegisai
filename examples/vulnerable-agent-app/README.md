# vulnerable-agent-app

Intentionally insecure LangChain tool-calling agent used as an AegisAI fixture. **Do not run.**

Expected findings (`aegisai scan examples/vulnerable-agent-app --no-integrations`):

| Rule | Location | Why |
|------|----------|-----|
| AGT001 | `run_command()` | tool parameter reaches `subprocess.check_output(shell=True)` |
| AGT001 | `load_report()` | tool parameter reaches `open()` and `pickle.load()` |
| AGT002 | `delete_customer()` | destructive tool without an approval boundary |
| AGT003 | module level | `ShellTool()`, `load_tools(["terminal", "requests_all"])`, `allow_dangerous_code=True` |
| AGT003 | `run_command()` | description advertises "any shell command" |
| AGT004 | `research()` | tool output passed to `eval()` |
| LLM002 | `__main__` block | `input()` passed directly to `shell.run()` |
