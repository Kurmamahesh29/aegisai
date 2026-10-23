# vulnerable-llm-app

Intentionally insecure Flask + OpenAI application used as an AegisAI test fixture.
**Do not deploy.** All credentials are fake.

Expected findings (`aegisai scan examples/vulnerable-llm-app --no-integrations`):

| Rule | Location | Why |
|------|----------|-----|
| SEC001 | `app.py` `OPENAI_API_KEY = "sk-proj-..."` | hard-coded API key |
| LLM003 | `ask()` | `DB_PASSWORD` interpolated into the system prompt |
| LLM001 | `ask()` | model output passed to `subprocess.run(..., shell=True)` |
| LLM004 | `ask()`, `summarize()`, `render()` | model output rendered as HTML / used as redirect target |
| SEC002 | `summarize()` | API key written to the log |
| SEC003 | `ping()` | request parameter reaches `subprocess.check_output(..., shell=True)` |
| CFG001 | `__main__` | `debug=True` on `0.0.0.0` |
| DEP001 | `requirements.txt` | pinned vulnerable versions (requires OSV-Scanner) |
