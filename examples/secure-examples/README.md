# secure-examples

Secure counterparts of the vulnerable fixtures. Each file applies the remediation that the
corresponding AegisAI rule recommends:

| File | Demonstrates |
|------|--------------|
| `secure_llm_app.py` | model output treated as data, typed decisions, allow-listed dispatch, no secrets in prompts or logs |
| `secure_rag_app.py` | tenant filter inside the query, minimal metadata, retrieved content summarised not returned |
| `secure_agent_app.py` | enumerated tool parameters, argument lists without a shell, human approval for destructive actions |
| `secure_mcp_server.py` | loopback binding, server-level auth settings, path containment, per-tool permission checks |
| `mcp.json` | secrets referenced through `${env:...}` / `${input:...}`, scoped filesystem root, HTTPS remote |

`aegisai scan examples/secure-examples --no-integrations` is expected to report zero findings.
The integration test suite asserts this to guard against false positives.
