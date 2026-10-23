# vulnerable-rag-app

Intentionally insecure FastAPI + Chroma + LangChain RAG service used as an AegisAI fixture.
**Do not deploy.**

Expected findings (`aegisai scan examples/vulnerable-rag-app --no-integrations`):

| Rule | Location | Why |
|------|----------|-----|
| RAG004 | `ingest()`, `build_document()` | `email`, `salary`, `ssn` stored as embedding metadata |
| RAG001 | `search()` | `collection.query(...)` without a tenant filter while `tenant_id` is in scope |
| RAG002 | `search()` | results filtered by `tenant_id` after retrieval |
| RAG004 | `search()` | retrieved documents returned to the client |
| RAG003 | `run_instruction()` | retrieved content reaches `subprocess.run(shell=True)` and `cursor.execute()` |
| RAG004 | `run_instruction()` | retrieved documents logged |
