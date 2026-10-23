"""Secure counterpart of vulnerable-rag-app. Should produce no AegisAI findings."""

import chromadb
from fastapi import Depends, FastAPI
from langchain_openai import ChatOpenAI

app = FastAPI()
chroma = chromadb.Client()
collection = chroma.get_or_create_collection("contracts")
llm = ChatOpenAI(model="gpt-4o-mini")


def current_tenant() -> str:
    return "tenant-from-auth-token"


def ingest(doc_id: str, text: str, tenant_id: str) -> None:
    # Only the tenant scope and a citation id are stored as metadata.
    collection.add(ids=[doc_id], documents=[text], metadatas=[{"tenant_id": tenant_id, "doc_id": doc_id}])


@app.get("/search")
def search(q: str, tenant_id: str = Depends(current_tenant)):
    # Tenant filter is enforced inside the query.
    results = collection.query(query_texts=[q], n_results=5, where={"tenant_id": tenant_id})
    context = "\n".join(results["documents"][0])
    answer = llm.invoke(f"Answer using only this context:\n{context}\n\nQuestion: {q}")
    # Retrieved documents are summarised by the model, not returned verbatim.
    return {"answer": answer.content, "citations": results["ids"][0]}
