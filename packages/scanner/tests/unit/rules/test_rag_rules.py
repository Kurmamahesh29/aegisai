"""Positive and negative tests for RAG001-RAG004."""

from __future__ import annotations

from aegisai.models.configuration import Profile
from aegisai.models.finding import Confidence, Severity
from conftest import findings_for, rule_ids, scan_code

RAG = [Profile.RAG]


def test_rag001_positive(project) -> None:
    code = """
        from fastapi import FastAPI
        app = FastAPI()

        @app.get("/s")
        def search(q: str, tenant_id: str, vectorstore):
            docs = vectorstore.similarity_search(q, k=5)
            retriever = vectorstore.as_retriever()
            return docs
    """
    found = findings_for(scan_code(project, code, profiles=RAG), "RAG001")
    assert {f.location.start_line for f in found} == {6, 7}
    assert all(f.review_required and f.confidence is Confidence.MEDIUM for f in found)


def test_rag001_negative(project) -> None:
    code = """
        def search(q: str, tenant_id: str, vectorstore, collection):
            a = vectorstore.similarity_search(q, filter={"tenant": tenant_id})
            b = collection.query(query_texts=[q], where={"tenant_id": tenant_id})
            c = vectorstore.as_retriever(search_kwargs={"filter": {"tenant": tenant_id}})
            d = vectorstore.similarity_search(q, namespace=tenant_id)
            return a, b, c, d

        def public_search(q: str, vectorstore):
            return vectorstore.similarity_search(q)
    """
    assert "RAG001" not in rule_ids(scan_code(project, code, profiles=RAG))


def test_rag002_positive(project) -> None:
    code = """
        def search(q, user_id, store):
            results = store.similarity_search(q)
            mine = [r for r in results if r.metadata["owner"] == user_id]
            for r in results:
                if r.metadata.get("tenant_id") != user_id:
                    continue
            return mine
    """
    found = findings_for(scan_code(project, code, profiles=RAG), "RAG002")
    assert {f.location.start_line for f in found} == {3, 5}


def test_rag002_negative(project) -> None:
    code = """
        def search(q, user_id, store):
            results = store.similarity_search(q, filter={"owner": user_id})
            best = [r for r in results if r.score > 0.5]
            return best
    """
    assert "RAG002" not in rule_ids(scan_code(project, code, profiles=RAG))


def test_rag003_positive(project) -> None:
    code = """
        import subprocess, requests
        def act(index):
            nodes = index.as_retriever().retrieve("q")
            subprocess.run(nodes[0].text, shell=True)
            requests.post(nodes[0].metadata["callback"], json={})
    """
    found = findings_for(scan_code(project, code, profiles=RAG), "RAG003")
    assert [f.severity for f in sorted(found, key=lambda f: f.location.start_line)] == [
        Severity.CRITICAL,
        Severity.HIGH,
    ]


def test_rag003_negative(project) -> None:
    code = """
        import subprocess
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI()
        def act(store, q):
            docs = store.similarity_search(q)
            context = "\\n".join(d.page_content for d in docs)
            answer = llm.invoke("Answer from context: " + context)
            return answer.content
    """
    assert "RAG003" not in rule_ids(scan_code(project, code, profiles=RAG))


def test_rag004_positive(project) -> None:
    code = """
        import logging
        from fastapi import FastAPI
        from langchain_core.documents import Document
        app = FastAPI()
        log = logging.getLogger()

        def ingest(store, text, email, ssn):
            store.add_texts([text], metadatas=[{"email": email, "ssn": ssn}])
            return Document(page_content=text, metadata={"salary": 1})

        @app.get("/s")
        def search(q, store):
            docs = store.similarity_search(q)
            log.info("docs %s", docs)
            return {"docs": docs}
    """
    found = findings_for(scan_code(project, code, profiles=RAG), "RAG004")
    kinds = sorted(f.title for f in found)
    assert kinds == [
        "Retrieved documents returned to the client",
        "Retrieved documents written to logs",
        "Sensitive metadata stored with embeddings",
        "Sensitive metadata stored with embeddings",
    ]


def test_rag004_negative(project) -> None:
    code = """
        from fastapi import FastAPI
        app = FastAPI()

        def ingest(store, text, tenant_id):
            store.add_texts([text], metadatas=[{"tenant_id": tenant_id, "source": "upload"}])

        @app.get("/s")
        def search(q, store):
            results = store.query(q)
            return {"ids": results["ids"], "scores": results["distances"]}
    """
    assert "RAG004" not in rule_ids(scan_code(project, code, profiles=RAG))
