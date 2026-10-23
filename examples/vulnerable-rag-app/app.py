"""Intentionally vulnerable RAG application used as an AegisAI fixture. DO NOT deploy."""

import logging
import sqlite3
import subprocess

import chromadb
from fastapi import FastAPI
from langchain_core.documents import Document
from langchain_openai import ChatOpenAI

app = FastAPI()
logger = logging.getLogger(__name__)
chroma = chromadb.Client()
collection = chroma.get_or_create_collection("contracts")
llm = ChatOpenAI(model="gpt-4o-mini")


def ingest(doc_id: str, text: str, owner_email: str, salary: int) -> None:
    # RAG004: sensitive attributes stored as embedding metadata.
    collection.add(
        ids=[doc_id],
        documents=[text],
        metadatas=[{"email": owner_email, "salary": salary}],
    )


@app.get("/search")
def search(q: str, tenant_id: str):
    # RAG001: tenant_id is in scope but the query is not filtered.
    results = collection.query(query_texts=[q], n_results=5)
    # RAG002: authorization applied after retrieval.
    allowed = [r for r in results["documents"][0] if r.metadata["tenant_id"] == tenant_id]
    # RAG004: retrieved documents returned verbatim.
    return {"results": allowed}


@app.get("/run")
def run_instruction(q: str):
    docs = collection.query(query_texts=[q], n_results=1)
    instruction = docs["documents"][0][0]
    # RAG003: retrieved content executed as a shell command.
    subprocess.run(instruction, shell=True)
    # RAG003: retrieved content used to build SQL.
    conn = sqlite3.connect("app.db")
    conn.cursor().execute(f"SELECT * FROM contracts WHERE title = '{instruction}'")
    logger.debug("retrieved: %s", docs)
    return {"ok": True}


def build_document(text: str, ssn: str) -> Document:
    # RAG004: PII in document metadata.
    return Document(page_content=text, metadata={"ssn": ssn})
