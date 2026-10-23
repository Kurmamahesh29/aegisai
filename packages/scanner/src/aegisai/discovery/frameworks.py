"""Detection of AI frameworks, web frameworks and vector stores from imports and manifests."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum


class Framework(StrEnum):
    """Known frameworks that influence rule applicability and confidence."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE_GENAI = "google-genai"
    LANGCHAIN = "langchain"
    LANGGRAPH = "langgraph"
    LLAMA_INDEX = "llama-index"
    CREWAI = "crewai"
    AUTOGEN = "autogen"
    OPENAI_AGENTS = "openai-agents"
    PYDANTIC_AI = "pydantic-ai"
    SEMANTIC_KERNEL = "semantic-kernel"
    SMOLAGENTS = "smolagents"
    LITELLM = "litellm"
    HAYSTACK = "haystack"
    DSPY = "dspy"
    OLLAMA = "ollama"
    COHERE = "cohere"
    MISTRAL = "mistral"
    GROQ = "groq"
    MCP = "mcp"
    FASTMCP = "fastmcp"
    MCP_TS = "mcp-typescript"
    CHROMA = "chroma"
    PINECONE = "pinecone"
    QDRANT = "qdrant"
    WEAVIATE = "weaviate"
    FAISS = "faiss"
    MILVUS = "milvus"
    PGVECTOR = "pgvector"
    FLASK = "flask"
    FASTAPI = "fastapi"
    DJANGO = "django"
    STARLETTE = "starlette"
    STREAMLIT = "streamlit"
    GRADIO = "gradio"
    VERCEL_AI = "vercel-ai"
    LANGCHAIN_JS = "langchain-js"


AI_FRAMEWORKS: frozenset[Framework] = frozenset(
    {
        Framework.OPENAI,
        Framework.ANTHROPIC,
        Framework.GOOGLE_GENAI,
        Framework.LANGCHAIN,
        Framework.LANGGRAPH,
        Framework.LLAMA_INDEX,
        Framework.CREWAI,
        Framework.AUTOGEN,
        Framework.OPENAI_AGENTS,
        Framework.PYDANTIC_AI,
        Framework.SEMANTIC_KERNEL,
        Framework.SMOLAGENTS,
        Framework.LITELLM,
        Framework.HAYSTACK,
        Framework.DSPY,
        Framework.OLLAMA,
        Framework.COHERE,
        Framework.MISTRAL,
        Framework.GROQ,
        Framework.VERCEL_AI,
        Framework.LANGCHAIN_JS,
    }
)

AGENT_FRAMEWORKS: frozenset[Framework] = frozenset(
    {
        Framework.LANGCHAIN,
        Framework.LANGGRAPH,
        Framework.LLAMA_INDEX,
        Framework.CREWAI,
        Framework.AUTOGEN,
        Framework.OPENAI_AGENTS,
        Framework.PYDANTIC_AI,
        Framework.SEMANTIC_KERNEL,
        Framework.SMOLAGENTS,
    }
)

VECTOR_STORES: frozenset[Framework] = frozenset(
    {
        Framework.CHROMA,
        Framework.PINECONE,
        Framework.QDRANT,
        Framework.WEAVIATE,
        Framework.FAISS,
        Framework.MILVUS,
        Framework.PGVECTOR,
        Framework.LLAMA_INDEX,
    }
)

MCP_FRAMEWORKS: frozenset[Framework] = frozenset(
    {Framework.MCP, Framework.FASTMCP, Framework.MCP_TS}
)

WEB_FRAMEWORKS: frozenset[Framework] = frozenset(
    {Framework.FLASK, Framework.FASTAPI, Framework.DJANGO, Framework.STARLETTE}
)

# Python top-level import module -> framework.
PYTHON_IMPORT_MAP: dict[str, Framework] = {
    "openai": Framework.OPENAI,
    "anthropic": Framework.ANTHROPIC,
    "google.generativeai": Framework.GOOGLE_GENAI,
    "google.genai": Framework.GOOGLE_GENAI,
    "vertexai": Framework.GOOGLE_GENAI,
    "langchain": Framework.LANGCHAIN,
    "langchain_core": Framework.LANGCHAIN,
    "langchain_community": Framework.LANGCHAIN,
    "langchain_openai": Framework.LANGCHAIN,
    "langchain_anthropic": Framework.LANGCHAIN,
    "langchain_experimental": Framework.LANGCHAIN,
    "langchain_google_genai": Framework.LANGCHAIN,
    "langchain_chroma": Framework.LANGCHAIN,
    "langchain_pinecone": Framework.LANGCHAIN,
    "langchain_text_splitters": Framework.LANGCHAIN,
    "langgraph": Framework.LANGGRAPH,
    "llama_index": Framework.LLAMA_INDEX,
    "crewai": Framework.CREWAI,
    "autogen": Framework.AUTOGEN,
    "autogen_agentchat": Framework.AUTOGEN,
    "autogen_core": Framework.AUTOGEN,
    "agents": Framework.OPENAI_AGENTS,
    "pydantic_ai": Framework.PYDANTIC_AI,
    "semantic_kernel": Framework.SEMANTIC_KERNEL,
    "smolagents": Framework.SMOLAGENTS,
    "litellm": Framework.LITELLM,
    "haystack": Framework.HAYSTACK,
    "dspy": Framework.DSPY,
    "ollama": Framework.OLLAMA,
    "cohere": Framework.COHERE,
    "mistralai": Framework.MISTRAL,
    "groq": Framework.GROQ,
    "mcp": Framework.MCP,
    "fastmcp": Framework.FASTMCP,
    "chromadb": Framework.CHROMA,
    "pinecone": Framework.PINECONE,
    "qdrant_client": Framework.QDRANT,
    "weaviate": Framework.WEAVIATE,
    "faiss": Framework.FAISS,
    "pymilvus": Framework.MILVUS,
    "pgvector": Framework.PGVECTOR,
    "flask": Framework.FLASK,
    "fastapi": Framework.FASTAPI,
    "django": Framework.DJANGO,
    "starlette": Framework.STARLETTE,
    "streamlit": Framework.STREAMLIT,
    "gradio": Framework.GRADIO,
}

# Package names from manifests (pip / npm) -> framework.
PACKAGE_MAP: dict[str, Framework] = {
    "openai": Framework.OPENAI,
    "anthropic": Framework.ANTHROPIC,
    "google-generativeai": Framework.GOOGLE_GENAI,
    "google-genai": Framework.GOOGLE_GENAI,
    "langchain": Framework.LANGCHAIN,
    "langchain-core": Framework.LANGCHAIN,
    "langchain-community": Framework.LANGCHAIN,
    "langchain-openai": Framework.LANGCHAIN,
    "langgraph": Framework.LANGGRAPH,
    "llama-index": Framework.LLAMA_INDEX,
    "llama-index-core": Framework.LLAMA_INDEX,
    "crewai": Framework.CREWAI,
    "pyautogen": Framework.AUTOGEN,
    "autogen-agentchat": Framework.AUTOGEN,
    "openai-agents": Framework.OPENAI_AGENTS,
    "pydantic-ai": Framework.PYDANTIC_AI,
    "semantic-kernel": Framework.SEMANTIC_KERNEL,
    "smolagents": Framework.SMOLAGENTS,
    "litellm": Framework.LITELLM,
    "haystack-ai": Framework.HAYSTACK,
    "dspy": Framework.DSPY,
    "dspy-ai": Framework.DSPY,
    "ollama": Framework.OLLAMA,
    "cohere": Framework.COHERE,
    "mistralai": Framework.MISTRAL,
    "groq": Framework.GROQ,
    "mcp": Framework.MCP,
    "fastmcp": Framework.FASTMCP,
    "chromadb": Framework.CHROMA,
    "pinecone": Framework.PINECONE,
    "pinecone-client": Framework.PINECONE,
    "qdrant-client": Framework.QDRANT,
    "weaviate-client": Framework.WEAVIATE,
    "faiss-cpu": Framework.FAISS,
    "faiss-gpu": Framework.FAISS,
    "pymilvus": Framework.MILVUS,
    "pgvector": Framework.PGVECTOR,
    "flask": Framework.FLASK,
    "fastapi": Framework.FASTAPI,
    "django": Framework.DJANGO,
    "starlette": Framework.STARLETTE,
    "streamlit": Framework.STREAMLIT,
    "gradio": Framework.GRADIO,
    # npm
    "@modelcontextprotocol/sdk": Framework.MCP_TS,
    "@anthropic-ai/sdk": Framework.ANTHROPIC,
    "@langchain/core": Framework.LANGCHAIN_JS,
    "@langchain/openai": Framework.LANGCHAIN_JS,
    "ai": Framework.VERCEL_AI,
    "@ai-sdk/openai": Framework.VERCEL_AI,
    "llamaindex": Framework.LLAMA_INDEX,
}

_JS_IMPORT = re.compile(r"""(?:from\s+|require\(\s*)["']([^"']+)["']""")


def frameworks_from_python_imports(modules: Iterable[str]) -> set[Framework]:
    """Map imported module names (``a.b.c``) to frameworks."""
    found: set[Framework] = set()
    for module in modules:
        parts = module.split(".")
        for depth in range(min(len(parts), 2), 0, -1):
            key = ".".join(parts[:depth])
            if key in PYTHON_IMPORT_MAP:
                found.add(PYTHON_IMPORT_MAP[key])
                break
    return found


def frameworks_from_packages(packages: Iterable[str]) -> set[Framework]:
    found: set[Framework] = set()
    for package in packages:
        framework = PACKAGE_MAP.get(package.lower())
        if framework is not None:
            found.add(framework)
    return found


def frameworks_from_js_source(text: str) -> set[Framework]:
    """Detect JS/TS frameworks from import / require specifiers."""
    found: set[Framework] = set()
    for match in _JS_IMPORT.finditer(text):
        spec = match.group(1)
        if spec.startswith("@modelcontextprotocol/sdk"):
            found.add(Framework.MCP_TS)
        elif spec == "openai" or spec.startswith("openai/"):
            found.add(Framework.OPENAI)
        elif spec.startswith("@anthropic-ai/"):
            found.add(Framework.ANTHROPIC)
        elif spec.startswith(("@langchain/", "langchain")):
            found.add(Framework.LANGCHAIN_JS)
        elif spec == "ai" or spec.startswith("@ai-sdk/"):
            found.add(Framework.VERCEL_AI)
        elif spec.startswith("llamaindex"):
            found.add(Framework.LLAMA_INDEX)
    return found


@dataclass(slots=True)
class FrameworkProfile:
    """Aggregated framework knowledge for a project."""

    frameworks: set[Framework] = field(default_factory=set)

    @property
    def has_ai(self) -> bool:
        return bool(self.frameworks & AI_FRAMEWORKS)

    @property
    def has_agents(self) -> bool:
        return bool(self.frameworks & AGENT_FRAMEWORKS)

    @property
    def has_vector_store(self) -> bool:
        return bool(self.frameworks & VECTOR_STORES)

    @property
    def has_mcp(self) -> bool:
        return bool(self.frameworks & MCP_FRAMEWORKS)

    @property
    def has_web(self) -> bool:
        return bool(self.frameworks & WEB_FRAMEWORKS)

    def sorted_names(self) -> list[str]:
        return sorted(f.value for f in self.frameworks)
