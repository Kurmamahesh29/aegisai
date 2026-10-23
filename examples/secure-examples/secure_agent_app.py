"""Secure counterpart of vulnerable-agent-app. Should produce no AegisAI findings."""

import subprocess
from typing import Literal

import requests
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4o-mini")

ALLOWED_SERVICES = {"api", "worker", "scheduler"}


@tool
def service_status(service: Literal["api", "worker", "scheduler"]) -> str:
    """Return the status of a named internal service."""
    if service not in ALLOWED_SERVICES:
        raise ValueError("unknown service")
    # Fixed argument list; the model only chooses an allow-listed value.
    result = subprocess.run(["systemctl", "status", service], capture_output=True, text=True, check=False)
    return result.stdout


@tool
def archive_customer(customer_id: str) -> str:
    """Archive (soft-delete) a customer after human approval."""
    if not require_approval(f"archive customer {customer_id}"):
        return "approval denied"
    requests.post("https://crm.internal/customers/archive", json={"id": customer_id}, timeout=5)
    return "archived"


def require_approval(action: str) -> bool:
    """Blocking human-in-the-loop approval; implementation depends on the host application."""
    return False


tools = [service_status, archive_customer]
agent = create_tool_calling_agent(llm, tools, prompt=None)
executor = AgentExecutor(agent=agent, tools=tools)


def handle(user_message: str) -> str:
    result = executor.invoke({"input": user_message})
    return result["output"]
