"""Intentionally vulnerable LangChain agent used as an AegisAI fixture. DO NOT deploy."""

import os
import pickle
import subprocess

import requests
from langchain.agents import AgentExecutor, create_tool_calling_agent, load_tools
from langchain_community.tools import ShellTool
from langchain_core.tools import tool
from langchain_experimental.agents import create_pandas_dataframe_agent
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4o-mini")


@tool
def run_command(command: str) -> str:
    """Run any shell command on the server and return its output."""
    # AGT001: tool parameter executed by the shell.
    return subprocess.check_output(command, shell=True).decode()


@tool
def delete_customer(customer_id: str) -> str:
    """Delete a customer record permanently."""
    # AGT002: destructive tool without an approval boundary.
    requests.delete(f"https://crm.internal/customers/{customer_id}", timeout=5)
    return "deleted"


@tool
def fetch_page(url: str) -> str:
    """Fetch a web page."""
    return requests.get(url, timeout=5).text


@tool
def load_report(path: str) -> dict:
    """Load a pickled report file."""
    # AGT001: tool parameter reaches filesystem + deserialization.
    with open(path, "rb") as handle:
        return pickle.load(handle)


# AGT003: dangerous built-in tools and flags.
shell = ShellTool()
dangerous_tools = load_tools(["terminal", "requests_all"], llm=llm)
pandas_agent = create_pandas_dataframe_agent(llm, df=None, allow_dangerous_code=True)

tools = [run_command, delete_customer, fetch_page, load_report, shell]
agent = create_tool_calling_agent(llm, tools, prompt=None)
executor = AgentExecutor(agent=agent, tools=tools)


def research(topic: str) -> str:
    page = fetch_page.invoke(topic)
    # AGT004: tool output evaluated as code.
    eval(page)
    return page


def handle(user_message: str) -> str:
    result = executor.invoke({"input": user_message})
    return result["output"]


if __name__ == "__main__":
    message = input("> ")
    # LLM002: raw user input passed straight into a shell tool.
    shell.run(message)
    print(handle(message), os.getcwd())
