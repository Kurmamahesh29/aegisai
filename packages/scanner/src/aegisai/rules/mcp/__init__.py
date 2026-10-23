"""MCP rules (MCP001-MCP005)."""

from aegisai.rules.mcp.authorization import MCPMissingAuthorizationRule
from aegisai.rules.mcp.config_secrets import MCPConfigSecretsRule
from aegisai.rules.mcp.permissions import MCPBroadPermissionsRule
from aegisai.rules.mcp.tool_execution import MCPToolExecutionRule
from aegisai.rules.mcp.transport import MCPTransportRule

__all__ = [
    "MCPBroadPermissionsRule",
    "MCPConfigSecretsRule",
    "MCPMissingAuthorizationRule",
    "MCPToolExecutionRule",
    "MCPTransportRule",
]
