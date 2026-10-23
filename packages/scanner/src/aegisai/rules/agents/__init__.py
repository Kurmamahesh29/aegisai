"""AI agent rules (AGT001-AGT004)."""

from aegisai.rules.agents.approval_boundary import MissingApprovalBoundaryRule
from aegisai.rules.agents.broad_tools import OverlyBroadToolRule
from aegisai.rules.agents.command_execution import AgentToolCommandExecutionRule
from aegisai.rules.agents.tool_output import UntrustedToolOutputRule

__all__ = [
    "AgentToolCommandExecutionRule",
    "MissingApprovalBoundaryRule",
    "OverlyBroadToolRule",
    "UntrustedToolOutputRule",
]
