"""Built-in rule packs."""

from __future__ import annotations

from aegisai.engine.registry import Rule
from aegisai.rules.agents import (
    AgentToolCommandExecutionRule,
    MissingApprovalBoundaryRule,
    OverlyBroadToolRule,
    UntrustedToolOutputRule,
)
from aegisai.rules.code import (
    SemgrepFindingRule,
    SensitiveLoggingRule,
    ShellInjectionRule,
    UnsafeConfigurationRule,
)
from aegisai.rules.dependencies import VulnerableDependencyRule
from aegisai.rules.llm import (
    LLMOutputToSensitiveOperationRule,
    MissingOutputValidationRule,
    SecretsInPromptsRule,
    UntrustedContentToToolRule,
)
from aegisai.rules.mcp import (
    MCPBroadPermissionsRule,
    MCPConfigSecretsRule,
    MCPMissingAuthorizationRule,
    MCPToolExecutionRule,
    MCPTransportRule,
)
from aegisai.rules.rag import (
    AuthorizationAfterRetrievalRule,
    MetadataExposureRule,
    MissingTenantFilterRule,
    RetrievedContentToPrivilegedActionRule,
)
from aegisai.rules.secrets import HardcodedCredentialsRule

# When two rules report the same location, the superseding rule wins (see deduplication).
RULE_PRECEDENCE: dict[str, frozenset[str]] = {
    "MCP003": frozenset({"SEC001"}),
    "AGT001": frozenset({"SEC003"}),
    "MCP001": frozenset({"SEC003"}),
}


def builtin_rules() -> list[Rule]:
    """Instantiate every built-in rule in a stable order."""
    return [
        HardcodedCredentialsRule(),
        SensitiveLoggingRule(),
        ShellInjectionRule(),
        VulnerableDependencyRule(),
        UnsafeConfigurationRule(),
        SemgrepFindingRule(),
        LLMOutputToSensitiveOperationRule(),
        UntrustedContentToToolRule(),
        SecretsInPromptsRule(),
        MissingOutputValidationRule(),
        AgentToolCommandExecutionRule(),
        MissingApprovalBoundaryRule(),
        OverlyBroadToolRule(),
        UntrustedToolOutputRule(),
        MissingTenantFilterRule(),
        AuthorizationAfterRetrievalRule(),
        RetrievedContentToPrivilegedActionRule(),
        MetadataExposureRule(),
        MCPToolExecutionRule(),
        MCPBroadPermissionsRule(),
        MCPConfigSecretsRule(),
        MCPMissingAuthorizationRule(),
        MCPTransportRule(),
    ]


__all__ = ["RULE_PRECEDENCE", "builtin_rules"]
