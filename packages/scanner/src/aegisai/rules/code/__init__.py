"""Conventional code and configuration rules (SEC002, SEC003, CFG001, SMG001)."""

from aegisai.rules.code.logging_exposure import SensitiveLoggingRule
from aegisai.rules.code.semgrep_rule import SemgrepFindingRule
from aegisai.rules.code.shell_injection import ShellInjectionRule
from aegisai.rules.code.unsafe_configuration import UnsafeConfigurationRule

__all__ = [
    "SemgrepFindingRule",
    "SensitiveLoggingRule",
    "ShellInjectionRule",
    "UnsafeConfigurationRule",
]
