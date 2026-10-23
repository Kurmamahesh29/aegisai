"""External scanner integrations and the optional AI review interface."""

from aegisai.integrations.base import ExternalAnalyzer, IntegrationOutcome
from aegisai.integrations.gitleaks import GitleaksAnalyzer
from aegisai.integrations.osv_scanner import OsvScannerAnalyzer
from aegisai.integrations.semgrep import SemgrepAnalyzer

ALL_INTEGRATIONS: dict[str, type[ExternalAnalyzer]] = {
    GitleaksAnalyzer.name: GitleaksAnalyzer,
    OsvScannerAnalyzer.name: OsvScannerAnalyzer,
    SemgrepAnalyzer.name: SemgrepAnalyzer,
}

__all__ = [
    "ALL_INTEGRATIONS",
    "ExternalAnalyzer",
    "GitleaksAnalyzer",
    "IntegrationOutcome",
    "OsvScannerAnalyzer",
    "SemgrepAnalyzer",
]
