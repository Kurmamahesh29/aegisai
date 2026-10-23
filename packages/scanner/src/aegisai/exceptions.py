"""Exception hierarchy for AegisAI."""

from __future__ import annotations


class AegisError(Exception):
    """Base class for all AegisAI errors."""


class ConfigurationError(AegisError):
    """Raised when configuration or CLI arguments are invalid."""


class ProjectRootError(AegisError):
    """Raised when the scan root is missing, unreadable, or unsafe."""


class AnalyzerUnavailableError(AegisError):
    """Raised when an enabled external analyzer cannot be executed."""


class AnalyzerExecutionError(AegisError):
    """Raised when an external analyzer ran but failed or returned unparseable output."""


class ScanTimeoutError(AegisError):
    """Raised when the overall scan deadline is exceeded."""


class ScanCancelledError(AegisError):
    """Raised when the scan is cancelled by the caller."""


class BaselineError(AegisError):
    """Raised when a baseline file is missing or malformed."""
