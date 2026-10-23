"""Structured logging with secret redaction.

Logs go to stderr so that machine-readable reports written to stdout stay clean.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from aegisai.utils.redaction import redact_text

LOGGER_NAME = "aegisai"


class RedactingFormatter(logging.Formatter):
    """Format log records as single-line JSON with redacted messages."""

    def format(self, record: logging.LogRecord) -> str:
        message = redact_text(record.getMessage())
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": message,
        }
        extra = getattr(record, "aegis", None)
        if isinstance(extra, dict):
            payload.update({k: redact_text(str(v)) for k, v in extra.items()})
        if record.exc_info:
            payload["exc"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False)


class HumanFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = redact_text(record.getMessage())
        base = f"[{record.levelname.lower()}] {message}"
        if record.exc_info:
            base += "\n" + redact_text(self.formatException(record.exc_info))
        return base


def configure_logging(verbose: bool = False, quiet: bool = False, json_logs: bool = False) -> None:
    """Configure the ``aegisai`` logger. Safe to call multiple times."""
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(RedactingFormatter() if json_logs else HumanFormatter())
    logger.addHandler(handler)
    if quiet:
        logger.setLevel(logging.ERROR)
    elif verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)
    logger.propagate = False


def get_logger(name: str | None = None) -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME)
