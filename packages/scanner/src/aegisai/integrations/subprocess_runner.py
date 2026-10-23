"""Safe subprocess execution for external scanners.

Guarantees: argument arrays only (never ``shell=True``), explicit executable resolution,
timeouts, bounded output, a minimal environment, and no inheritance of stdin.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from aegisai.exceptions import AnalyzerUnavailableError
from aegisai.utils.logging import get_logger

log = get_logger("subprocess")

MAX_OUTPUT_BYTES = 50 * 1024 * 1024  # 50 MiB per stream
_SAFE_ENV_KEYS = (
    "PATH",
    "HOME",
    "USERPROFILE",
    "TEMP",
    "TMP",
    "TMPDIR",
    "SYSTEMROOT",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "no_proxy",
)


@dataclass(slots=True)
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    truncated: bool = False


def resolve_executable(name: str, explicit: str | None = None) -> str:
    """Resolve an executable without shell lookup tricks.

    ``explicit`` must point at an existing file; otherwise ``name`` is looked up on PATH.
    Relative explicit paths are rejected to avoid executing an unintended binary from the CWD.
    """
    if explicit:
        candidate = Path(explicit).expanduser()
        if not candidate.is_absolute():
            raise AnalyzerUnavailableError(
                f"executable path for {name} must be absolute: {explicit}"
            )
        if not candidate.is_file():
            raise AnalyzerUnavailableError(f"configured {name} executable not found: {candidate}")
        if not os.access(candidate, os.X_OK):
            raise AnalyzerUnavailableError(
                f"configured {name} executable is not executable: {candidate}"
            )
        return str(candidate)
    found = shutil.which(name)
    if found is None:
        raise AnalyzerUnavailableError(f"{name} is not installed or not on PATH")
    return found


def minimal_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {key: os.environ[key] for key in _SAFE_ENV_KEYS if key in os.environ}
    if extra:
        env.update(extra)
    return env


def run_command(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout_seconds: int = 120,
    env: dict[str, str] | None = None,
    max_output_bytes: int = MAX_OUTPUT_BYTES,
) -> CommandResult:
    """Run ``args`` (an argument array) and capture bounded output.

    Raises :class:`AnalyzerUnavailableError` if the executable cannot be started.
    A timeout kills the process and returns ``timed_out=True`` rather than raising, so the
    caller can report partial output.
    """
    if not args or not args[0]:
        raise AnalyzerUnavailableError("empty command")
    if not Path(args[0]).is_absolute():
        raise AnalyzerUnavailableError(
            f"executable must be resolved to an absolute path: {args[0]}"
        )
    log.debug("running %s (cwd=%s, timeout=%ss)", args, cwd, timeout_seconds)
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            args,
            cwd=str(cwd) if cwd else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=minimal_env(env),
            shell=False,
        )
    except (OSError, ValueError) as exc:
        raise AnalyzerUnavailableError(f"cannot start {args[0]}: {exc}") from exc
    timed_out = False
    try:
        stdout_b, stderr_b = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        stdout_b, stderr_b = process.communicate()
    duration = int((time.monotonic() - started) * 1000)
    truncated = len(stdout_b) > max_output_bytes or len(stderr_b) > max_output_bytes
    stdout = stdout_b[:max_output_bytes].decode("utf-8", errors="replace")
    stderr = stderr_b[:max_output_bytes].decode("utf-8", errors="replace")
    return CommandResult(
        args=list(args),
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
        duration_ms=duration,
        timed_out=timed_out,
        truncated=truncated,
    )


def tool_version(executable: str, flag: str = "--version", timeout_seconds: int = 20) -> str | None:
    """Best-effort version string for diagnostics; never raises."""
    try:
        result = run_command([executable, flag], timeout_seconds=timeout_seconds)
    except AnalyzerUnavailableError:
        return None
    text = (result.stdout or result.stderr).strip().splitlines()
    return text[0][:120] if text else None
