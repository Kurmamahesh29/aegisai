"""AegisAI command-line interface.

Exit codes (documented in docs/ci-cd.md):
  0  scan completed, no active finding at or above --fail-on
  1  at least one active finding at or above --fail-on
  2  scan failed (invalid arguments, configuration, unreadable root, internal error)
  3  scan incomplete (timeout, limits, or a required analyzer unavailable)
  130 cancelled by the user
"""

from __future__ import annotations

import json
import signal
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn

from aegisai import __version__
from aegisai.config import find_config_file, load_config, write_default_config
from aegisai.engine.baseline import baseline_from_result, write_baseline
from aegisai.engine.registry import default_registry
from aegisai.engine.runner import ScanOptions, run_scan
from aegisai.exceptions import AegisError, ConfigurationError, ScanCancelledError
from aegisai.integrations import ALL_INTEGRATIONS
from aegisai.integrations.subprocess_runner import resolve_executable, tool_version
from aegisai.models.configuration import DEFAULT_CONFIG_FILENAME, Profile, ReportFormat
from aegisai.models.finding import Severity
from aegisai.models.scan import ExitCode, ScanResult
from aegisai.reporters import (
    render_html,
    render_json,
    render_sarif,
    render_terminal,
    write_schemas,
)
from aegisai.utils.logging import configure_logging, get_logger

app = typer.Typer(
    name="aegisai",
    help="AegisAI - security scanner for LLM, RAG, agent and MCP applications.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode=None,
)
rules_app = typer.Typer(help="Inspect built-in rules.", no_args_is_help=True)
config_app = typer.Typer(help="Manage configuration.", no_args_is_help=True)
baseline_app = typer.Typer(help="Create baselines for existing findings.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")
app.add_typer(config_app, name="config")
app.add_typer(baseline_app, name="baseline")

log = get_logger("cli")
_stderr = Console(stderr=True, highlight=False)


class _Cancellation:
    """Cooperative cancellation driven by SIGINT/SIGTERM."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def install(self) -> None:
        def handler(_signum: int, _frame: Any) -> None:
            self._event.set()

        try:
            signal.signal(signal.SIGINT, handler)
            signal.signal(signal.SIGTERM, handler)
        except (ValueError, OSError):  # not in main thread
            pass

    def requested(self) -> bool:
        return self._event.is_set()


def _fail(message: str, code: int = ExitCode.FAILED) -> None:
    _stderr.print(f"[bold red]error:[/bold red] {message}")
    raise typer.Exit(code)


def _parse_severity(value: str | None) -> Severity | None:
    if value is None:
        return None
    if value.lower() in {"none", "off"}:
        return None
    try:
        return Severity(value.lower())
    except ValueError as exc:
        raise typer.BadParameter(
            f"unknown severity {value!r}; choose from {', '.join(s.value for s in Severity)} or none"
        ) from exc


def _parse_profiles(values: list[str] | None) -> list[Profile] | None:
    if not values:
        return None
    profiles: list[Profile] = []
    for raw in values:
        for item in raw.split(","):
            item = item.strip().lower()
            if not item:
                continue
            try:
                profiles.append(Profile(item))
            except ValueError as exc:
                raise typer.BadParameter(
                    f"unknown profile {item!r}; choose from {', '.join(p.value for p in Profile)}"
                ) from exc
    return profiles or None


def _parse_formats(values: list[str] | None) -> list[ReportFormat]:
    if not values:
        return [ReportFormat.TERMINAL]
    formats: list[ReportFormat] = []
    for raw in values:
        for item in raw.split(","):
            item = item.strip().lower()
            if not item:
                continue
            try:
                fmt = ReportFormat(item)
            except ValueError as exc:
                raise typer.BadParameter(
                    f"unknown format {item!r}; choose from {', '.join(f.value for f in ReportFormat)}"
                ) from exc
            if fmt not in formats:
                formats.append(fmt)
    return formats


def _read_exclude_file(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise typer.BadParameter(f"cannot read exclude file {path}: {exc}") from exc
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Project directory to scan.", exists=False)] = Path(
        "."
    ),
    profile: Annotated[
        list[str] | None,
        typer.Option(
            "--profile",
            "-p",
            help="Scan profile(s): all, ai, llm, agents, rag, mcp, code, secrets, dependencies. Repeatable or comma-separated.",
        ),
    ] = None,
    severity: Annotated[
        str | None,
        typer.Option("--severity", "-s", help="Only report findings at or above this severity."),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on", help="Exit 1 when an active finding reaches this severity (or 'none')."
        ),
    ] = None,
    fmt: Annotated[
        list[str] | None,
        typer.Option(
            "--format", "-f", help="Report format(s): terminal, json, sarif, html. Repeatable."
        ),
    ] = None,
    output: Annotated[
        list[Path] | None,
        typer.Option(
            "--output",
            "-o",
            help="Output file for each non-terminal format, in order. Omit to write to stdout.",
        ),
    ] = None,
    config_file: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help=f"Configuration file (default: nearest {DEFAULT_CONFIG_FILENAME}).",
        ),
    ] = None,
    no_config: Annotated[
        bool, typer.Option("--no-config", help="Ignore any configuration file and use defaults.")
    ] = False,
    baseline: Annotated[
        Path | None,
        typer.Option(
            "--baseline", help="Baseline file; only new findings count towards --fail-on."
        ),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", "-e", help="Additional glob pattern to exclude. Repeatable."),
    ] = None,
    exclude_file: Annotated[
        Path | None, typer.Option("--exclude-file", help="File with one exclude glob per line.")
    ] = None,
    disable_rule: Annotated[
        list[str] | None, typer.Option("--disable-rule", help="Rule id to disable. Repeatable.")
    ] = None,
    timeout: Annotated[
        int | None, typer.Option("--timeout", min=1, help="Overall scan timeout in seconds.")
    ] = None,
    max_file_size_kb: Annotated[
        int | None, typer.Option("--max-file-size-kb", min=1, help="Skip files larger than this.")
    ] = None,
    no_integrations: Annotated[
        bool,
        typer.Option(
            "--no-integrations",
            help="Run only built-in deterministic rules (no gitleaks/osv-scanner/semgrep).",
        ),
    ] = False,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            help="Treat enabled-but-unavailable integrations as a scan failure (exit 3).",
        ),
    ] = False,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="Only print the summary line and errors.")
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Print diagnostics, skipped rules and full warnings."),
    ] = False,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable coloured output.")] = False,
    no_progress: Annotated[
        bool, typer.Option("--no-progress", help="Disable the progress bar.")
    ] = False,
) -> None:
    """Scan a project directory for AI application security weaknesses."""
    configure_logging(verbose=verbose, quiet=quiet)
    cancellation = _Cancellation()
    cancellation.install()

    try:
        resolved_root = path.expanduser().resolve()
        if no_config:
            config_path = None
        elif config_file is not None:
            if not config_file.is_file():
                _fail(f"configuration file not found: {config_file}")
            config_path = config_file
        else:
            config_path = find_config_file(resolved_root if resolved_root.is_dir() else Path.cwd())
        config = load_config(config_path)
    except ConfigurationError as exc:
        _fail(str(exc))
        return

    formats = _parse_formats(fmt)
    file_formats = [f for f in formats if f is not ReportFormat.TERMINAL]
    outputs = list(output or [])
    if len(outputs) > len(file_formats):
        _fail("more --output paths than non-terminal formats")
    excludes = list(exclude or [])
    if exclude_file is not None:
        excludes.extend(_read_exclude_file(exclude_file))
    stdout_formats = [f for i, f in enumerate(file_formats) if i >= len(outputs)]
    terminal_stream = sys.stderr if stdout_formats else sys.stdout

    options = ScanOptions(
        root=resolved_root,
        config=config,
        config_path=config_path,
        profiles=_parse_profiles(profile),
        min_severity=_parse_severity(severity),
        fail_on=_parse_severity(fail_on),
        fail_on_overridden=fail_on is not None,
        baseline_path=baseline,
        extra_excludes=excludes,
        disabled_rules=list(disable_rule or []),
        timeout_seconds=timeout,
        max_file_size_kb=max_file_size_kb,
        no_integrations=no_integrations,
        strict_integrations=True if strict else None,
        command_line=["aegisai", *sys.argv[1:]],
        should_cancel=cancellation.requested,
    )

    show_progress = not (quiet or no_progress) and sys.stderr.isatty()
    result: ScanResult
    try:
        if show_progress:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=_stderr,
                transient=True,
            ) as progress_bar:
                task = progress_bar.add_task("scanning", total=None)

                def on_progress(message: str, index: int, total: int) -> None:
                    progress_bar.update(
                        task, description=message[:60], completed=index, total=total or None
                    )

                options.progress = on_progress
                result = run_scan(options)
        else:
            result = run_scan(options)
    except ScanCancelledError:
        _stderr.print("[bold red]scan cancelled[/bold red]")
        raise typer.Exit(ExitCode.CANCELLED) from None
    except KeyboardInterrupt:
        _stderr.print("[bold red]scan cancelled[/bold red]")
        raise typer.Exit(ExitCode.CANCELLED) from None
    except AegisError as exc:
        _fail(str(exc))
        return
    except Exception as exc:
        log.error("internal error", exc_info=verbose)
        _fail(f"internal error: {type(exc).__name__}: {exc}")
        return

    rules_meta = default_registry().metadata()
    for index, report_format in enumerate(file_formats):
        if report_format is ReportFormat.JSON:
            text = render_json(result)
        elif report_format is ReportFormat.SARIF:
            text = render_sarif(result, rules_meta)
        else:
            text = render_html(result)
        if index < len(outputs):
            target = outputs[index]
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text + "\n", encoding="utf-8")
            except OSError as exc:
                _fail(f"cannot write report {target}: {exc}")
            if not quiet:
                _stderr.print(f"wrote {report_format.value} report to {target}")
        else:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()

    if ReportFormat.TERMINAL in formats:
        render_terminal(
            result,
            stream=terminal_stream,
            color=not no_color and terminal_stream.isatty(),
            quiet=quiet,
            verbose=verbose,
        )
    elif not quiet:
        render_terminal(result, stream=sys.stderr, color=False, quiet=True)
    raise typer.Exit(result.summary.exit_code)


@app.command()
def version() -> None:
    """Print the AegisAI version."""
    typer.echo(f"aegisai {__version__}")


@app.command()
def doctor() -> None:
    """Check which external integrations are available."""
    registry = default_registry()
    typer.echo(f"aegisai {__version__} - {len(registry)} built-in rules")
    typer.echo(f"python {sys.version.split()[0]}")
    for name, analyzer_cls in ALL_INTEGRATIONS.items():
        analyzer = analyzer_cls()
        try:
            executable = resolve_executable(analyzer.executable_name)
        except AegisError as exc:
            typer.echo(f"{name}: unavailable ({exc})")
            continue
        found = tool_version(executable, "version" if name == "gitleaks" else "--version")
        typer.echo(f"{name}: {executable} ({found or 'version unknown'})")


@app.command()
def schema(
    output_dir: Annotated[
        Path, typer.Option("--output-dir", "-o", help="Directory for JSON Schema files.")
    ] = Path("docs/schema"),
) -> None:
    """Write JSON Schema files for the scan result and finding formats."""
    for written in write_schemas(output_dir):
        typer.echo(f"wrote {written}")


@rules_app.command("list")
def rules_list(
    profile: Annotated[
        list[str] | None, typer.Option("--profile", "-p", help="Only rules in these profiles.")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """List built-in rules."""
    from aegisai.models.configuration import packs_for_profiles

    registry = default_registry()
    profiles = _parse_profiles(profile) or [Profile.ALL]
    packs = packs_for_profiles(profiles)
    rules = [r.metadata for r in registry if r.metadata.pack in packs]
    if as_json:
        typer.echo(json.dumps([r.model_dump(mode="json") for r in rules], indent=2))
        return
    typer.echo(f"{'ID':<8}{'SEVERITY':<15}{'PACK':<14}{'CONF':<8}NAME")
    for meta in rules:
        flag = " (heuristic)" if meta.heuristic else ""
        typer.echo(
            f"{meta.rule_id:<8}{meta.default_severity.value:<15}{meta.pack.value:<14}{meta.default_confidence.value:<8}{meta.name}{flag}"
        )
    typer.echo(f"\n{len(rules)} rule(s)")


@rules_app.command("show")
def rules_show(
    rule_id: Annotated[str, typer.Argument(help="Rule identifier, e.g. LLM001.")],
) -> None:
    """Show the full definition of a rule."""
    rule = default_registry().get(rule_id.upper())
    if rule is None:
        _fail(f"unknown rule {rule_id}")
        return
    meta = rule.metadata
    typer.echo(f"{meta.rule_id} - {meta.name} (v{meta.version})")
    typer.echo(
        f"category: {meta.category.value} | pack: {meta.pack.value} | severity: {meta.default_severity.value} | confidence: {meta.default_confidence.value}"
    )
    typer.echo(f"artifacts: {', '.join(a.value for a in meta.artifact_types)}")
    if meta.requires_integration:
        typer.echo(f"requires integration: {meta.requires_integration}")
    typer.echo(f"heuristic: {'yes (review required)' if meta.heuristic else 'no'}")
    typer.echo("")
    typer.echo(meta.description)
    typer.echo("")
    typer.echo(f"confidence: {meta.confidence_behavior}")
    typer.echo(f"impact: {meta.impact}")
    typer.echo(f"remediation: {meta.remediation}")
    if meta.cwe_ids:
        typer.echo(f"cwe: {', '.join(meta.cwe_ids)}")
    if meta.owasp_references:
        typer.echo(f"owasp: {', '.join(meta.owasp_references)}")
    for ref in meta.references:
        typer.echo(f"  - {ref}")


@config_app.command("init")
def config_init(
    path: Annotated[Path, typer.Option("--path", help="Where to write the configuration.")] = Path(
        DEFAULT_CONFIG_FILENAME
    ),
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing file.")] = False,
) -> None:
    """Write a documented default .aegisai.yaml."""
    try:
        written = write_default_config(path, force=force)
    except ConfigurationError as exc:
        _fail(str(exc))
        return
    typer.echo(f"wrote {written}")


@baseline_app.command("create")
def baseline_create(
    path: Annotated[Path, typer.Argument(help="Project directory to scan.")] = Path("."),
    output: Annotated[Path, typer.Option("--output", "-o", help="Baseline file to write.")] = Path(
        "aegis-baseline.json"
    ),
    profile: Annotated[list[str] | None, typer.Option("--profile", "-p")] = None,
    no_integrations: Annotated[bool, typer.Option("--no-integrations")] = False,
) -> None:
    """Scan the project and record all current findings as the baseline."""
    configure_logging()
    try:
        resolved_root = path.expanduser().resolve()
        config_path = find_config_file(resolved_root)
        config = load_config(config_path)
        result = run_scan(
            ScanOptions(
                root=resolved_root,
                config=config,
                config_path=config_path,
                profiles=_parse_profiles(profile),
                no_integrations=no_integrations,
                command_line=["aegisai", *sys.argv[1:]],
            )
        )
    except AegisError as exc:
        _fail(str(exc))
        return
    if result.status.value in {"failed", "incomplete"}:
        _fail(
            f"refusing to write a baseline from an {result.status.value} scan: {result.status_reason}",
            ExitCode.INCOMPLETE,
        )
    write_baseline(baseline_from_result(result), output)
    typer.echo(f"wrote baseline with {len(result.findings)} finding(s) to {output}")


def main(argv: Sequence[str] | None = None) -> None:
    """Console-script entry point."""
    app(args=list(argv) if argv is not None else None, prog_name="aegisai")


if __name__ == "__main__":  # pragma: no cover
    main()
