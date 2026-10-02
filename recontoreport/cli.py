"""Command-line entrypoint for ReconToReport.

Usage examples:
    r2r run --config config.yaml --phases 1 --i-have-authorization
    r2r report --config config.yaml
    r2r initdb --config config.yaml
"""

from __future__ import annotations

import logging
import sys

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from . import __version__
from .config import Config
from .db import create_all, make_engine, make_session_factory
from .orchestrator import Orchestrator, parse_phase_arg
from .report import generate_reports

console = Console()

DEFAULT_PHASES = [1, 2, 3, 4, 5]


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
    )


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="recontoreport")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """ReconToReport — authorized-pentest recon-to-report pipeline."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)


@main.command("initdb")
@click.option("--config", "config_path", required=True, type=click.Path(exists=True))
def initdb(config_path: str) -> None:
    """Create database tables (quick-start; prefer `alembic upgrade head`)."""
    cfg = Config.load(config_path)
    engine = make_engine(cfg.database_url)
    create_all(engine)
    console.print(f"[green]Initialized database:[/] {cfg.database_url}")


@main.command("run")
@click.option("--config", "config_path", default=None, type=click.Path(exists=True),
              help="Config file. Optional if --url is given.")
@click.option("--url", "url", default=None,
              help="Target website URL. Used alone (no --config) for a quick scan, "
                   "or with --config to override its target.url.")
@click.option(
    "--phases", "phases_arg", default=None,
    help="Which phases to run: e.g. '1,2,3', '1 2 3', a single '3', or 'all'. "
    "Default: all. Dependency phases are added automatically.",
)
@click.option(
    "--i-have-authorization",
    "authorized",
    is_flag=True,
    default=False,
    help="Confirm you have explicit written authorization to test the target. "
    "REQUIRED before any active scanning phase runs.",
)
@click.option("--report/--no-report", default=True, help="Render a report after phases run.")
@click.pass_context
def run(
    ctx: click.Context,
    config_path: str,
    url: str | None,
    phases_arg: str | None,
    authorized: bool,
    report: bool,
) -> None:
    """Run the pipeline phases against the target."""
    from urllib.parse import urlparse
    from .phases import resolve_phases

    if not config_path and not url:
        raise click.UsageError("provide --config <file> and/or --url <target>.")

    from .config import normalize_url

    if config_path:
        cfg = Config.load(config_path)
        # --url overrides the configured target, auto-adding its host to scope.
        if url:
            cfg.target_url = normalize_url(url)
            host = urlparse(cfg.target_url).hostname or ""
            if host and not cfg.scope.in_scope(host):
                cfg.scope.include.extend([host, f"*.{host}"])
                console.print(f"[yellow]Added '{host}' (and *.{host}) to scope for this run.[/]")
    else:
        # --url only: build a default config on the fly.
        cfg = Config.from_url(url)
        console.print("[dim]No --config given; using defaults (db: recontoreport.db, reports: ./reports).[/]")

    requested = parse_phase_arg(phases_arg, DEFAULT_PHASES)
    phase_numbers, auto_added = resolve_phases(requested)

    console.rule("[bold]ReconToReport")
    console.print(f"Target : [cyan]{cfg.target_url}[/]")
    console.print(f"Phases : {phase_numbers}" + (
        f"  [dim](auto-added dependencies: {auto_added})[/]" if auto_added else ""
    ))
    console.print(f"Scope  : include={cfg.scope.include} exclude={cfg.scope.exclude}")

    if not authorized:
        console.print(
            "\n[yellow bold]No authorization flag provided.[/] "
            "Active scanning phases will be SKIPPED.\n"
            "Re-run with [bold]--i-have-authorization[/] once you have explicit, "
            "written permission from the target owner.\n"
        )

    orch = Orchestrator(cfg, authorized=authorized)
    results = orch.run(phase_numbers)

    table = Table(title="Phase results", show_lines=False)
    table.add_column("Phase")
    table.add_column("Name")
    table.add_column("Result")
    table.add_column("Assets", justify="right")
    table.add_column("Findings", justify="right")
    for r in results:
        if r.skipped:
            state = "[yellow]SKIPPED[/]"
        elif r.ok:
            state = "[green]OK[/]"
        else:
            state = "[red]FAILED[/]"
        table.add_row(str(r.number), r.name, state, str(r.assets_created), str(r.findings_created))
    console.print(table)

    for r in results:
        for err in r.errors:
            console.print(f"  [red]phase {r.number}:[/] {err}")

    if report:
        _render(cfg, orch)

    # Non-zero exit if any non-skipped phase failed, so CI/scripts can detect it.
    if any((not r.ok and not r.skipped) for r in results):
        sys.exit(1)


@main.command("report")
@click.option("--config", "config_path", default=None, type=click.Path(exists=True),
              help="Config file. Optional if --url is given.")
@click.option("--url", "url", default=None, help="Target URL (uses default config).")
def report_cmd(config_path: str | None, url: str | None) -> None:
    """Render a report from the existing data store (no scanning)."""
    if not config_path and not url:
        raise click.UsageError("provide --config <file> and/or --url <target>.")
    from .config import normalize_url

    if config_path:
        cfg = Config.load(config_path)
        if url:
            cfg.target_url = normalize_url(url)
    else:
        cfg = Config.from_url(url)
    orch = Orchestrator(cfg, authorized=False, init_db=False)
    _render(cfg, orch)


def _render(cfg: Config, orch: Orchestrator) -> None:
    # Resolve the target id for the configured URL.
    from sqlalchemy import select
    from .models import Target

    factory = make_session_factory(orch.engine)
    s = factory()
    try:
        target = s.execute(
            select(Target).where(Target.url == cfg.target_url)
        ).scalar_one_or_none()
        if target is None:
            console.print("[red]No target found in the database for this URL. Run phases first.[/]")
            return
        target_id = target.id
    finally:
        s.close()

    written = generate_reports(factory, target_id, cfg.output_dir, cfg.output_formats)
    for path in written:
        console.print(f"[green]Report written:[/] {path.resolve()}")
    if not written:
        console.print("[yellow]No report formats produced (check output.formats).[/]")
        return written

    # Call out the HTML report path on its own line so it's easy to copy / open.
    html = next((p for p in written if p.suffix == ".html"), written[0])
    console.print(f"\n[bold]Open the report:[/] [cyan]{html.resolve()}[/]")
    console.print(f"[dim]  macOS:   open \"{html.resolve()}\"[/]")
    console.print(f"[dim]  Linux:   xdg-open \"{html.resolve()}\"[/]")
    return written


@main.command("ui")
@click.option("--port", default=8000, help="Port to serve on (default 8000).")
@click.option("--no-open", is_flag=True, default=False, help="Don't auto-open the browser.")
def ui_cmd(port: int, no_open: bool) -> None:
    """Launch the browser-based UI (needs the 'ui' extra: pip install -e '.[ui]')."""
    try:
        from .web.app import main as run_ui
    except ImportError:
        console.print("[red]Flask not installed.[/] Run: pip install -e \".[ui]\"")
        raise SystemExit(1)
    run_ui(port=port, open_browser=not no_open)


if __name__ == "__main__":
    main()
