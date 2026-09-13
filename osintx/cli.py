"""OSINT-X AI — command-line interface.

Entry point registered as `osintx` (see osintx.py / pyproject setup).
"""
from __future__ import annotations

from functools import wraps
import sqlite3
import unicodedata
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.markup import escape
from rich.text import Text

from config.loader import ensure_user_config, load_config, ConfigError
from ai.provider import AIProviderError
from ai.engine import build_provider
from core.orchestrator import Orchestrator
from core.tool_registry import ToolRegistry
from database.store import get_by_id, get_latest, list_history, save_investigation, HistoryError
from reports.generator import generate_reports, validate_formats
from utils.logger import setup_logging
from utils.validators import ValidationError

app = typer.Typer(
    name="osintx",
    help="OSINT-X AI — AI-Powered Linux OSINT Investigation Framework",
    add_completion=True,
)
console = Console()


def guard_cli(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except KeyboardInterrupt:
            console.print("Interrupted; running command stopped.", markup=False)
            raise typer.Exit(130)
        except (ConfigError, ValidationError, AIProviderError, HistoryError) as exc:
            console.print(f"Error: {exc}", markup=False)
            raise typer.Exit(1)
        except (OSError, sqlite3.Error) as exc:
            console.print(f"Filesystem/history error ({type(exc).__name__}); check path and permissions.", markup=False)
            raise typer.Exit(1)
    return wrapped

BANNER = r"""
 ██████╗ ███████╗██╗███╗   ██╗████████╗   ██╗  ██╗     █████╗ ██╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝   ╚██╗██╔╝    ██╔══██╗██║
██║   ██║███████╗██║██╔██╗ ██║   ██║   █████╗╚███╔╝     ███████║██║
██║   ██║╚════██║██║██║╚██╗██║   ██║   ╚════╝██╔██╗     ██╔══██║██║
╚██████╔╝███████║██║██║ ╚████║   ██║        ██╔╝ ██╗    ██║  ██║██║
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝        ╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝
        AI-Powered Linux OSINT Investigation Framework
"""

VALID_TARGET_FLAGS = ["name", "username", "email", "phone", "domain", "ip", "company", "image"]


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        console.print(Panel.fit(BANNER, style="bold cyan"))
        console.print(ctx.get_help())


@app.command()
@guard_cli
def version():
    """Show version information."""
    console.print("[bold cyan]OSINT-X AI[/] version [bold]1.1.0[/]")
    console.print("Python 3.10+ · Linux CLI OSINT Framework")


@app.command()
@guard_cli
def config(
    init: bool = typer.Option(False, "--init", help="Create ~/.osintx/config.yaml from the default template"),
    show: bool = typer.Option(False, "--show", help="Print the resolved configuration"),
):
    """View or initialize configuration."""
    if init:
        path = ensure_user_config()
        console.print(f"[green]Config initialized at[/] {path}")
    if show or not init:
        cfg = load_config()
        console.print_json(data=cfg.model_dump(mode="json"))


@app.command("update-tools")
@guard_cli
def update_tools():
    """Show detection status for every supported Linux OSINT tool."""
    cfg = load_config()
    registry = ToolRegistry(configured_paths=cfg.tools)

    table = Table(title="OSINT-X AI — Tool Detection Status")
    table.add_column("Tool")
    table.add_column("Status")
    for name, status in registry.summary_table_rows():
        table.add_row(name, status)
    console.print(table)

    missing = registry.missing_tools()
    if missing:
        console.print(
            f"\n[yellow]{len(missing)} tool(s) not detected.[/] Install them via your package "
            "manager or pip/go, then re-run this command. Missing tools are skipped gracefully "
            "during investigations."
        )


@app.command()
@guard_cli
def investigate(
    name: Optional[str] = typer.Option(None, help="Full name to investigate"),
    username: Optional[str] = typer.Option(None, help="Username to investigate"),
    email: Optional[str] = typer.Option(None, help="Email address to investigate"),
    phone: Optional[str] = typer.Option(None, help="Phone number to investigate (syntax check only)"),
    domain: Optional[str] = typer.Option(None, help="Domain to investigate"),
    ip: Optional[str] = typer.Option(None, help="IP address to investigate"),
    company: Optional[str] = typer.Option(None, help="Company name to investigate"),
    image: Optional[str] = typer.Option(None, help="Path to an image file to investigate"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", help="Override configured output directory"),
    formats: Optional[str] = typer.Option(None, "--formats", help="Comma-separated report formats to generate"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI prioritization"),
    offline: bool = typer.Option(False, "--offline", help="Run local processing and suggestions only; no network collection or AI"),
    i_have_authorization: bool = typer.Option(
        False, "--i-have-authorization",
        help="Confirms you are authorized to port-scan the IP target (required for nmap step)",
    ),
):
    """Run an OSINT investigation against a single target."""
    provided = {k: v for k, v in {
        "person": name, "username": username, "email": email, "phone": phone,
        "domain": domain, "ip": ip, "company": company, "image": image,
    }.items() if v is not None}

    if len(provided) == 0:
        console.print("[red]Error:[/] provide exactly one target flag, e.g. --domain example.com")
        raise typer.Exit(code=1)
    if len(provided) > 1:
        console.print(f"[red]Error:[/] provide only one target flag at a time (got {list(provided.keys())})")
        raise typer.Exit(code=1)

    target_type, target_value = next(iter(provided.items()))

    if target_type == "phone":
        console.print(
            "[yellow]Phone investigation is limited to syntax validation only in this release "
            "(no carrier/OSINT lookups are performed to avoid unreliable or invasive data "
            "sources).[/]"
        )
        from utils.validators import validate_phone
        try:
            validate_phone(target_value)
            console.print(f"[green]'{target_value}' is a syntactically valid phone number.[/]")
        except ValidationError as exc:
            console.print(str(exc), markup=False)
            raise typer.Exit(code=1)
        raise typer.Exit(code=0)

    cfg = load_config()
    fmt_list = validate_formats(formats.split(",") if formats is not None else cfg.reports.formats)
    setup_logging(cfg.general.log_dir, cfg.general.log_level)

    orchestrator = Orchestrator(cfg)

    console.print(Panel.fit(f"Investigating [bold]{target_type}[/] = [bold cyan]{escape(target_value)}[/]"))

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task(description="Running OSINT modules & tools...", total=None)
        try:
            investigation = orchestrator.investigate(
                target_type, target_value,
                use_ai=not no_ai and not offline,
                offline=offline,
                allow_port_scan=i_have_authorization,
            )
        except ValidationError as exc:
            progress.stop()
            console.print(f"[red]Validation error:[/] {exc}")
            raise typer.Exit(code=1)
        except ValueError as exc:
            progress.stop()
            console.print(f"[red]Error:[/] {exc}")
            raise typer.Exit(code=1)
        progress.update(task, completed=True)

    try:
        save_investigation(investigation)
    except (OSError, sqlite3.Error) as exc:
        investigation.warnings.append(f'History could not be saved ({type(exc).__name__}); collection results retained.')
    out_dir = output_dir or cfg.general.output_dir
    written = generate_reports(investigation, out_dir, fmt_list)

    _print_summary(investigation)
    console.print("\nReports written:" if written else "\nNo reports written; see warnings.", markup=False)
    for fmt, path in written.items():
        console.print(f"  {fmt}: {path}", markup=False)
    if len(written) != len(fmt_list):
        raise typer.Exit(1)


def _terminal(value):
    return ''.join(c if not unicodedata.category(c).startswith('C') or c in '\n\t' else '\ufffd' for c in str(value))


def _print_summary(investigation):
    console.print(f"OSINT-X AI — {investigation.target_type}: {investigation.target_value}", markup=False)
    console.print(f"Investigation: {investigation.id} | AI: {investigation.ai_status.value}", markup=False)
    for title, entities in investigation.entity_groups():
        table = Table(title=title)
        for header in ('Type', 'Value', 'Source', 'Status'):
            table.add_column(header, overflow='fold')
        for entity in entities:
            table.add_row(Text(entity.type.value), Text(_terminal(entity.value)), Text(_terminal(entity.source)), Text(entity.status.value))
        console.print(table if entities else Text(f'{title}: none'))
    table = Table(title='SOURCE RESULTS / ERRORS / UNAVAILABLE SOURCES')
    for header in ('Source', 'Status', 'Details'):
        table.add_column(header, overflow='fold')
    for result in investigation.tool_results:
        table.add_row(Text(_terminal(result.tool)), Text(result.status.value), Text(_terminal(result.error or '')))
    console.print(table)
    if investigation.suggestions:
        console.print('SEARCH SUGGESTIONS (UNVERIFIED; not discoveries)', markup=False)
        for suggestion in investigation.suggestions:
            console.print(f"  {suggestion['label']}: {suggestion['url']}", markup=False)
    for warning in investigation.warnings:
        console.print('Warning: ' + _terminal(warning), markup=False)


@app.command()
@guard_cli
def report(
    which: str = typer.Argument("latest", help="'latest' or an investigation ID"),
):
    """Re-display a previously stored investigation summary."""
    data = get_latest() if which == "latest" else get_by_id(which)
    if not data:
        console.print(f"[red]No investigation found for '{which}'.[/]")
        raise typer.Exit(code=1)

    if any('status' not in entity for entity in data.get('entities', [])):
        console.print('Legacy report: findings have not been verified under the current status schema.', markup=False)
    console.print_json(data=data)


@app.command()
@guard_cli
def history(limit: int = typer.Option(20, min=1, max=1000, help="How many past investigations to list")):
    """List past investigations stored locally."""
    rows = list_history(limit)
    if not rows:
        console.print("[yellow]No investigation history yet.[/]")
        return
    table = Table(title="Investigation History")
    table.add_column("ID")
    table.add_column("Type")
    table.add_column("Target")
    table.add_column("Started")
    table.add_column("Entities")
    for r in rows:
        table.add_row(*(Text(str(r[key])) for key in ("id", "target_type", "target_value", "started_at", "entity_count")))
    console.print(table)


@app.command()
@guard_cli
def models(provider: Optional[str] = typer.Option(None, help="gemini, groq, or ollama")):
    """List models returned by the selected provider (requires network/local service)."""
    cfg = load_config()
    if provider:
        if provider not in ('gemini', 'groq', 'ollama'):
            raise ValidationError('Provider must be gemini, groq, or ollama')
        cfg.ai.provider = provider
    for model in build_provider(cfg.ai).list_models():
        console.print(model, markup=False)


if __name__ == "__main__":
    app()
