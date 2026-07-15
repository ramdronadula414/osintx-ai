"""OSINT-X AI — command-line interface.

Entry point registered as `osintx` (see osintx.py / pyproject setup).
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ai.engine import AIEngine
from config.loader import ensure_user_config, load_config
from core.orchestrator import Orchestrator
from core.tool_registry import ToolRegistry
from database.store import get_by_id, get_latest, list_history, save_investigation
from reports.generator import generate_reports
from utils.logger import setup_logging
from utils.validators import ValidationError

app = typer.Typer(
    name="osintx",
    help="OSINT-X AI — AI-Powered Linux OSINT Investigation Framework",
    add_completion=True,
)
console = Console()

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
def version():
    """Show version information."""
    console.print("[bold cyan]OSINT-X AI[/] version [bold]1.0.0[/]")
    console.print("Python 3.11+ · Linux CLI OSINT Framework")


@app.command()
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
        console.print_json(data=cfg.model_dump())


@app.command("update-tools")
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
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI enrichment (facts-only report)"),
    i_have_authorization: bool = typer.Option(
        False, "--i-have-authorization",
        help="Confirms you are authorized to port-scan the IP target (required for nmap step)",
    ),
):
    """Run an OSINT investigation against a single target."""
    provided = {k: v for k, v in {
        "person": name, "username": username, "email": email, "phone": phone,
        "domain": domain, "ip": ip, "company": company, "image": image,
    }.items() if v}

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
            console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=0)

    cfg = load_config()
    setup_logging(cfg.general.log_dir, cfg.general.log_level)

    orchestrator = Orchestrator(cfg)

    console.print(Panel.fit(f"Investigating [bold]{target_type}[/] = [bold cyan]{target_value}[/]"))

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task(description="Running OSINT modules & tools...", total=None)
        try:
            investigation = orchestrator.investigate(
                target_type, target_value,
                use_ai=not no_ai,
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

    save_investigation(investigation)

    fmt_list = [f.strip() for f in formats.split(",")] if formats else cfg.reports.formats
    out_dir = output_dir or cfg.general.output_dir
    written = generate_reports(investigation, out_dir, fmt_list)

    _print_summary(investigation)
    console.print("\n[bold green]Reports written:[/]")
    for fmt, path in written.items():
        console.print(f"  [cyan]{fmt}[/]: {path}")


def _print_summary(investigation):
    table = Table(title=f"Investigation Summary — {investigation.id}")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Target", f"{investigation.target_type} = {investigation.target_value}")
    table.add_row("Entities Collected", str(len(investigation.entities)))
    table.add_row("Tools Run", str(len(investigation.tool_results)))
    table.add_row("Exposure Score", str(investigation.risk.exposure_score))
    table.add_row("Confidence Score", str(investigation.risk.confidence_score))
    console.print(table)

    if investigation.warnings:
        console.print("\n[yellow]Warnings:[/]")
        for w in investigation.warnings:
            console.print(f"  ⚠ {w}")


@app.command()
def report(
    which: str = typer.Argument("latest", help="'latest' or an investigation ID"),
):
    """Re-display a previously stored investigation summary."""
    data = get_latest() if which == "latest" else get_by_id(which)
    if not data:
        console.print(f"[red]No investigation found for '{which}'.[/]")
        raise typer.Exit(code=1)

    console.print_json(data=data)


@app.command()
def history(limit: int = typer.Option(20, help="How many past investigations to list")):
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
        table.add_row(r["id"], r["target_type"], r["target_value"], r["started_at"], str(r["entity_count"]))
    console.print(table)


if __name__ == "__main__":
    app()
