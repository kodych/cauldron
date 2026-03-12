"""Cauldron CLI commands.

Themed after brewing potions:
  brew   — import scan files (throw ingredients in)
  boil   — run AI analysis
  taste  — view graph statistics
  paths  — show attack paths
  pour   — export report
  reset  — clear the cauldron
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

# Force UTF-8 output on Windows to avoid cp1252 encoding errors
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

console = Console()

BANNER = """
[bold magenta]   .-'~~~'-.
  /   .===.  \\
  |  ( o o )  |
  \\   .---.  /     Cauldron
   '-.....-'
   _|     |_       Network Attack Path Discovery
  |  \\___/  |
  |_________|      Throw your scans in. Get attack paths out.[/bold magenta]
"""

ROLE_ICONS = {
    "domain_controller": "[red]DC[/red]",
    "web_server": "[blue]WEB[/blue]",
    "database": "[yellow]DB[/yellow]",
    "mail_server": "[magenta]MAIL[/magenta]",
    "network_equipment": "[green]NET[/green]",
    "printer": "[white]PRT[/white]",
    "voip": "[cyan]VOIP[/cyan]",
    "remote_access": "[bright_yellow]RDP[/bright_yellow]",
    "file_server": "[bright_blue]FS[/bright_blue]",
    "unknown": "[dim]?[/dim]",
}


@click.group()
@click.version_option(version="0.1.0", prog_name="cauldron")
def cli():
    """Cauldron -- Network Attack Path Discovery."""
    pass


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--source", "-s", default=None, help="Scan source name/IP (where was scan run from)")
@click.option("--masscan", is_flag=True, default=False, help="Parse as Masscan output (default: Nmap XML)")
def brew(file: Path, source: str | None, masscan: bool):
    """Import scan results into the cauldron.

    FILE is the path to an Nmap XML (-oX) or Masscan output file.
    """
    console.print(BANNER)

    if masscan:
        console.print("[yellow]Masscan parser not yet implemented. Coming soon![/yellow]")
        raise SystemExit(1)

    console.print(f"[bold cyan]Brewing:[/bold cyan] {file.name}")
    console.print(f"[dim]  Source: {source or 'auto-detect'}[/dim]")
    console.print()

    # Parse
    with console.status("[bold green]Parsing scan file..."):
        from cauldron.parsers.nmap_parser import parse_nmap_xml

        try:
            scan = parse_nmap_xml(file)
        except Exception as e:
            console.print(f"[bold red]x Failed to parse:[/bold red] {e}")
            raise SystemExit(1)

    console.print(f"  [green]+[/green] Parsed {len(scan.hosts_up)} live hosts, {scan.total_services} services")

    if not scan.hosts_up:
        console.print("[yellow]  ! No live hosts found in scan. Nothing to import.[/yellow]")
        return

    # Check Neo4j connection
    with console.status("[bold green]Connecting to Neo4j..."):
        from cauldron.graph.connection import verify_connection

        if not verify_connection():
            console.print("[bold red]x Cannot connect to Neo4j.[/bold red]")
            console.print("  Make sure Neo4j is running: [cyan]docker compose up -d[/cyan]")
            raise SystemExit(1)

    console.print("  [green]+[/green] Connected to Neo4j")

    # Ingest
    with console.status("[bold green]Importing into graph..."):
        from cauldron.graph.ingestion import ingest_scan

        stats = ingest_scan(scan, source_name=source)

    console.print(f"  [green]+[/green] Imported {stats['hosts_imported']} hosts, {stats['services_imported']} services")
    console.print(f"  [green]+[/green] {stats['segments_created']} network segments")
    console.print()
    console.print("[bold green]Brew complete![/bold green] Run [cyan]cauldron taste[/cyan] to see the graph stats.")


@cli.command()
def taste():
    """Show graph statistics -- what's in the cauldron."""
    from cauldron.graph.connection import verify_connection
    from cauldron.graph.ingestion import get_graph_stats, get_host_role_distribution

    if not verify_connection():
        console.print("[bold red]x Cannot connect to Neo4j.[/bold red]")
        console.print("  Make sure Neo4j is running: [cyan]docker compose up -d[/cyan]")
        raise SystemExit(1)

    stats = get_graph_stats()
    roles = get_host_role_distribution()

    console.print()
    console.print("[bold magenta]Cauldron Contents[/bold magenta]")
    console.print()

    # Main stats table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", width=20)
    table.add_column(style="bold white")
    table.add_row("Hosts", str(stats["hosts"]))
    table.add_row("Services", str(stats["services"]))
    table.add_row("Network Segments", str(stats["segments"]))
    table.add_row("Vulnerabilities", str(stats["vulnerabilities"]))
    table.add_row("Scan Sources", str(stats["scan_sources"]))
    console.print(table)

    if roles:
        console.print()
        console.print("[bold]Host Roles:[/bold]")
        role_table = Table(show_header=False, box=None, padding=(0, 2))
        role_table.add_column(style="dim", width=25)
        role_table.add_column(style="bold")

        for role, count in roles.items():
            icon = ROLE_ICONS.get(role, "[dim]?[/dim]")
            role_display = role.replace("_", " ").title()
            role_table.add_row(f"  {icon} {role_display}", str(count))
        console.print(role_table)

    console.print()


@cli.command()
@click.confirmation_option(prompt="This will delete ALL data in the cauldron. Are you sure?")
def reset():
    """Empty the cauldron -- delete all graph data."""
    from cauldron.graph.connection import clear_database, verify_connection

    if not verify_connection():
        console.print("[bold red]x Cannot connect to Neo4j.[/bold red]")
        raise SystemExit(1)

    with console.status("[bold red]Emptying the cauldron..."):
        clear_database()

    console.print("[bold red]Cauldron emptied.[/bold red] All data has been deleted.")


@cli.command()
def boil():
    """Run analysis on the graph (coming soon)."""
    console.print("[yellow]Analysis not yet implemented. Coming soon![/yellow]")
    console.print("  This will: classify hosts, enrich CVEs, discover attack paths.")


@cli.command()
def paths():
    """Show discovered attack paths (coming soon)."""
    console.print("[yellow]Attack path discovery not yet implemented. Coming soon![/yellow]")
    console.print("  This will show ranked attack paths from your position to critical targets.")


@cli.command()
@click.option("--format", "fmt", type=click.Choice(["pdf", "html", "json"]), default="html")
def pour(fmt: str):
    """Export a report from the cauldron (coming soon)."""
    console.print(f"[yellow]Report generation ({fmt}) not yet implemented. Coming soon![/yellow]")
