"""Cauldron CLI commands.

Themed after brewing potions:
  brew       — import scan files (throw ingredients in)
  boil       — run analysis (classify, exploit DB, CVE, topology, pivots)
  taste      — view graph statistics
  paths      — show attack paths with exploit details
  condiments — quick reference: guaranteed exploits per host
  pour       — export report
  reset      — clear the cauldron
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
[bold magenta]            ) (
         ) (   ) (
        ( o  O  o )
       .~~~~~~~~~~~.
      /    o    o   \\
     |   CAULDRON    |       Cauldron
     |   ~~~ * ~~~   |       Network Attack Path Discovery
      \\    o    o   /        v0.1.0
       .___________.
         |||||||||
       ^^^^^^^^^^^^
       )  )  )  )  )
      (__(__(__(__(__[/bold magenta]
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
    "hypervisor": "[bright_green]VM[/bright_green]",
    "dns_server": "[bright_cyan]DNS[/bright_cyan]",
    "proxy": "[bright_magenta]PROXY[/bright_magenta]",
    "monitoring": "[bright_white]MON[/bright_white]",
    "siem": "[bold red]SIEM[/bold red]",
    "ci_cd": "[bold yellow]CI/CD[/bold yellow]",
    "vpn_gateway": "[bold green]VPN[/bold green]",
    "backup": "[bright_blue]BAK[/bright_blue]",
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

    # Classify hosts
    from cauldron.ai.classifier import classify_hosts

    classify_hosts(scan.hosts_up)
    classified = sum(1 for h in scan.hosts_up if h.role.value != "unknown")
    console.print(f"  [green]+[/green] Classified {classified}/{len(scan.hosts_up)} hosts")

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

    # Topology info
    from cauldron.graph.topology import get_topology_stats

    topo = get_topology_stats()
    if topo["segments"]:
        console.print()
        console.print("[bold]Network Topology:[/bold]")
        seg_table = Table(show_header=True, box=None, padding=(0, 2))
        seg_table.add_column("Segment", style="cyan")
        seg_table.add_column("Hosts", style="bold", justify="right")
        seg_table.add_column("Reaches", style="green", justify="right")

        for seg in topo["segments"]:
            seg_table.add_row(
                seg["cidr"],
                str(seg["hosts"]),
                str(seg["reaches"]) if seg["reaches"] > 0 else "[dim]-[/dim]",
            )
        console.print(seg_table)

        if topo["gateways"]:
            console.print(f"  [dim]Gateway hosts: {topo['gateways']}[/dim]")

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
@click.option("--ai", is_flag=True, default=False, help="Enable AI analysis (requires CAULDRON_ANTHROPIC_API_KEY)")
def boil(ai: bool):
    """Run analysis on the graph -- classify hosts, enrich data."""
    from cauldron.graph.connection import verify_connection
    from cauldron.graph.ingestion import classify_graph_hosts

    if not verify_connection():
        console.print("[bold red]x Cannot connect to Neo4j.[/bold red]")
        raise SystemExit(1)

    console.print()
    console.print("[bold magenta]Boiling the cauldron...[/bold magenta]")
    console.print()

    # Phase 1: Host classification
    with console.status("[bold green]Classifying hosts..."):
        result = classify_graph_hosts()

    console.print(f"  [green]+[/green] Classified {result['classified']}/{result['total']} hosts")
    if result["roles"]:
        for role, count in sorted(result["roles"].items(), key=lambda x: -x[1]):
            icon = ROLE_ICONS.get(role, "[dim]?[/dim]")
            console.print(f"      {icon} {role.replace('_', ' ').title()}: {count}")

    # Phase 1.5: Local Exploit DB matching
    console.print()
    console.print("[bold cyan]Phase 2: Local Exploit Database[/bold cyan]")

    from cauldron.exploits.matcher import ExploitDB

    with console.status("[bold green]Matching services against exploit database..."):
        exploit_db = ExploitDB()
        exploit_stats = exploit_db.match_from_graph()

    if exploit_stats["exploits_found"]:
        console.print(
            f"  [bold red]![/bold red] Found [bold red]{exploit_stats['exploits_found']}[/bold red] "
            f"known exploits on [bold]{exploit_stats['hosts_matched']}[/bold] hosts"
        )
        if exploit_stats["guaranteed_wins"]:
            console.print(
                f"  [bold red]![/bold red] [bold red]{exploit_stats['guaranteed_wins']} guaranteed wins[/bold red] "
                f"(easy difficulty)"
            )
    else:
        console.print("  [dim]  No matches in local exploit database[/dim]")

    # Phase 3: CVE enrichment (NVD API)
    console.print()
    console.print("[bold cyan]Phase 3: CVE Enrichment (NVD API)[/bold cyan]")

    from cauldron.ai.cve_enricher import enrich_services_from_graph

    with console.status("[bold green]Enriching services with CVE data (this may take a while)..."):
        cve_stats = enrich_services_from_graph()

    console.print(f"  [green]+[/green] Checked {cve_stats['services_checked']} product+version pairs")
    console.print(f"  [green]+[/green] Found {cve_stats['total_cves_found']} CVEs across {cve_stats['services_with_cves']} services")
    if cve_stats["from_cache"]:
        console.print(f"  [dim]  ({cve_stats['from_cache']} from cache, {cve_stats['api_calls']} API calls)[/dim]")
    if cve_stats["errors"]:
        console.print(f"  [yellow]  ! {cve_stats['errors']} errors during enrichment[/yellow]")

    # Phase 4: Network topology
    console.print()
    console.print("[bold cyan]Phase 4: Network Topology[/bold cyan]")

    from cauldron.graph.topology import build_segment_connectivity

    with console.status("[bold green]Building segment connectivity..."):
        topo_stats = build_segment_connectivity()

    console.print(f"  [green]+[/green] Analyzed {topo_stats['segments_analyzed']} network segments")
    console.print(f"  [green]+[/green] {topo_stats['can_reach_created']} reachability paths between segments")
    if topo_stats["gateway_hosts"]:
        console.print(f"  [green]+[/green] {topo_stats['gateway_hosts']} gateway/router hosts detected")

    # Phase 5: Attack path pivots
    console.print()
    console.print("[bold cyan]Phase 5: Attack Paths[/bold cyan]")

    from cauldron.ai.attack_paths import build_pivot_relationships

    with console.status("[bold green]Building pivot relationships..."):
        pivot_stats = build_pivot_relationships()

    console.print(f"  [green]+[/green] Analyzed {pivot_stats['pairs_analyzed']} host pairs")
    console.print(f"  [green]+[/green] Created {pivot_stats['pivots_created']} pivot relationships")

    # Phase 6: AI Analysis (optional)
    if ai:
        console.print()
        console.print("[bold cyan]Phase 6: AI Analysis[/bold cyan]")

        from cauldron.ai.analyzer import analyze_graph, is_ai_available

        if not is_ai_available():
            console.print("  [yellow]! Skipped: CAULDRON_ANTHROPIC_API_KEY not set[/yellow]")
        else:
            with console.status("[bold green]Running AI analysis (this may take a while)..."):
                ai_result = analyze_graph()

            if ai_result.cves_found:
                console.print(f"  [green]+[/green] AI found {ai_result.cves_found} CVEs across {ai_result.services_enriched} services")
            if ai_result.ambiguous_classified:
                console.print(f"  [green]+[/green] AI re-classified {ai_result.ambiguous_classified} ambiguous hosts")
            if ai_result.pivots_created:
                console.print(f"  [green]+[/green] AI created {ai_result.pivots_created} new pivot relationships")
            if ai_result.insights:
                console.print(f"  [green]+[/green] {len(ai_result.insights)} attack chains discovered:")
                for insight in ai_result.insights[:5]:
                    prio_color = "red" if insight.priority <= 2 else "yellow" if insight.priority <= 3 else "dim"
                    console.print(f"      [{prio_color}]P{insight.priority}[/{prio_color}] {insight.title}")
            if not any([ai_result.cves_found, ai_result.ambiguous_classified, ai_result.pivots_created]):
                console.print("  [dim]  No new findings[/dim]")

            # Rebuild pivots if AI found new CVEs (upgrades shared_segment → exploit/vuln_service)
            if ai_result.cves_found:
                console.print()
                console.print("[bold cyan]Rebuilding pivots with AI findings...[/bold cyan]")
                pivot_stats = build_pivot_relationships()
                console.print(f"  [green]+[/green] Updated {pivot_stats['pivots_created']} pivot relationships")

    console.print()
    console.print("[bold green]Boil complete![/bold green] Run [cyan]cauldron paths[/cyan] to see attack paths.")


@cli.command()
@click.option("--target", "-t", default=None, help="Target IP address")
@click.option("--role", "-r", default=None, help="Target role (e.g. domain_controller)")
@click.option("--top", "-n", default=10, help="Number of paths to show")
def paths(target: str | None, role: str | None, top: int):
    """Show discovered attack paths ranked by exploitability."""
    from cauldron.graph.connection import verify_connection

    if not verify_connection():
        console.print("[bold red]x Cannot connect to Neo4j.[/bold red]")
        raise SystemExit(1)

    from cauldron.ai.attack_paths import discover_attack_paths, get_path_summary

    console.print()

    # Show summary first
    summary = get_path_summary()
    if summary["total_pivots"] == 0:
        console.print("[yellow]No pivot relationships found. Run [cyan]cauldron boil[/cyan] first.[/yellow]")
        return

    console.print("[bold magenta]Attack Path Analysis[/bold magenta]")
    console.print()
    console.print(f"  Pivot relationships: {summary['total_pivots']}", end="")
    if summary["easy_pivots"]:
        console.print(f"  ([red]{summary['easy_pivots']} easy[/red]", end="")
        console.print(f", [yellow]{summary['medium_pivots']} medium[/yellow]", end="")
        console.print(f", [dim]{summary['hard_pivots']} hard[/dim])", end="")
    console.print()

    if summary["high_value_targets"]:
        targets_str = ", ".join(
            f"{ROLE_ICONS.get(r, r)} x{c}"
            for r, c in summary["high_value_targets"].items()
        )
        console.print(f"  High-value targets: {targets_str}")

    console.print()

    # Discover paths
    with console.status("[bold green]Discovering attack paths..."):
        attack_paths = discover_attack_paths(
            target_role=role,
            target_ip=target,
        )

    if not attack_paths:
        console.print("[yellow]No attack paths found to the specified targets.[/yellow]")
        return

    # Only show paths that have real exploits or CVEs — no empty paths
    actionable = [p for p in attack_paths if p.has_exploits or p.max_cvss > 0]
    if not actionable:
        console.print("[yellow]No exploitable attack paths found. Hosts exist but no known vulnerabilities.[/yellow]")
        return
    display_paths = actionable[:top]

    # Display paths with exploit details
    for i, path in enumerate(display_paths, 1):
        # Header line: score + path chain
        path_parts = []
        for node in path.nodes:
            if node.role == "scan_source":
                path_parts.append(f"[dim]{node.ip}[/dim]")
            else:
                icon = ROLE_ICONS.get(node.role, "[dim]?[/dim]")
                label = node.hostname or node.ip
                path_parts.append(f"{icon} {label}")
        path_str = " -> ".join(path_parts)

        score_color = "bold red" if path.score >= 60 else "bold yellow" if path.score >= 40 else "white"
        console.print(f"  [{score_color}]#{i}  Score {path.score:.0f}[/{score_color}]  {path_str}")

        # Details: exploits along the path (skip scan_source)
        for node in path.nodes:
            if node.role == "scan_source" or not node.vulns:
                continue
            icon = ROLE_ICONS.get(node.role, "[dim]?[/dim]")
            for vuln in node.vulns[:3]:  # Top 3 vulns per node
                expl_marker = "[red]EXPLOIT[/red]" if vuln.has_exploit else f"[yellow]CVSS {vuln.cvss:.1f}[/yellow]"
                # Clean title: first sentence, max 60 chars
                title = _truncate_title(vuln.title)
                title_str = f" {title}" if title else ""
                console.print(f"       {icon} {node.ip}  {expl_marker} {vuln.cve_id}{title_str}")

        # Show pivot methods if available
        methods = [m for m in path.pivot_methods if m != "direct"]
        if methods:
            method_str = " -> ".join(methods)
            console.print(f"       [dim]pivot: {method_str}[/dim]")

        console.print()


def _truncate_title(title: str, max_len: int = 60) -> str:
    """Truncate a vulnerability title to a readable length."""
    if not title:
        return ""
    import re
    # Find first real sentence boundary (skip periods in version numbers like "8.7")
    m = re.search(r"(?<!\d)\.(?!\d)", title)
    if m and 10 < m.start() < max_len:
        return title[:m.start()]
    # Try semicolon or comma after a reasonable length
    for sep in (";", ","):
        idx = title.find(sep)
        if 20 < idx < max_len:
            return title[:idx]
    if len(title) > max_len:
        return title[:max_len].rsplit(" ", 1)[0] + "..."
    return title



@cli.command()
def condiments():
    """Show guaranteed exploits per host (quick reference)."""
    from cauldron.graph.connection import verify_connection

    if not verify_connection():
        console.print("[bold red]x Cannot connect to Neo4j.[/bold red]")
        raise SystemExit(1)

    from cauldron.exploits.matcher import ExploitDB

    console.print()
    console.print("[bold magenta]Exploit Database Matches[/bold magenta]")
    console.print()

    exploit_db = ExploitDB()
    reports = exploit_db.get_host_reports()

    if not reports:
        console.print("[yellow]No exploit matches found. Run [cyan]cauldron boil[/cyan] first to import services.[/yellow]")
        return

    total_exploits = sum(len(r.exploits) for r in reports)
    total_easy = sum(r.guaranteed_wins for r in reports)
    total_rce = sum(1 for r in reports if r.has_rce)

    console.print(f"  [bold red]{total_exploits}[/bold red] exploits on [bold]{len(reports)}[/bold] hosts")
    console.print(f"  [bold red]{total_easy}[/bold red] guaranteed wins (easy difficulty)")
    if total_rce:
        console.print(f"  [bold red]{total_rce}[/bold red] hosts with RCE")
    console.print()

    for report in reports:
        host_label = report.ip
        if report.hostname:
            host_label += f" ({report.hostname})"
        if report.os_name:
            host_label += f" [{report.os_name}]"

        console.print(f"  [bold]{host_label}[/bold]")
        for exploit in report.exploits:
            diff_color = "red" if exploit.difficulty == "easy" else "yellow" if exploit.difficulty == "medium" else "dim"
            cve_str = f" {exploit.cve}" if exploit.cve else ""
            module_str = f" | {exploit.module}" if exploit.module else ""
            console.print(
                f"    [{diff_color}]{exploit.difficulty.upper():6s}[/{diff_color}] "
                f"{exploit.title}{cve_str}{module_str}"
            )
        console.print()

    console.print(f"[dim]Database: {exploit_db.size} rules loaded[/dim]")
    console.print()


@cli.command()
@click.option("--format", "fmt", type=click.Choice(["pdf", "html", "json"]), default="html")
def pour(fmt: str):
    """Export a report from the cauldron (coming soon)."""
    console.print(f"[yellow]Report generation ({fmt}) not yet implemented. Coming soon![/yellow]")
