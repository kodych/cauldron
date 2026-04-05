"""Cauldron CLI commands.

Themed after brewing potions:
  brew       — import scan files (throw ingredients in)
  boil       — run analysis (classify, exploit DB, CVE, topology, paths)
  taste      — view graph statistics
  paths      — show attack paths with exploit details
  collect    — extract target lists for pentesting tools
  condiments — quick reference: guaranteed exploits per host
  serve      — start REST API server
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
    "management": "[bold cyan]MGMT[/bold cyan]",
    "unknown": "[dim]?[/dim]",
}


@click.group()
@click.version_option(version="0.1.0", prog_name="cauldron")
def cli():
    """Cauldron -- Network Attack Path Discovery."""
    pass


def _parse_scan_file(file: Path, fmt: str = "auto") -> "ScanResult":  # noqa: F821
    """Parse a scan file, auto-detecting format if needed."""
    from cauldron.parsers.nmap_parser import parse_nmap_xml
    from cauldron.parsers.masscan_parser import parse_masscan

    if fmt == "nmap":
        return parse_nmap_xml(file)
    if fmt == "masscan":
        return parse_masscan(file)

    # Auto-detect: read first bytes
    content = file.read_text(encoding="utf-8", errors="ignore")[:2000]
    stripped = content.strip()

    # JSON → masscan
    if stripped.startswith("[") or stripped.startswith("{"):
        return parse_masscan(file)

    # XML — check scanner attribute
    if 'scanner="masscan"' in stripped:
        return parse_masscan(file)

    # Default: nmap XML
    return parse_nmap_xml(file)


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--source", "-s", default=None, help="Scan source name/IP (where was scan run from)")
@click.option("--format", "fmt", type=click.Choice(["auto", "nmap", "masscan"]), default="auto",
              help="Scan file format (default: auto-detect)")
def brew(file: Path, source: str | None, fmt: str):
    """Import scan results into the cauldron.

    FILE is the path to an Nmap XML (-oX) or Masscan (-oX/-oJ) output file.
    Format is auto-detected from file content.
    """
    console.print(BANNER)

    # Auto-detect scan source from filename if not provided
    if not source:
        source = file.stem

    console.print(f"[bold cyan]Brewing:[/bold cyan] {file.name}")
    console.print(f"[dim]  Source: {source}[/dim]")
    console.print()

    # Parse — auto-detect or use explicit format
    with console.status("[bold green]Parsing scan file..."):
        try:
            scan = _parse_scan_file(file, fmt)
        except Exception as e:
            console.print(f"[bold red]x Failed to parse:[/bold red] {e}")
            raise SystemExit(1)

    scanner_label = f" ({scan.scanner})" if scan.scanner != "nmap" else ""

    console.print(f"  [green]+[/green] Parsed {len(scan.hosts_up)} live hosts, {scan.total_services} services{scanner_label}")

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
@click.option("--nvd", is_flag=True, default=False, help="Enable NVD CVE enrichment (network API, may take minutes)")
@click.option("--ai", is_flag=True, default=False, help="Enable AI analysis (requires CAULDRON_ANTHROPIC_API_KEY)")
@click.option("--all", "run_all", is_flag=True, default=False, help="Enable all enrichments (--nvd --ai)")
def boil(nvd: bool, ai: bool, run_all: bool):
    """Run analysis on the graph -- classify hosts, enrich data.

    By default runs only local analysis (exploit DB, topology, attack paths).
    Use --nvd for NVD CVE enrichment, --ai for AI analysis, or --all for both.
    """
    from cauldron.graph.connection import verify_connection
    from cauldron.graph.ingestion import classify_graph_hosts

    if run_all:
        nvd = ai = True

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

    # Phase 2.5: Script-based confidence upgrade
    from cauldron.exploits.matcher import upgrade_confidence_from_scripts

    with console.status("[bold green]Checking nmap scripts for confirmed vulnerabilities..."):
        script_stats = upgrade_confidence_from_scripts()

    if script_stats["upgrades"] or script_stats["new_vulns"]:
        console.print(
            f"  [green]+[/green] Scripts: {script_stats['upgrades']} confidence upgrades, "
            f"{script_stats['new_vulns']} new confirmed findings"
        )

    # Phase 2.7: Bruteforceable service detection
    from cauldron.exploits.matcher import mark_bruteforceable_services

    with console.status("[bold green]Detecting bruteforceable services..."):
        brute_stats = mark_bruteforceable_services()

    if brute_stats["marked"]:
        console.print(
            f"  [green]+[/green] {brute_stats['marked']} bruteforceable services detected"
        )

    # Phase 3: CVE enrichment (NVD API) — optional
    console.print()
    console.print("[bold cyan]Phase 3: CVE Enrichment (NVD API)[/bold cyan]")

    if nvd:
        from cauldron.ai.cve_enricher import enrich_services_from_graph

        with console.status("[bold green]Enriching services with CVE data (this may take a while)..."):
            cve_stats = enrich_services_from_graph()

        console.print(f"  [green]+[/green] Checked {cve_stats['services_checked']} product+version pairs")
        console.print(f"  [green]+[/green] Found {cve_stats['total_cves_found']} CVEs across {cve_stats['services_with_cves']} services")
        if cve_stats["from_cache"]:
            console.print(f"  [dim]  ({cve_stats['from_cache']} from cache, {cve_stats['api_calls']} API calls)[/dim]")
        if cve_stats["errors"]:
            console.print(f"  [yellow]  ! {cve_stats['errors']} errors during enrichment[/yellow]")
    else:
        console.print("  [dim]Skipped (use --nvd to enable)[/dim]")

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

    # Phase 5: Attack path discovery
    console.print()
    console.print("[bold cyan]Phase 5: Attack Paths[/bold cyan]")

    from cauldron.ai.attack_paths import get_path_summary

    summary = get_path_summary()
    console.print(f"  [green]+[/green] {summary['vulnerable_hosts']} vulnerable hosts found")
    if summary["with_exploits"]:
        console.print(f"  [bold red]![/bold red] {summary['with_exploits']} hosts with known exploits")
    if summary["pivot_hosts"]:
        console.print(f"  [green]+[/green] {summary['pivot_hosts']} true pivot hosts detected (multi-scan)")

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
            if ai_result.insights:
                console.print(f"  [green]+[/green] {len(ai_result.insights)} attack insights discovered:")
                for insight in ai_result.insights[:5]:
                    prio_color = "red" if insight.priority <= 2 else "yellow" if insight.priority <= 3 else "dim"
                    console.print(f"      [{prio_color}]P{insight.priority}[/{prio_color}] {insight.title}")
            if ai_result.false_positives_found:
                console.print(f"  [green]+[/green] Marked {ai_result.false_positives_found} CVEs as AI-detected false positives")
            if not any([ai_result.cves_found, ai_result.ambiguous_classified, ai_result.insights, ai_result.false_positives_found]):
                console.print("  [dim]  No new findings[/dim]")

            # AI CVEs are immediately available for path discovery
            if ai_result.cves_found:
                console.print("  [dim]  AI CVEs added — will appear in attack paths[/dim]")

    console.print()
    console.print("[bold green]Boil complete![/bold green] Run [cyan]cauldron paths[/cyan] to see attack paths.")


@cli.command()
@click.option("--target", "-t", default=None, help="Target IP address")
@click.option("--role", "-r", default=None, help="Target role (e.g. domain_controller)")
@click.option("--top", "-n", default=10, help="Number of paths to show")
@click.option("--all", "show_all", is_flag=True, default=False, help="Include check-level paths (default: confirmed/likely only)")
def paths(target: str | None, role: str | None, top: int, show_all: bool):
    """Show discovered attack paths ranked by exploitability."""
    from cauldron.graph.connection import verify_connection

    if not verify_connection():
        console.print("[bold red]x Cannot connect to Neo4j.[/bold red]")
        raise SystemExit(1)

    from cauldron.ai.attack_paths import discover_attack_paths, get_path_summary

    console.print()

    # Show summary first
    summary = get_path_summary()
    if summary["vulnerable_hosts"] == 0:
        console.print("[yellow]No vulnerable hosts found. Run [cyan]cauldron boil[/cyan] first.[/yellow]")
        return

    console.print("[bold magenta]Attack Path Analysis[/bold magenta]")
    console.print()
    console.print(f"  Vulnerable hosts: {summary['vulnerable_hosts']}", end="")
    if summary["with_exploits"]:
        console.print(f"  ([red]{summary['with_exploits']} with exploits[/red]", end="")
        if summary["confirmed"]:
            console.print(f", [bold]{summary['confirmed']} confirmed[/bold]", end="")
        console.print(")", end="")
    console.print()

    if summary["high_value_targets"]:
        targets_str = ", ".join(
            f"{ROLE_ICONS.get(r, r)} x{c}"
            for r, c in summary["high_value_targets"].items()
        )
        console.print(f"  High-value targets: {targets_str}")

    if summary["pivot_hosts"]:
        console.print(f"  [bold green]Pivot hosts: {summary['pivot_hosts']}[/bold green] (bridge external/internal scans)")

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

    # Default: only confirmed/likely paths. --all includes check-level too
    if not show_all:
        confirmed_likely = [p for p in actionable if p.max_confidence in ("confirmed", "likely")]
        check_only = [p for p in actionable if p.max_confidence == "check"]
        display_paths = confirmed_likely[:top]
        hidden_check = len(check_only)
    else:
        display_paths = actionable[:top]
        hidden_check = 0

    if not display_paths and not show_all:
        # No confirmed/likely but there are check paths
        console.print("[yellow]No confirmed/likely attack paths found.[/yellow]")
        if hidden_check:
            console.print(f"[dim]  {hidden_check} check-level paths available. Use --all to see them.[/dim]")
        return

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
                # Label: EXPLOIT for confirmed/likely, CHECK for check
                if vuln.confidence == "check":
                    expl_marker = "[dim]CHECK[/dim]"
                elif vuln.has_exploit:
                    expl_marker = "[red]EXPLOIT[/red]"
                else:
                    expl_marker = f"[yellow]CVSS {vuln.cvss:.1f}[/yellow]"
                # Clean title: first sentence, max 60 chars
                title = _truncate_title(vuln.title)
                title_str = f" {title}" if title else ""
                console.print(f"       {icon} {node.ip}  {expl_marker} {vuln.cve_id}{title_str}")

        # Show attack methods
        methods = path.attack_methods
        if methods:
            method_labels = {
                "exploit": "[red]exploit[/red]",
                "relay": "[yellow]relay[/yellow]",
                "credential": "[yellow]credential[/yellow]",
                "cve": "[dim]CVE[/dim]",
                "pivot": "[bold green]pivot[/bold green]",
                "direct": "[dim]direct[/dim]",
            }
            method_str = " + ".join(method_labels.get(m, m) for m in methods)
            console.print(f"       method: {method_str}")

        console.print()

    # Show hint about hidden check paths
    if hidden_check and not show_all:
        console.print(f"[dim]  + {hidden_check} check-level paths hidden. Use --all to see them.[/dim]")
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
@click.option("--filter", "-f", "filter_name", default=None, help="Built-in filter (smb, rdp, ssh, vuln, etc.)")
@click.option("--port", "-p", default=None, type=int, help="Custom port filter")
@click.option("--role", "-r", default=None, help="Filter by host role (e.g. domain_controller, database)")
@click.option("--source", "-s", default=None, help="Only hosts visible from this scan source")
@click.option("--format", "fmt", type=click.Choice(["ip", "ip:port", "csv"]), default="ip", help="Output format")
@click.option("--output", "-o", default=None, type=click.Path(), help="Write to file instead of stdout")
@click.option("--list", "list_filters", is_flag=True, default=False, help="List available built-in filters")
def collect(filter_name: str | None, port: int | None, role: str | None,
            source: str | None, fmt: str, output: str | None, list_filters: bool):
    """Collect target lists — pipe to netexec, nuclei, nmap.

    \b
    Examples:
      cauldron collect --filter smb                    # All SMB hosts
      cauldron collect --filter smb --format ip:port   # IP:445 format
      cauldron collect --filter vuln                   # All vulnerable hosts
      cauldron collect --filter exploitable            # Confirmed/likely only
      cauldron collect --port 8080                     # Custom port
      cauldron collect --role database                 # By role
      cauldron collect --filter smb -o targets.txt     # Save to file
      cauldron collect --filter smb -s scanner1        # From specific scan source
      cauldron collect --list                          # Show available filters
    """
    from cauldron.collect import collect_targets, list_filters as get_filters

    if list_filters:
        console.print()
        console.print("[bold magenta]Available Collect Filters[/bold magenta]")
        console.print()
        table = Table(show_header=True, box=None, padding=(0, 2))
        table.add_column("Filter", style="cyan")
        table.add_column("Description", style="white")
        for f in get_filters():
            table.add_row(f["name"], f["description"])
        console.print(table)
        console.print()
        return

    if not filter_name and not port and not role:
        console.print("[yellow]Specify --filter, --port, or --role. Use --list to see available filters.[/yellow]")
        return

    from cauldron.graph.connection import verify_connection

    if not verify_connection():
        console.print("[bold red]x Cannot connect to Neo4j.[/bold red]")
        raise SystemExit(1)

    try:
        result = collect_targets(
            filter_name=filter_name,
            port=port,
            role=role,
            source=source,
        )
    except ValueError as e:
        console.print(f"[bold red]x {e}[/bold red]")
        raise SystemExit(1)

    if not result.hosts:
        console.print(f"[yellow]No hosts found for filter '{result.filter_used}'.[/yellow]")
        return

    # Format output lines
    lines = []
    for host in result.hosts:
        if fmt == "ip:port" and host.port:
            lines.append(f"{host.ip}:{host.port}")
        elif fmt == "csv":
            hostname = host.hostname or ""
            role_str = host.role or ""
            lines.append(f"{host.ip},{hostname},{role_str}")
        else:
            lines.append(host.ip)

    # Output
    if output:
        with open(output, "w") as f:
            f.write("\n".join(lines) + "\n")
        console.print(f"[green]+[/green] {result.total} hosts written to {output}")
    else:
        # Print to stdout (raw, no Rich formatting — pipeable)
        for line in lines:
            click.echo(line)

    # Summary to stderr (so pipe still works)
    if not output:
        import sys
        print(f"# {result.total} hosts ({result.filter_used})", file=sys.stderr)


@cli.command()
@click.option("--host", "-h", default="0.0.0.0", help="Bind address")
@click.option("--port", "-p", default=8000, type=int, help="Port number")
@click.option("--reload", is_flag=True, default=False, help="Auto-reload on code changes")
def serve(host: str, port: int, reload: bool):
    """Start the REST API server."""
    console.print(BANNER)
    console.print(f"[bold cyan]Starting API server on {host}:{port}[/bold cyan]")
    console.print(f"[dim]  Docs: http://{host if host != '0.0.0.0' else 'localhost'}:{port}/docs[/dim]")
    console.print()

    import uvicorn

    uvicorn.run(
        "cauldron.api.server:app",
        host=host,
        port=port,
        reload=reload,
    )


@cli.command()
@click.option("--format", "fmt", type=click.Choice(["md", "json", "html"]), default="md",
              help="Report format (default: markdown)")
@click.option("-o", "--output", default=None, type=click.Path(), help="Output file (default: stdout)")
@click.option("--top", default=20, help="Number of top findings to include")
def pour(fmt: str, output: str | None, top: int):
    """Export scan report from the cauldron."""
    from cauldron.graph.connection import verify_connection

    if not verify_connection():
        console.print("[bold red]x Cannot connect to Neo4j.[/bold red]")
        raise SystemExit(1)

    with console.status("[bold green]Generating report..."):
        from cauldron.report import generate_markdown, generate_json, generate_html

        if fmt == "json":
            content = generate_json(top=top)
        elif fmt == "html":
            content = generate_html(top=top)
        else:
            content = generate_markdown(top=top)

    if output:
        Path(output).write_text(content, encoding="utf-8")
        console.print(f"[green]+[/green] Report saved to [cyan]{output}[/cyan]")
    else:
        console.print(content)
