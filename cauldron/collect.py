"""Collect targets from the graph — BloodHound-style target lists.

Provides filter-based queries for extracting IPs/host:port pairs
ready to pipe into pentesting tools (netexec, nuclei, nmap, etc).
"""

from __future__ import annotations

from dataclasses import dataclass

from cauldron.graph.connection import get_session

# Built-in filters: name → description, cypher WHERE clause, default port
BUILTIN_FILTERS: dict[str, dict] = {
    "smb": {
        "description": "SMB/CIFS hosts (port 445)",
        "match_service": True,
        "where": "s.port = 445",
        "port": 445,
    },
    "rdp": {
        "description": "Remote Desktop hosts (port 3389)",
        "match_service": True,
        "where": "s.port = 3389",
        "port": 3389,
    },
    "ssh": {
        "description": "SSH hosts (port 22)",
        "match_service": True,
        "where": "s.port = 22",
        "port": 22,
    },
    "ftp": {
        "description": "FTP hosts (port 21)",
        "match_service": True,
        "where": "s.port = 21",
        "port": 21,
    },
    "http": {
        "description": "HTTP/HTTPS hosts (ports 80, 443, 8080, 8443)",
        "match_service": True,
        "where": "s.port IN [80, 443, 8080, 8443]",
    },
    "mssql": {
        "description": "Microsoft SQL Server (port 1433)",
        "match_service": True,
        "where": "s.port = 1433",
        "port": 1433,
    },
    "mysql": {
        "description": "MySQL/MariaDB (port 3306)",
        "match_service": True,
        "where": "s.port = 3306",
        "port": 3306,
    },
    "postgres": {
        "description": "PostgreSQL (port 5432)",
        "match_service": True,
        "where": "s.port = 5432",
        "port": 5432,
    },
    "dns": {
        "description": "DNS servers (port 53)",
        "match_service": True,
        "where": "s.port = 53",
        "port": 53,
    },
    "smtp": {
        "description": "SMTP mail servers (port 25, 587)",
        "match_service": True,
        "where": "s.port IN [25, 587]",
    },
    "ldap": {
        "description": "LDAP/AD hosts (port 389, 636)",
        "match_service": True,
        "where": "s.port IN [389, 636]",
    },
    "snmp": {
        "description": "SNMP hosts (port 161)",
        "match_service": True,
        "where": "s.port = 161",
        "port": 161,
    },
    "vnc": {
        "description": "VNC hosts (port 5900-5910)",
        "match_service": True,
        "where": "s.port >= 5900 AND s.port <= 5910",
        "port": 5900,
    },
    "telnet": {
        "description": "Telnet hosts (port 23)",
        "match_service": True,
        "where": "s.port = 23",
        "port": 23,
    },
    "kerberos": {
        "description": "Kerberos hosts — likely DCs (port 88)",
        "match_service": True,
        "where": "s.port = 88",
        "port": 88,
    },
    "winrm": {
        "description": "WinRM hosts (port 5985, 5986)",
        "match_service": True,
        "where": "s.port IN [5985, 5986]",
    },
    "vuln": {
        "description": "All hosts with any vulnerability",
        "match_vuln": True,
        "where": None,
    },
    "exploitable": {
        "description": "Hosts with confirmed/likely exploits",
        "match_vuln": True,
        "where": "rel.confidence IN ['confirmed', 'likely']",
    },
    "rce": {
        "description": "Hosts with RCE vulnerabilities (enables_pivot = true)",
        "match_vuln": True,
        "where": "v.enables_pivot = true",
    },
    "kev": {
        "description": "Hosts with CISA Known Exploited Vulnerabilities (actively exploited in the wild)",
        "match_vuln": True,
        "where": "coalesce(v.in_cisa_kev, false) = true",
    },
    "owned": {
        "description": "Hosts marked as owned (we have shell/access)",
        "where": "coalesce(h.owned, false) = true",
    },
    "target": {
        "description": "Hosts marked as target (engagement goals)",
        "where": "coalesce(h.target, false) = true",
    },
    "target-blocked": {
        "description": "Target hosts with no actionable vulnerability — engagement blockers",
        "where": (
            "coalesce(h.target, false) = true AND NOT EXISTS { "
            "MATCH (h)-[:HAS_SERVICE]->(:Service)-[r:HAS_VULN]->(:Vulnerability) "
            "WHERE r.checked_status IS NULL OR r.checked_status <> 'false_positive' "
            "}"
        ),
    },
    "dc": {
        "description": "Domain Controllers",
        "where": "h.role = 'domain_controller'",
    },
    "db": {
        "description": "Database servers",
        "where": "h.role = 'database'",
    },
    "brute": {
        "description": "Bruteforceable services (SSH, RDP, SMB, databases, etc.)",
        "match_service": True,
        "where": "(s.bruteforceable = true OR s.bruteforceable_manual = true)",
        "per_service": True,  # return one entry per socket, not per host
    },
}


@dataclass
class CollectResult:
    """Result of a collect query."""

    hosts: list[HostEntry]
    filter_used: str
    total: int


@dataclass
class HostEntry:
    """A single host entry from collect."""

    ip: str
    hostname: str | None = None
    port: int | None = None
    role: str | None = None


def collect_targets(
    *,
    filter_name: str | None = None,
    port: int | None = None,
    role: str | None = None,
    source: str | None = None,
) -> CollectResult:
    """Query the graph for targets matching the given criteria.

    Args:
        filter_name: Built-in filter name (e.g. 'smb', 'rdp', 'vuln').
        port: Custom port filter.
        role: Filter by host role.
        source: Only hosts visible from this scan source.

    Returns:
        CollectResult with matching hosts.
    """
    if filter_name and filter_name not in BUILTIN_FILTERS:
        available = ", ".join(sorted(BUILTIN_FILTERS.keys()))
        raise ValueError(f"Unknown filter '{filter_name}'. Available: {available}")

    if port is not None and not (1 <= port <= 65535):
        raise ValueError(f"Invalid port: {port}. Must be 1-65535")

    # Build query from parts
    match_clauses = ["MATCH (h:Host)"]
    where_clauses: list[str] = []
    params: dict = {}
    default_port: int | None = None

    if filter_name:
        filt = BUILTIN_FILTERS[filter_name]
        default_port = filt.get("port")
        if filt.get("match_vuln"):
            # Bind the HAS_VULN relationship as ``rel`` so per-edge filters
            # (confidence, checked_status) work without accidentally reading
            # node-scoped confidence from the shared Vulnerability.
            match_clauses.append("MATCH (h)-[:HAS_SERVICE]->(:Service)-[rel:HAS_VULN]->(v:Vulnerability)")
            # Every vuln-based filter auto-excludes operator-dismissed
            # findings. Enforced here, once, so a future new vuln filter
            # can't silently re-introduce the "FP-marked vulns still come
            # back from --filter exploitable" bug.
            where_clauses.append(
                "(rel.checked_status IS NULL OR rel.checked_status <> 'false_positive')",
            )
        elif filt.get("match_service"):
            match_clauses.append("MATCH (h)-[:HAS_SERVICE]->(s:Service)")
        if filt.get("where"):
            where_clauses.append(filt["where"])
    elif port:
        match_clauses.append("MATCH (h)-[:HAS_SERVICE]->(s:Service)")
        where_clauses.append("s.port = $port")
        params["port"] = port
        default_port = port
    elif role:
        where_clauses.append("h.role = $role")
        params["role"] = role

    # Source filter: only hosts scanned from this source
    if source:
        match_clauses.append("MATCH (src:ScanSource)-[:SCANNED_FROM]->(h)")
        where_clauses.append("src.name = $source")
        params["source"] = source

    # Assemble
    match_str = "\n".join(match_clauses)
    where_str = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

    # per_service mode: return one entry per (host, port) instead of per host
    per_service = filter_name and BUILTIN_FILTERS.get(filter_name, {}).get("per_service")

    if per_service:
        query = f"""
            {match_str}
            {where_str}
            WITH DISTINCT h, s
            RETURN h.ip AS ip, h.hostname AS hostname, h.role AS role, s.port AS port
            ORDER BY h.ip, s.port
        """
    else:
        query = f"""
            {match_str}
            {where_str}
            WITH DISTINCT h
            RETURN h.ip AS ip, h.hostname AS hostname, h.role AS role
            ORDER BY h.ip
        """

    with get_session() as session:
        result = session.run(query, params)
        hosts = []
        for record in result:
            entry = HostEntry(
                ip=record["ip"],
                hostname=record.get("hostname"),
                port=record.get("port") if per_service else default_port,
                role=record.get("role"),
            )
            hosts.append(entry)

    label = filter_name or (f"port:{port}" if port else (f"role:{role}" if role else "all"))
    if source:
        label += f"@{source}"
    return CollectResult(hosts=hosts, filter_used=label, total=len(hosts))


def list_filters() -> list[dict]:
    """Return available built-in filters with descriptions."""
    return [
        {"name": name, "description": info["description"]}
        for name, info in sorted(BUILTIN_FILTERS.items())
    ]
