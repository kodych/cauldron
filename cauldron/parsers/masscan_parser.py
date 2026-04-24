"""Masscan output parser.

Parses Masscan's XML (-oX) and JSON (-oJ) output formats into Cauldron data models.
Masscan only reports open ports — no version detection, no scripts, no OS detection.
Use nmap for detailed service enumeration after masscan discovery.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from cauldron.graph.models import Host, ScanResult, Service


def parse_masscan(source: str | Path) -> ScanResult:
    """Parse a Masscan output file (XML or JSON) into a ScanResult.

    Auto-detects format based on content.

    Args:
        source: Path to the output file, or raw content string.

    Returns:
        ScanResult with discovered hosts and open ports.

    Raises:
        ValueError: If the file format is not recognized.
    """
    content = _read_content(source)
    stripped = content.strip()

    if stripped.startswith("<?xml") or stripped.startswith("<nmaprun"):
        return _parse_xml(content)
    if stripped.startswith("[") or stripped.startswith("{"):
        return _parse_json(content)

    raise ValueError(
        "Unrecognized Masscan output format. "
        "Expected XML (-oX) or JSON (-oJ) output."
    )


def _read_content(source: str | Path) -> str:
    """Read content from file path or return raw string."""
    if isinstance(source, Path):
        return source.read_text(encoding="utf-8")
    if isinstance(source, str):
        first = source.strip()[:1]
        if first in ("<", "[", "{"):
            return source
        # Could be a file path — check if it exists
        p = Path(source)
        if p.exists():
            return p.read_text(encoding="utf-8")
    return source


def _parse_xml(content: str) -> ScanResult:
    """Parse Masscan XML output.

    Masscan XML mimics nmap XML format but with minimal data:
    - No <service> details (no product, version, banner)
    - No <os> detection
    - No <script> results
    - Only open ports
    """
    root = ET.fromstring(content)

    if root.tag != "nmaprun":
        raise ValueError(f"Expected <nmaprun> root element, got <{root.tag}>")

    scanner_version = root.get("version", "")
    scan_args = root.get("args", "")
    start_time = _parse_timestamp(root.get("start"))

    # Collect ports per IP
    hosts_map: dict[str, Host] = {}

    for host_elem in root.findall("host"):
        # Address: prefer IPv4, fall back to IPv6. Mirrors the nmap
        # parser so masscan XML scans of v6 ranges don't silently lose
        # hosts (the JSON path already accepts v6 via the untyped ``ip``
        # field, so XML-only drops were an asymmetry bug).
        ip = None
        ipv6 = None
        for addr in host_elem.findall("address"):
            addr_type = addr.get("addrtype", "")
            if addr_type == "ipv4":
                ip = addr.get("addr")
            elif addr_type == "ipv6" and ipv6 is None:
                ipv6 = addr.get("addr")
        if ip is None:
            ip = ipv6
        if not ip:
            continue

        # Get or create host
        if ip not in hosts_map:
            hosts_map[ip] = Host(ip=ip, state="up")

        host = hosts_map[ip]

        # Parse ports
        for port_elem in host_elem.findall("ports/port"):
            service = _parse_port_xml(port_elem)
            if service and not _has_port(host, service.port, service.protocol):
                host.services.append(service)

    # End time
    end_time = None
    finished = root.find("runstats/finished")
    if finished is not None:
        end_time = _parse_timestamp(finished.get("time"))

    return ScanResult(
        hosts=list(hosts_map.values()),
        scanner="masscan",
        scanner_version=scanner_version,
        scan_args=scan_args,
        start_time=start_time,
        end_time=end_time,
    )


def _parse_port_xml(elem: ET.Element) -> Service | None:
    """Parse a single <port> element from Masscan XML."""
    state_elem = elem.find("state")
    if state_elem is None:
        return None

    if state_elem.get("state") != "open":
        return None

    port = int(elem.get("portid", "0"))
    protocol = elem.get("protocol", "tcp")

    if port == 0:
        return None

    # Masscan may include a basic <service> with just the name
    name = None
    svc_elem = elem.find("service")
    if svc_elem is not None:
        name = svc_elem.get("name")

    return Service(
        port=port,
        protocol=protocol,
        state="open",
        name=name,
    )


def _parse_json(content: str) -> ScanResult:
    """Parse Masscan JSON output.

    Masscan JSON format is an array of records:
    [
        {"ip": "10.0.0.1", "timestamp": "1234567890", "ports": [
            {"port": 80, "proto": "tcp", "status": "open", "service": {"name": "http"}}
        ]},
        ...
    ]

    Note: Masscan JSON sometimes has trailing comma issues or
    is newline-delimited JSON (one object per line).
    """
    stripped = content.strip()

    # Handle masscan's trailing-comma JSON (common quirk)
    # Remove trailing comma before closing bracket
    import re
    stripped = re.sub(r",\s*\]", "]", stripped)

    # Try standard JSON array first
    try:
        records = json.loads(stripped)
    except json.JSONDecodeError:
        # Try newline-delimited JSON (ndjson)
        records = _parse_ndjson(stripped)

    if not isinstance(records, list):
        raise ValueError("Expected JSON array of scan records")

    hosts_map: dict[str, Host] = {}

    for record in records:
        if not isinstance(record, dict):
            continue

        ip = record.get("ip")
        if not ip:
            continue

        if ip not in hosts_map:
            hosts_map[ip] = Host(ip=ip, state="up")

        host = hosts_map[ip]

        for port_data in record.get("ports", []):
            service = _parse_port_json(port_data)
            if service and not _has_port(host, service.port, service.protocol):
                host.services.append(service)

    return ScanResult(
        hosts=list(hosts_map.values()),
        scanner="masscan",
    )


def _parse_port_json(data: dict) -> Service | None:
    """Parse a single port record from Masscan JSON."""
    status = data.get("status", data.get("state", ""))
    if status != "open":
        return None

    port = data.get("port", 0)
    if not port:
        return None

    protocol = data.get("proto", "tcp")
    name = None

    svc = data.get("service", {})
    if isinstance(svc, dict):
        name = svc.get("name")

    return Service(
        port=port,
        protocol=protocol,
        state="open",
        name=name,
    )


def _parse_ndjson(content: str) -> list[dict]:
    """Parse newline-delimited JSON."""
    records = []
    for line in content.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in ("[]", "[", "]"):
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def _has_port(host: Host, port: int, protocol: str) -> bool:
    """Check if host already has this port/protocol."""
    return any(s.port == port and s.protocol == protocol for s in host.services)


def _parse_timestamp(value: str | None) -> datetime | None:
    """Parse Unix timestamp string to datetime."""
    if not value:
        return None
    try:
        return datetime.fromtimestamp(int(value))
    except (ValueError, OSError):
        return None
