"""Nmap XML output parser.

Parses Nmap's XML output format (-oX) into Cauldron data models.
Handles various Nmap versions and output quirks defensively.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from cauldron.graph.models import Host, ScanResult, ScriptResult, Service, TracerouteHop


def parse_nmap_xml(source: str | Path) -> ScanResult:
    """Parse an Nmap XML file into a ScanResult.

    Args:
        source: Path to the XML file, or raw XML string.

    Returns:
        ScanResult with all parsed hosts and metadata.

    Raises:
        ValueError: If the file is not valid Nmap XML.
    """
    if isinstance(source, Path) or (isinstance(source, str) and not source.strip().startswith("<")):
        tree = ET.parse(source)
        root = tree.getroot()
    else:
        root = ET.fromstring(source)

    if root.tag != "nmaprun":
        raise ValueError(f"Not an Nmap XML file: root element is <{root.tag}>, expected <nmaprun>")

    result = ScanResult(
        scanner="nmap",
        scanner_version=root.get("version"),
        scan_args=root.get("args"),
        start_time=_parse_timestamp(root.get("start")),
    )

    # Parse end time from <runstats>
    runstats = root.find("runstats/finished")
    if runstats is not None:
        result.end_time = _parse_timestamp(runstats.get("time"))

    # Parse each host
    for host_elem in root.findall("host"):
        host = _parse_host(host_elem)
        if host is not None:
            result.hosts.append(host)

    return result


def _parse_host(elem: ET.Element) -> Host | None:
    """Parse a single <host> element."""
    # Status
    status_elem = elem.find("status")
    state = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

    # Address (IPv4 preferred, fallback to IPv6)
    ip = None
    mac = None
    mac_vendor = None
    for addr_elem in elem.findall("address"):
        addr_type = addr_elem.get("addrtype", "")
        if addr_type == "ipv4":
            ip = addr_elem.get("addr")
        elif addr_type == "ipv6" and ip is None:
            ip = addr_elem.get("addr")
        elif addr_type == "mac":
            mac = addr_elem.get("addr")
            mac_vendor = addr_elem.get("vendor")

    if ip is None:
        return None

    host = Host(
        ip=ip,
        state=state,
        mac=mac,
        mac_vendor=mac_vendor,
    )

    # Hostname
    hostname_elem = elem.find("hostnames/hostname[@type='user']")
    if hostname_elem is None:
        hostname_elem = elem.find("hostnames/hostname[@type='PTR']")
    if hostname_elem is None:
        hostname_elem = elem.find("hostnames/hostname")
    if hostname_elem is not None:
        host.hostname = hostname_elem.get("name")

    # OS detection
    osmatch_elem = elem.find("os/osmatch")
    if osmatch_elem is not None:
        host.os_name = osmatch_elem.get("name")
        try:
            host.os_accuracy = int(osmatch_elem.get("accuracy", "0"))
        except (ValueError, TypeError):
            host.os_accuracy = None

    # Ports & Services
    for port_elem in elem.findall("ports/port"):
        service = _parse_port(port_elem)
        if service is not None:
            host.services.append(service)

    # Traceroute
    for hop_elem in elem.findall("trace/hop"):
        hop = _parse_traceroute_hop(hop_elem)
        if hop is not None:
            host.traceroute.append(hop)

    # Host-level scripts (<hostscript>)
    for script_elem in elem.findall("hostscript/script"):
        host.host_scripts.append(ScriptResult(
            script_id=script_elem.get("id", "unknown"),
            output=script_elem.get("output", ""),
        ))

    return host


def _parse_port(elem: ET.Element) -> Service | None:
    """Parse a single <port> element."""
    try:
        port_num = int(elem.get("portid", "0"))
    except (ValueError, TypeError):
        return None

    protocol = elem.get("protocol", "tcp")

    state_elem = elem.find("state")
    state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

    # Skip closed ports — they just add noise
    if state == "closed":
        return None

    service = Service(
        port=port_num,
        protocol=protocol,
        state=state,
    )

    # Service info
    svc_elem = elem.find("service")
    if svc_elem is not None:
        service.name = svc_elem.get("name")
        service.product = svc_elem.get("product")
        service.version = svc_elem.get("version")
        service.extra_info = svc_elem.get("extrainfo")
        # Preserve the raw service fingerprint — nmap emits it only when its
        # signatures couldn't identify the product, so it carries the richest
        # hints we'll get without re-probing (cookies, Server: headers,
        # characteristic HTML error pages).
        service.servicefp = svc_elem.get("servicefp")

        # Build banner from tunnel/servicefp if available
        tunnel = svc_elem.get("tunnel")
        if tunnel:
            service.banner = f"tunnel:{tunnel}"

        # CPE URIs (nmap's built-in CPE detection)
        for cpe_elem in svc_elem.findall("cpe"):
            if cpe_elem.text:
                service.cpe.append(cpe_elem.text)

    # NSE script results
    for script_elem in elem.findall("script"):
        script = ScriptResult(
            script_id=script_elem.get("id", "unknown"),
            output=script_elem.get("output", ""),
        )
        service.scripts.append(script)

    return service


def _parse_traceroute_hop(elem: ET.Element) -> TracerouteHop | None:
    """Parse a single <hop> element from traceroute."""
    try:
        ttl = int(elem.get("ttl", "0"))
    except (ValueError, TypeError):
        return None

    rtt = None
    rtt_str = elem.get("rtt")
    if rtt_str:
        try:
            rtt = float(rtt_str)
        except (ValueError, TypeError):
            pass

    return TracerouteHop(
        ttl=ttl,
        ip=elem.get("ipaddr"),
        hostname=elem.get("host"),
        rtt=rtt,
    )


def _parse_timestamp(value: str | None) -> datetime | None:
    """Parse a Unix timestamp string into datetime."""
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(value))
    except (ValueError, TypeError, OSError):
        return None
