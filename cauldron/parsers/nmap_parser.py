"""Nmap XML output parser.

Parses Nmap's XML output format (-oX) into Cauldron data models.
Handles various Nmap versions and output quirks defensively.
"""

from __future__ import annotations

import re
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

    # OS detection. Two sources, ranked by quality:
    #
    # 1. ``<os><osmatch><osclass>`` — the structured classification from
    #    ``nmap -O``. ``osfamily`` is an enumerated value (Windows /
    #    Linux / IOS / embedded / Mac OS X / BSD), so we don't have to
    #    parse the free-form ``osmatch.name`` string for family detection.
    #    ``vendor`` / ``osgen`` give the supplementary "Microsoft / 11"
    #    breakdown the UI uses for the role badge.
    # 2. ``<service ostype="Windows">`` — set by ``-sV`` when a service
    #    banner reveals the host OS (msrpc on Windows, ssh on Cisco IOS).
    #    Fallback for scans without ``-O``.
    osmatch_elem = elem.find("os/osmatch")
    if osmatch_elem is not None:
        host.os_name = osmatch_elem.get("name")
        try:
            host.os_accuracy = int(osmatch_elem.get("accuracy", "0"))
        except (ValueError, TypeError):
            host.os_accuracy = None
        osclass_elem = osmatch_elem.find("osclass")
        if osclass_elem is not None:
            host.os_family = osclass_elem.get("osfamily") or None
            host.os_vendor = osclass_elem.get("vendor") or None
            host.os_gen = osclass_elem.get("osgen") or None

    # Ports & Services
    for port_elem in elem.findall("ports/port"):
        service = _parse_port(port_elem)
        if service is not None:
            host.services.append(service)

    # Service-ostype fallback — only fills os_family when -O didn't run.
    # First non-empty ``ostype`` from any service wins; the value is
    # already canonical (``Windows`` / ``IOS`` / ``Linux``) so we use it
    # as-is. Doesn't override an already-set ``os_family`` from osclass.
    if not host.os_family:
        for svc_elem in elem.findall("ports/port/service"):
            ostype = svc_elem.get("ostype")
            if ostype:
                host.os_family = ostype
                break

    # ``smb-os-discovery`` overrides the ``<osmatch>`` fingerprint guess.
    # The NSE script queries the SMB protocol directly and returns the OS
    # string the target reports about itself, which is more reliable than
    # nmap's TCP/IP-stack fingerprint — particularly for Windows, where
    # Win 7 SP1 and Server 2012 R2 share an NT 6.1 signature and routinely
    # get transposed in the osmatch ranking (the "Server 2012" mis-id on
    # Win 7 SP1 boxes is the classic case). The CPE the script returns
    # (e.g. ``cpe:/o:microsoft:windows_7::sp1:professional``) is also
    # propagated to the SMB service so the CVE enricher gets a versioned
    # CPE for MS17-010 / BlueKeep / etc. instead of the versionless
    # ``cpe:/o:microsoft:windows`` that nmap attaches by default.
    smb_os_elem = elem.find("hostscript/script[@id='smb-os-discovery']")
    if smb_os_elem is not None:
        smb_os_name: str | None = None
        smb_os_cpe: str | None = None
        for sub in smb_os_elem.findall("elem"):
            key = sub.get("key")
            if key == "os" and sub.text:
                smb_os_name = sub.text.strip()
            elif key == "cpe" and sub.text:
                smb_os_cpe = sub.text.strip()
        if smb_os_name:
            host.os_name = smb_os_name
            # smb-os-discovery is protocol-level truth, not a guess.
            host.os_accuracy = 100
            # The OS string is "Windows ..." for every Microsoft target
            # (Samba targets are rare and surface a different shape we
            # don't try to canonicalise here).
            if re.search(r"\bWindows\b", smb_os_name, re.IGNORECASE):
                host.os_family = "Windows"
                host.os_vendor = "Microsoft"
                # Re-derive the structured generation marker so role
                # rules and exploit-rule ``os_hint`` matchers see the
                # same enumerated value they'd get from an ``osclass``
                # element ("7", "10", "2012", "XP", ...).
                gen_match = re.search(
                    r"Windows\s+(?:Server\s+)?(\d+(?:\.\d+)?|XP|Vista|NT|ME|2000)",
                    smb_os_name, re.IGNORECASE,
                )
                if gen_match:
                    host.os_gen = gen_match.group(1)
        if smb_os_cpe:
            # Attach the OS CPE to SMB-stack services (139 netbios-ssn,
            # 445 microsoft-ds). These are the surfaces where OS-level
            # CVEs (MS17-010, MS08-067, SMBGhost) are exploited, so the
            # enricher needs a versioned CPE on those edges. Other ports
            # on the same host are intentionally skipped — pushing the
            # OS CPE to every port would produce N copies of every
            # OS-attributed CVE (one per service), which the UI/CLI
            # dedupe later anyway but at the cost of N× writes.
            for s in host.services:
                if s.port in (139, 445) and smb_os_cpe not in s.cpe:
                    s.cpe.append(smb_os_cpe)

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
