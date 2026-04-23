"""Import parsed scan results into Neo4j graph database.

Key design principle: MERGE, don't CREATE.
Re-importing the same scan updates existing nodes rather than creating duplicates.
New scans from different sources enrich the graph incrementally.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime

from neo4j import Session

from cauldron.graph.connection import get_session, init_schema
from cauldron.graph.models import Host, ScanResult, Service
from cauldron.graph.topology import _ip_to_segment


def ingest_scan(scan: ScanResult, source_name: str | None = None) -> dict:
    """Import a complete scan result into Neo4j.

    Args:
        scan: Parsed scan result.
        source_name: Name/IP of the scan source (where scan was run from).

    Returns:
        Dict with import statistics.
    """
    init_schema()

    stats = {
        "hosts_imported": 0,
        "hosts_skipped": 0,
        "services_imported": 0,
        "segments_created": 0,
        "relationships_created": 0,
    }

    source = source_name or scan.scan_source or "unknown"
    # Always use wall-clock time for import timestamps so that
    # re-importing the same (or modified) scan file produces distinct
    # first_seen / last_seen values, enabling scan-diff detection.
    timestamp = datetime.now()
    seen_segments: set[str] = set()

    with get_session() as session:
        # Create or update scan source
        _upsert_scan_source(session, source, timestamp, scan.scan_args)

        for host in scan.hosts_up:
            if not host.ip:
                stats["hosts_skipped"] += 1
                continue

            # Upsert host
            _upsert_host(session, host, timestamp)
            stats["hosts_imported"] += 1

            # Link scan source to host
            _link_scan_source(session, source, host.ip)
            stats["relationships_created"] += 1

            # Determine network segment and link
            segment = _ip_to_segment(host.ip)
            if segment:
                _upsert_segment(session, segment)
                _link_host_to_segment(session, host.ip, segment)
                if segment not in seen_segments:
                    seen_segments.add(segment)
                    stats["segments_created"] += 1

            # Upsert services and their scripts
            for service in host.services:
                if service.state in ("open", "filtered"):
                    _upsert_service(session, host.ip, service, timestamp)
                    stats["services_imported"] += 1
                    # Store script results on the service node
                    for script in service.scripts:
                        _upsert_script_result(session, host.ip, service.port, service.protocol, script)

            # Host-level script results (stored on Host node)
            for script in host.host_scripts:
                _upsert_host_script(session, host.ip, script)

            # Traceroute relationships
            for hop in host.traceroute:
                if hop.ip and hop.ip != host.ip:
                    _upsert_traceroute_hop(session, host.ip, hop.ip, hop.ttl)
                    stats["relationships_created"] += 1

    return stats


def _upsert_scan_source(session: Session, name: str, timestamp: datetime, args: str | None) -> None:
    """Create or update a scan source node."""
    session.run(
        """
        MERGE (s:ScanSource {name: $name})
        ON CREATE SET s.first_seen = $ts, s.last_seen = $ts, s.scan_args = $args
        ON MATCH SET s.last_seen = $ts
        """,
        name=name,
        ts=timestamp.isoformat(),
        args=args,
    )


def _upsert_host(session: Session, host: Host, timestamp: datetime) -> None:
    """Create or update a host node."""
    session.run(
        """
        MERGE (h:Host {ip: $ip})
        ON CREATE SET
            h.first_seen = $ts,
            h.last_seen = $ts,
            h.hostname = $hostname,
            h.os_name = $os_name,
            h.os_accuracy = $os_accuracy,
            h.mac = $mac,
            h.mac_vendor = $mac_vendor,
            h.state = $state,
            h.role = $role,
            h.role_confidence = $role_confidence,
            h.owned = false,
            h.target = false
        ON MATCH SET
            h.last_seen = $ts,
            h.state = $state,
            h.hostname = COALESCE($hostname, h.hostname),
            h.os_name = COALESCE($os_name, h.os_name),
            h.os_accuracy = CASE WHEN $os_accuracy > COALESCE(h.os_accuracy, 0) THEN $os_accuracy ELSE h.os_accuracy END,
            h.mac = COALESCE($mac, h.mac),
            h.mac_vendor = COALESCE($mac_vendor, h.mac_vendor)
        """,
        ip=host.ip,
        ts=timestamp.isoformat(),
        hostname=host.hostname,
        os_name=host.os_name,
        os_accuracy=host.os_accuracy,
        mac=host.mac,
        mac_vendor=host.mac_vendor,
        state=host.state,
        role=host.role.value,
        role_confidence=host.role_confidence,
    )


def _link_scan_source(session: Session, source_name: str, host_ip: str) -> None:
    """Create SCANNED_FROM relationship."""
    session.run(
        """
        MATCH (s:ScanSource {name: $source})
        MATCH (h:Host {ip: $ip})
        MERGE (s)-[:SCANNED_FROM]->(h)
        """,
        source=source_name,
        ip=host_ip,
    )


def _upsert_segment(session: Session, cidr: str) -> None:
    """Create or update a network segment."""
    session.run(
        """
        MERGE (s:NetworkSegment {cidr: $cidr})
        """,
        cidr=cidr,
    )


def _link_host_to_segment(session: Session, host_ip: str, segment_cidr: str) -> None:
    """Link host to its network segment."""
    session.run(
        """
        MATCH (h:Host {ip: $ip})
        MATCH (s:NetworkSegment {cidr: $cidr})
        MERGE (h)-[:IN_SEGMENT]->(s)
        """,
        ip=host_ip,
        cidr=segment_cidr,
    )


def _upsert_service(session: Session, host_ip: str, service: Service, timestamp: datetime | None = None) -> None:
    """Create or update a service node linked to a host.

    Services are identified by host_ip + port + protocol combination.
    """
    # Store CPE as semicolon-joined string (Neo4j doesn't have list properties in community)
    cpe_str = ";".join(service.cpe) if service.cpe else None
    ts = timestamp.isoformat() if timestamp else datetime.now().isoformat()

    session.run(
        """
        MATCH (h:Host {ip: $ip})
        MERGE (svc:Service {host_ip: $ip, port: $port, protocol: $protocol})
        ON CREATE SET
            svc.first_seen = $ts,
            svc.last_seen = $ts,
            svc.state = $state,
            svc.name = $name,
            svc.product = $product,
            svc.version = $version,
            svc.extra_info = $extra_info,
            svc.banner = $banner,
            svc.servicefp = $servicefp,
            svc.cpe = $cpe
        ON MATCH SET
            svc.last_seen = $ts,
            svc.state = $state,
            svc.name = COALESCE($name, svc.name),
            svc.product = COALESCE($product, svc.product),
            svc.version = COALESCE($version, svc.version),
            svc.extra_info = COALESCE($extra_info, svc.extra_info),
            svc.servicefp = COALESCE($servicefp, svc.servicefp),
            svc.cpe = COALESCE($cpe, svc.cpe)
        MERGE (h)-[:HAS_SERVICE]->(svc)
        """,
        ip=host_ip,
        ts=ts,
        port=service.port,
        protocol=service.protocol,
        state=service.state,
        name=service.name,
        product=service.product,
        version=service.version,
        extra_info=service.extra_info,
        banner=service.banner,
        servicefp=service.servicefp,
        cpe=cpe_str,
    )


def _upsert_script_result(
    session: Session, host_ip: str, port: int, protocol: str, script
) -> None:
    """Store nmap script result as a property on the Service node.

    Scripts are stored as a JSON-like string list in svc.scripts property,
    and key scripts (vuln confirmations) are stored as individual properties.
    """
    from cauldron.graph.models import ScriptResult

    if not isinstance(script, ScriptResult):
        return

    # Store script output as property: script_<id> = output
    # Sanitize script_id: only allow alphanumeric and underscores
    import re
    safe_id = re.sub(r"[^a-zA-Z0-9_]", "_", script.script_id)[:100]
    prop_name = f"script_{safe_id}"
    session.run(
        f"""
        MATCH (svc:Service {{host_ip: $ip, port: $port, protocol: $protocol}})
        SET svc.`{prop_name}` = $output
        """,
        ip=host_ip,
        port=port,
        protocol=protocol,
        output=script.output[:2000],  # Limit output size
    )


def _upsert_host_script(session: Session, host_ip: str, script) -> None:
    """Store host-level nmap script result as a property on the Host node.

    Host-level scripts (from <hostscript>) apply to the host as a whole,
    not to any specific service. Examples: smb2-security-mode, smb-os-discovery.
    """
    from cauldron.graph.models import ScriptResult

    if not isinstance(script, ScriptResult):
        return

    import re
    safe_id = re.sub(r"[^a-zA-Z0-9_]", "_", script.script_id)[:100]
    prop_name = f"script_{safe_id}"
    session.run(
        f"""
        MATCH (h:Host {{ip: $ip}})
        SET h.`{prop_name}` = $output
        """,
        ip=host_ip,
        output=script.output[:2000],
    )


def _upsert_traceroute_hop(session: Session, target_ip: str, hop_ip: str, ttl: int) -> None:
    """Create ROUTE_THROUGH relationship from traceroute data."""
    # Validate hop IP before creating Host node
    try:
        ipaddress.ip_address(hop_ip)
    except (ValueError, TypeError):
        return  # Skip invalid IPs from traceroute

    # First ensure the hop host exists
    session.run(
        """
        MERGE (h:Host {ip: $ip})
        ON CREATE SET h.state = 'up', h.role = 'unknown', h.role_confidence = 0.0
        """,
        ip=hop_ip,
    )
    session.run(
        """
        MATCH (target:Host {ip: $target_ip})
        MATCH (hop:Host {ip: $hop_ip})
        MERGE (target)-[r:ROUTE_THROUGH]->(hop)
        SET r.ttl = $ttl
        """,
        target_ip=target_ip,
        hop_ip=hop_ip,
        ttl=ttl,
    )


def get_graph_stats() -> dict:
    """Get statistics about the current graph."""
    with get_session() as session:
        result = session.run(
            """
            MATCH (h:Host) WITH count(h) as hosts
            OPTIONAL MATCH (s:Service) WITH hosts, count(s) as services
            OPTIONAL MATCH (seg:NetworkSegment) WITH hosts, services, count(seg) as segments
            OPTIONAL MATCH ()-[r:HAS_VULN]->(v:Vulnerability)
            WITH hosts, services, segments, r, v
            WITH hosts, services, segments,
                 count(DISTINCT CASE WHEN r.checked_status IS NULL OR r.checked_status <> 'false_positive' THEN v END) as vulns,
                 sum(CASE WHEN v IS NOT NULL AND (r.checked_status IS NULL OR r.checked_status <> 'false_positive') THEN 1 ELSE 0 END) as findings
            OPTIONAL MATCH (src:ScanSource) WITH hosts, services, segments, vulns, findings, count(src) as sources
            RETURN hosts, services, segments, vulns, findings, sources
            """
        )
        record = result.single()
        if record is None:
            return {"hosts": 0, "services": 0, "segments": 0, "vulnerabilities": 0, "findings": 0, "scan_sources": 0}

        return {
            "hosts": record["hosts"],
            "services": record["services"],
            "segments": record["segments"],
            "vulnerabilities": record["vulns"],
            "findings": record["findings"],
            "scan_sources": record["sources"],
        }


def get_host_role_distribution() -> dict[str, int]:
    """Get count of hosts per role."""
    with get_session() as session:
        result = session.run(
            """
            MATCH (h:Host)
            RETURN h.role AS role, count(h) AS count
            ORDER BY count DESC
            """
        )
        return {record["role"]: record["count"] for record in result}


def classify_graph_hosts() -> dict:
    """Classify all hosts in the graph using rule-based classifier.

    Reads hosts and their services from Neo4j, runs the classifier,
    and updates the role/role_confidence properties.

    Returns:
        Dict with classification stats.
    """
    from cauldron.ai.classifier import classify_host
    from cauldron.graph.models import Host as HostModel
    from cauldron.graph.models import Service as ServiceModel

    stats: dict = {"total": 0, "classified": 0, "roles": {}}

    with get_session() as session:
        # Fetch all hosts with their services
        result = session.run(
            """
            MATCH (h:Host)
            OPTIONAL MATCH (h)-[:HAS_SERVICE]->(s:Service)
            RETURN h.ip AS ip, h.hostname AS hostname,
                   collect({port: s.port, protocol: s.protocol,
                           state: s.state, name: s.name,
                           product: s.product, version: s.version}) AS services
            """
        )

        for record in result:
            stats["total"] += 1
            ip = record["ip"]

            # Build Host model from Neo4j data
            services = []
            for svc_data in record["services"]:
                if svc_data.get("port") is not None:
                    services.append(ServiceModel(
                        port=svc_data["port"],
                        protocol=svc_data.get("protocol", "tcp"),
                        state=svc_data.get("state", "open"),
                        name=svc_data.get("name"),
                        product=svc_data.get("product"),
                        version=svc_data.get("version"),
                    ))

            host = HostModel(ip=ip, hostname=record.get("hostname"), services=services)
            classification = classify_host(host)

            # Update Neo4j
            session.run(
                """
                MATCH (h:Host {ip: $ip})
                SET h.role = $role, h.role_confidence = $confidence
                """,
                ip=ip,
                role=classification.role.value,
                confidence=classification.confidence,
            )

            if classification.role.value != "unknown":
                stats["classified"] += 1
                role_name = classification.role.value
                stats["roles"][role_name] = stats["roles"].get(role_name, 0) + 1

            # Auto-target domain controllers
            if classification.role.value == "domain_controller":
                session.run(
                    "MATCH (h:Host {ip: $ip}) WHERE h.target <> true SET h.target = true",
                    ip=ip,
                )

    return stats


def set_host_owned(ip: str, owned: bool) -> bool:
    """Mark a host as owned (compromised) or unmark it.

    When marking as owned, target is automatically cleared — goal achieved.
    """
    with get_session() as session:
        if owned:
            result = session.run(
                "MATCH (h:Host {ip: $ip}) SET h.owned = true, h.target = false RETURN h.ip",
                ip=ip,
            )
        else:
            result = session.run(
                "MATCH (h:Host {ip: $ip}) SET h.owned = false RETURN h.ip",
                ip=ip,
            )
        return result.single() is not None


def set_host_target(ip: str, target: bool) -> bool:
    """Mark a host as target (engagement goal) or unmark it."""
    with get_session() as session:
        result = session.run(
            "MATCH (h:Host {ip: $ip}) SET h.target = $target RETURN h.ip",
            ip=ip, target=target,
        )
        return result.single() is not None
