"""Network topology analysis.

Builds segment connectivity (CAN_REACH) from traceroute data,
analyzes reachability from scan sources, and provides topology statistics.
"""

from __future__ import annotations

import ipaddress
import logging

from cauldron.graph.connection import get_session

logger = logging.getLogger(__name__)


def build_segment_connectivity() -> dict:
    """Build CAN_REACH relationships between network segments.

    Analyzes ROUTE_THROUGH (traceroute) data and IN_SEGMENT membership
    to determine which segments can reach which other segments.

    Logic:
    - For each scan source, find all hosts it scanned (SCANNED_FROM).
    - The scan source can reach every segment containing a scanned host.
    - Traceroute hops reveal intermediate segments in the path.
    - Adjacent segments in a traceroute path get CAN_REACH edges.

    Returns:
        Dict with topology build statistics.
    """
    stats = {
        "can_reach_created": 0,
        "segments_analyzed": 0,
        "gateway_hosts": 0,
    }

    with get_session() as session:
        # Step 1: Find all traceroute paths.
        # Each path is: target host has ROUTE_THROUGH to intermediate hops.
        # Hops have TTL indicating order.
        # We need: scan_source_segment -> hop_segments -> target_segment
        result = session.run(
            """
            MATCH (target:Host)-[rt:ROUTE_THROUGH]->(hop:Host)
            OPTIONAL MATCH (target)-[:IN_SEGMENT]->(ts:NetworkSegment)
            OPTIONAL MATCH (hop)-[:IN_SEGMENT]->(hs:NetworkSegment)
            RETURN target.ip AS target_ip,
                   ts.cidr AS target_segment,
                   hop.ip AS hop_ip,
                   hs.cidr AS hop_segment,
                   rt.ttl AS ttl
            ORDER BY target.ip, rt.ttl
            """
        )

        # Group traceroute paths by target
        paths: dict[str, list[dict]] = {}
        for record in result:
            target_ip = record["target_ip"]
            if target_ip not in paths:
                paths[target_ip] = []
            paths[target_ip].append({
                "hop_ip": record["hop_ip"],
                "hop_segment": record["hop_segment"],
                "target_segment": record["target_segment"],
                "ttl": record["ttl"],
            })

        # Step 2: For each path, create CAN_REACH between consecutive segments.
        # Also ensure hop hosts are in their segments.
        segment_pairs: set[tuple[str, str]] = set()

        for target_ip, hops in paths.items():
            # Sort by TTL to get ordered path
            hops.sort(key=lambda h: h["ttl"] or 0)
            target_segment = hops[0]["target_segment"] if hops else None

            # Build segment chain: [hop1_seg, hop2_seg, ..., target_seg]
            seg_chain: list[str] = []
            for hop in hops:
                hop_seg = hop["hop_segment"]
                if hop_seg and (not seg_chain or seg_chain[-1] != hop_seg):
                    seg_chain.append(hop_seg)

            if target_segment and (not seg_chain or seg_chain[-1] != target_segment):
                seg_chain.append(target_segment)

            # Create CAN_REACH for consecutive segment pairs
            for i in range(len(seg_chain) - 1):
                src_seg = seg_chain[i]
                dst_seg = seg_chain[i + 1]
                if src_seg != dst_seg:
                    segment_pairs.add((src_seg, dst_seg))

        # Step 3: Also create CAN_REACH based on scan source reachability.
        # If a scan source scanned hosts in segments A and B, and the scan
        # source is in segment S, then S can reach both A and B.
        source_result = session.run(
            """
            MATCH (src:ScanSource)-[:SCANNED_FROM]->(h:Host)-[:IN_SEGMENT]->(seg:NetworkSegment)
            RETURN src.name AS source, collect(DISTINCT seg.cidr) AS segments
            """
        )

        for record in source_result:
            source_name = record["source"]
            segments = record["segments"]

            # Try to determine scan source segment from its name/IP
            source_segment = _ip_to_segment(source_name)

            if source_segment and len(segments) > 0:
                # Ensure the scan source segment node exists
                session.run(
                    "MERGE (:NetworkSegment {cidr: $cidr})",
                    cidr=source_segment,
                )
                for seg in segments:
                    if seg != source_segment:
                        segment_pairs.add((source_segment, seg))

            # Also: all scanned segments can reach each other
            # (the scanner proved connectivity between them)
            for i, seg_a in enumerate(segments):
                for seg_b in segments[i + 1:]:
                    if seg_a != seg_b:
                        segment_pairs.add((seg_a, seg_b))
                        segment_pairs.add((seg_b, seg_a))

        # Step 4: Write CAN_REACH relationships
        for src_seg, dst_seg in segment_pairs:
            result = session.run(
                """
                MATCH (s1:NetworkSegment {cidr: $src})
                MATCH (s2:NetworkSegment {cidr: $dst})
                MERGE (s1)-[:CAN_REACH]->(s2)
                RETURN s1.cidr AS src
                """,
                src=src_seg,
                dst=dst_seg,
            )
            if result.single():
                stats["can_reach_created"] += 1

        # Step 5: Ensure traceroute hop hosts have segments
        _ensure_hop_segments(session)
        stats["gateway_hosts"] = _count_gateway_hosts(session)

        # Count analyzed segments
        seg_count = session.run(
            "MATCH (s:NetworkSegment) RETURN count(s) AS cnt"
        ).single()
        stats["segments_analyzed"] = seg_count["cnt"] if seg_count else 0

    return stats


def _ensure_hop_segments(session) -> None:
    """Ensure traceroute hop hosts are linked to their /24 segments."""
    result = session.run(
        """
        MATCH (h:Host)
        WHERE NOT (h)-[:IN_SEGMENT]->(:NetworkSegment)
        RETURN h.ip AS ip
        """
    )

    for record in result:
        ip = record["ip"]
        segment = _ip_to_segment(ip)
        if segment:
            session.run(
                "MERGE (s:NetworkSegment {cidr: $cidr})",
                cidr=segment,
            )
            session.run(
                """
                MATCH (h:Host {ip: $ip})
                MATCH (s:NetworkSegment {cidr: $cidr})
                MERGE (h)-[:IN_SEGMENT]->(s)
                """,
                ip=ip,
                cidr=segment,
            )


def _count_gateway_hosts(session) -> int:
    """Count hosts that appear as traceroute hops (gateway/router role)."""
    result = session.run(
        """
        MATCH (h:Host)<-[:ROUTE_THROUGH]-()
        RETURN count(DISTINCT h) AS cnt
        """
    )
    record = result.single()
    return record["cnt"] if record else 0


def _ip_to_segment(ip: str, prefix_len: int | None = None) -> str | None:
    """Convert an IP address to its network segment CIDR.

    Uses configurable prefix length (default from settings.segment_prefix_len).
    """
    if prefix_len is None:
        from cauldron.config import settings
        prefix_len = settings.segment_prefix_len
    try:
        addr = ipaddress.ip_address(ip)
        network = ipaddress.ip_network(f"{addr}/{prefix_len}", strict=False)
        return str(network)
    except ValueError:
        return None


def get_reachability_from(source_ip: str) -> list[dict]:
    """Analyze network reachability from a given source IP.

    Returns a list of reachable segments with path information.

    Args:
        source_ip: IP address of the source (e.g., scan source).

    Returns:
        List of dicts with segment, hop_count, and path details.
    """
    source_segment = _ip_to_segment(source_ip)
    if not source_segment:
        return []

    reachable = []

    with get_session() as session:
        # Direct: segments reachable via CAN_REACH (1 hop)
        result = session.run(
            """
            MATCH (s1:NetworkSegment {cidr: $src})-[:CAN_REACH]->(s2:NetworkSegment)
            OPTIONAL MATCH (s2)<-[:IN_SEGMENT]-(h:Host)
            RETURN s2.cidr AS segment,
                   1 AS hops,
                   count(h) AS host_count
            """,
            src=source_segment,
        )

        for record in result:
            reachable.append({
                "segment": record["segment"],
                "hops": record["hops"],
                "host_count": record["host_count"],
            })

        # Transitive: segments reachable via CAN_REACH chains (2+ hops)
        result = session.run(
            """
            MATCH path = (s1:NetworkSegment {cidr: $src})-[:CAN_REACH*2..4]->(s2:NetworkSegment)
            WHERE s1 <> s2
            WITH s2, min(length(path)) AS min_hops
            OPTIONAL MATCH (s2)<-[:IN_SEGMENT]-(h:Host)
            RETURN s2.cidr AS segment,
                   min_hops AS hops,
                   count(h) AS host_count
            """,
            src=source_segment,
        )

        seen = {r["segment"] for r in reachable}
        for record in result:
            seg = record["segment"]
            if seg not in seen:
                reachable.append({
                    "segment": seg,
                    "hops": record["hops"],
                    "host_count": record["host_count"],
                })
                seen.add(seg)

    reachable.sort(key=lambda r: (r["hops"], r["segment"]))
    return reachable


def get_topology_stats() -> dict:
    """Get topology statistics for display.

    Returns:
        Dict with segment connectivity stats.
    """
    with get_session() as session:
        result = session.run(
            """
            MATCH (s:NetworkSegment)
            OPTIONAL MATCH (s)<-[:IN_SEGMENT]-(h:Host)
            WITH s, count(h) AS host_count
            OPTIONAL MATCH (s)-[:CAN_REACH]->(s2:NetworkSegment)
            RETURN s.cidr AS segment,
                   host_count,
                   count(s2) AS reaches
            ORDER BY s.cidr
            """
        )

        segments = []
        for record in result:
            segments.append({
                "cidr": record["segment"],
                "hosts": record["host_count"],
                "reaches": record["reaches"],
            })

        # Count gateway hosts (appear in traceroute hops)
        gw_result = session.run(
            """
            MATCH (h:Host)<-[:ROUTE_THROUGH]-()
            RETURN count(DISTINCT h) AS gateways
            """
        )
        gw_record = gw_result.single()
        gateways = gw_record["gateways"] if gw_record else 0

        # Count total CAN_REACH edges
        reach_result = session.run(
            """
            MATCH ()-[r:CAN_REACH]->()
            RETURN count(r) AS total_reach
            """
        )
        reach_record = reach_result.single()
        total_reach = reach_record["total_reach"] if reach_record else 0

        return {
            "segments": segments,
            "gateways": gateways,
            "total_reach_edges": total_reach,
        }
