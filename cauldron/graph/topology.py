"""Network segment helpers.

Hosts are bucketed into /24 NetworkSegment nodes at ingest time for visual
grouping in the UI and for the future operator-configurable mask feature.

Reachability between hosts is NOT computed here — SCANNED_FROM is the only
reachability claim Cauldron makes, and it is already recorded directly on
the scan-import path: for every host a ScanSource returned, the scanner
could reach the host (the TCP ACK came back) and the host could reach the
scanner (the ACK came from there). Anything beyond those two directed
edges is unknowable without scanning from the target itself.
"""

from __future__ import annotations

import ipaddress
import logging

from cauldron.graph.connection import get_session

logger = logging.getLogger(__name__)


def _ip_to_segment(ip: str, prefix_len: int | None = None) -> str | None:
    """Convert an IP address to its network segment CIDR.

    Uses configurable prefix length (default from ``settings.segment_prefix_len``).
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


def get_topology_stats() -> dict:
    """Segment-level stats for orientation — list of segments with host counts.

    Segments are a /24 default assumption, not verified network topology, so
    this deliberately does not claim anything about which segment can reach
    which. Consumers that want that view have to scan from an additional
    position.
    """
    with get_session() as session:
        result = session.run(
            """
            MATCH (s:NetworkSegment)
            OPTIONAL MATCH (s)<-[:IN_SEGMENT]-(h:Host)
            WITH s, count(h) AS host_count
            RETURN s.cidr AS segment, host_count
            ORDER BY s.cidr
            """
        )
        segments = [
            {"cidr": record["segment"], "hosts": record["host_count"]}
            for record in result
        ]

        return {"segments": segments}
