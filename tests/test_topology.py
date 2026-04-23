"""Tests for network segment helpers."""

from __future__ import annotations

import pytest

from cauldron.graph.connection import clear_database, get_session, verify_connection
from cauldron.graph.topology import _ip_to_segment, get_topology_stats


class TestIpToSegment:
    def test_valid_ip(self):
        assert _ip_to_segment("10.0.1.10") == "10.0.1.0/24"

    def test_network_boundary(self):
        assert _ip_to_segment("192.168.0.1") == "192.168.0.0/24"

    def test_custom_prefix(self):
        assert _ip_to_segment("10.0.1.10", prefix_len=16) == "10.0.0.0/16"

    def test_invalid_ip(self):
        assert _ip_to_segment("not-an-ip") is None

    def test_hostname_returns_none(self):
        assert _ip_to_segment("server.local") is None


@pytest.mark.skipif(not verify_connection(), reason="Neo4j not available")
class TestGetTopologyStats:
    @pytest.fixture(autouse=True)
    def clean_db(self):
        clear_database()
        yield
        clear_database()

    def test_empty_graph(self):
        stats = get_topology_stats()
        assert stats == {"segments": []}

    def test_reports_hosts_per_segment(self):
        with get_session() as session:
            session.run("CREATE (:NetworkSegment {cidr: '10.0.1.0/24'})")
            session.run("CREATE (:NetworkSegment {cidr: '10.0.2.0/24'})")
            for ip, cidr in (
                ("10.0.1.10", "10.0.1.0/24"),
                ("10.0.1.20", "10.0.1.0/24"),
                ("10.0.2.5", "10.0.2.0/24"),
            ):
                session.run(
                    """
                    CREATE (h:Host {ip: $ip, state: 'up'})
                    WITH h
                    MATCH (s:NetworkSegment {cidr: $cidr})
                    CREATE (h)-[:IN_SEGMENT]->(s)
                    """,
                    ip=ip, cidr=cidr,
                )

        stats = get_topology_stats()
        by_cidr = {s["cidr"]: s["hosts"] for s in stats["segments"]}
        assert by_cidr == {"10.0.1.0/24": 2, "10.0.2.0/24": 1}
