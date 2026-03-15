"""Tests for network topology analysis."""

from __future__ import annotations

import pytest

from cauldron.graph.connection import clear_database, get_session, verify_connection
from cauldron.graph.topology import (
    _ip_to_segment,
    build_segment_connectivity,
    get_reachability_from,
    get_topology_stats,
)

pytestmark = pytest.mark.skipif(
    not verify_connection(),
    reason="Neo4j not available",
)


@pytest.fixture(autouse=True)
def clean_db():
    """Clear database before and after each test."""
    clear_database()
    yield
    clear_database()


def _setup_basic_network():
    """Create a basic multi-segment network in Neo4j.

    Topology:
        ScanSource("attacker") --SCANNED_FROM--> hosts in 10.0.1.0/24 and 10.0.2.0/24

        Segments: 10.0.0.0/24 (gateway), 10.0.1.0/24 (servers), 10.0.2.0/24 (DMZ)

        Traceroute to DC01 (10.0.1.10): attacker -> 10.0.0.1 (gw) -> 10.0.1.10
        Traceroute to WEB01 (10.0.2.20): attacker -> 10.0.0.1 (gw) -> 10.0.2.1 (sw) -> 10.0.2.20
    """
    with get_session() as session:
        # Create scan source
        session.run("CREATE (:ScanSource {name: '192.168.1.100'})")

        # Create hosts
        session.run("""
            CREATE (:Host {ip: '10.0.0.1', state: 'up', role: 'network_equipment', role_confidence: 0.9})
        """)
        session.run("""
            CREATE (:Host {ip: '10.0.1.10', state: 'up', role: 'domain_controller', role_confidence: 0.95})
        """)
        session.run("""
            CREATE (:Host {ip: '10.0.1.30', state: 'up', role: 'database', role_confidence: 0.9})
        """)
        session.run("""
            CREATE (:Host {ip: '10.0.2.1', state: 'up', role: 'network_equipment', role_confidence: 0.8})
        """)
        session.run("""
            CREATE (:Host {ip: '10.0.2.20', state: 'up', role: 'web_server', role_confidence: 0.85})
        """)
        session.run("""
            CREATE (:Host {ip: '10.0.2.40', state: 'up', role: 'mail_server', role_confidence: 0.8})
        """)

        # Create segments
        for cidr in ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"]:
            session.run("CREATE (:NetworkSegment {cidr: $cidr})", cidr=cidr)

        # Link hosts to segments
        for ip, cidr in [
            ("10.0.0.1", "10.0.0.0/24"),
            ("10.0.1.10", "10.0.1.0/24"),
            ("10.0.1.30", "10.0.1.0/24"),
            ("10.0.2.1", "10.0.2.0/24"),
            ("10.0.2.20", "10.0.2.0/24"),
            ("10.0.2.40", "10.0.2.0/24"),
        ]:
            session.run(
                """
                MATCH (h:Host {ip: $ip}), (s:NetworkSegment {cidr: $cidr})
                CREATE (h)-[:IN_SEGMENT]->(s)
                """,
                ip=ip, cidr=cidr,
            )

        # Link scan source to scanned hosts
        for ip in ["10.0.1.10", "10.0.1.30", "10.0.2.20", "10.0.2.40"]:
            session.run(
                """
                MATCH (src:ScanSource {name: '192.168.1.100'}), (h:Host {ip: $ip})
                CREATE (src)-[:SCANNED_FROM]->(h)
                """,
                ip=ip,
            )

        # Traceroute: DC01 path (target -> hops)
        session.run("""
            MATCH (target:Host {ip: '10.0.1.10'}), (hop:Host {ip: '10.0.0.1'})
            CREATE (target)-[:ROUTE_THROUGH {ttl: 1}]->(hop)
        """)

        # Traceroute: DB01 path
        session.run("""
            MATCH (target:Host {ip: '10.0.1.30'}), (hop:Host {ip: '10.0.0.1'})
            CREATE (target)-[:ROUTE_THROUGH {ttl: 1}]->(hop)
        """)

        # Traceroute: WEB01 path (2 hops)
        session.run("""
            MATCH (target:Host {ip: '10.0.2.20'}), (hop:Host {ip: '10.0.0.1'})
            CREATE (target)-[:ROUTE_THROUGH {ttl: 1}]->(hop)
        """)
        session.run("""
            MATCH (target:Host {ip: '10.0.2.20'}), (hop:Host {ip: '10.0.2.1'})
            CREATE (target)-[:ROUTE_THROUGH {ttl: 2}]->(hop)
        """)

        # Traceroute: MAIL01 path (2 hops)
        session.run("""
            MATCH (target:Host {ip: '10.0.2.40'}), (hop:Host {ip: '10.0.0.1'})
            CREATE (target)-[:ROUTE_THROUGH {ttl: 1}]->(hop)
        """)
        session.run("""
            MATCH (target:Host {ip: '10.0.2.40'}), (hop:Host {ip: '10.0.2.1'})
            CREATE (target)-[:ROUTE_THROUGH {ttl: 2}]->(hop)
        """)


class TestIpToSegment:
    def test_valid_ip(self):
        assert _ip_to_segment("10.0.1.10") == "10.0.1.0/24"

    def test_network_boundary(self):
        assert _ip_to_segment("192.168.0.1") == "192.168.0.0/24"

    def test_invalid_ip(self):
        assert _ip_to_segment("not-an-ip") is None

    def test_hostname_returns_none(self):
        assert _ip_to_segment("server.local") is None


class TestBuildSegmentConnectivity:
    def test_creates_can_reach_from_traceroute(self):
        _setup_basic_network()
        stats = build_segment_connectivity()

        assert stats["can_reach_created"] > 0
        # 3 original segments + scan source segment (192.168.1.0/24)
        assert stats["segments_analyzed"] >= 3

        # Verify CAN_REACH edges exist
        with get_session() as session:
            result = session.run(
                """
                MATCH (s1:NetworkSegment)-[:CAN_REACH]->(s2:NetworkSegment)
                RETURN s1.cidr AS src, s2.cidr AS dst
                ORDER BY s1.cidr, s2.cidr
                """
            )
            edges = [(r["src"], r["dst"]) for r in result]

        # Gateway segment (10.0.0.0/24) should reach server segment (10.0.1.0/24)
        assert ("10.0.0.0/24", "10.0.1.0/24") in edges
        # Gateway segment should reach DMZ (10.0.2.0/24)
        assert ("10.0.0.0/24", "10.0.2.0/24") in edges

    def test_gateway_hosts_detected(self):
        _setup_basic_network()
        stats = build_segment_connectivity()

        # 10.0.0.1 and 10.0.2.1 are gateways (appear in ROUTE_THROUGH)
        assert stats["gateway_hosts"] >= 2

    def test_empty_graph(self):
        stats = build_segment_connectivity()
        assert stats["can_reach_created"] == 0
        assert stats["segments_analyzed"] == 0

    def test_idempotent(self):
        """Running build twice should not duplicate CAN_REACH edges."""
        _setup_basic_network()
        build_segment_connectivity()

        with get_session() as session:
            result = session.run(
                "MATCH ()-[r:CAN_REACH]->() RETURN count(r) AS cnt"
            )
            count_after_first = result.single()["cnt"]

        build_segment_connectivity()

        with get_session() as session:
            result = session.run(
                "MATCH ()-[r:CAN_REACH]->() RETURN count(r) AS cnt"
            )
            count_after_second = result.single()["cnt"]

        # MERGE prevents duplicates — count should be identical
        assert count_after_first == count_after_second

    def test_scan_source_reachability(self):
        """Scan source segment should have CAN_REACH to scanned segments."""
        _setup_basic_network()

        # Also create segment for scan source
        with get_session() as session:
            session.run("CREATE (:NetworkSegment {cidr: '192.168.1.0/24'})")

        build_segment_connectivity()

        with get_session() as session:
            result = session.run(
                """
                MATCH (s1:NetworkSegment {cidr: '192.168.1.0/24'})-[:CAN_REACH]->(s2:NetworkSegment)
                RETURN collect(s2.cidr) AS reachable
                """
            )
            reachable = result.single()["reachable"]

        # Scan source at 192.168.1.100 scanned hosts in 10.0.1.0/24 and 10.0.2.0/24
        assert "10.0.1.0/24" in reachable
        assert "10.0.2.0/24" in reachable


class TestEnsureHopSegments:
    def test_hop_hosts_get_segments(self):
        """Hosts created from traceroute should get IN_SEGMENT links."""
        with get_session() as session:
            # Create a host without segment (like a traceroute hop)
            session.run(
                "CREATE (:Host {ip: '10.5.0.1', state: 'up', role: 'unknown', role_confidence: 0.0})"
            )

        build_segment_connectivity()

        with get_session() as session:
            result = session.run(
                """
                MATCH (h:Host {ip: '10.5.0.1'})-[:IN_SEGMENT]->(s:NetworkSegment)
                RETURN s.cidr AS cidr
                """
            )
            record = result.single()

        assert record is not None
        assert record["cidr"] == "10.5.0.0/24"


class TestGetReachabilityFrom:
    def test_reachable_segments(self):
        _setup_basic_network()
        build_segment_connectivity()

        reachable = get_reachability_from("10.0.0.1")

        segments = [r["segment"] for r in reachable]
        # From gateway segment, should reach server and DMZ segments
        assert "10.0.1.0/24" in segments
        assert "10.0.2.0/24" in segments

    def test_invalid_source(self):
        result = get_reachability_from("not-an-ip")
        assert result == []

    def test_unreachable_returns_empty(self):
        _setup_basic_network()
        build_segment_connectivity()

        # From an isolated segment
        result = get_reachability_from("172.16.0.1")
        assert result == []


class TestGetTopologyStats:
    def test_stats_with_data(self):
        _setup_basic_network()
        build_segment_connectivity()

        topo = get_topology_stats()
        # 3 original segments + scan source segment (192.168.1.0/24)
        assert len(topo["segments"]) >= 3
        assert topo["gateways"] >= 2
        assert topo["total_reach_edges"] > 0

        # Check segment details
        seg_map = {s["cidr"]: s for s in topo["segments"]}
        assert seg_map["10.0.1.0/24"]["hosts"] == 2  # DC01 + DB01
        assert seg_map["10.0.2.0/24"]["hosts"] == 3  # sw + WEB01 + MAIL01

    def test_stats_empty_graph(self):
        topo = get_topology_stats()
        assert topo["segments"] == []
        assert topo["gateways"] == 0
        assert topo["total_reach_edges"] == 0


class TestTopologyWithCorporateData:
    """Integration test using the corporate_network.xml test data."""

    def test_full_topology_pipeline(self):
        from pathlib import Path

        from cauldron.graph.ingestion import ingest_scan
        from cauldron.parsers.nmap_parser import parse_nmap_xml

        xml_path = Path(__file__).parent.parent / "data" / "samples" / "corporate_network.xml"
        if not xml_path.exists():
            pytest.skip("corporate_network.xml not found")

        scan = parse_nmap_xml(xml_path)
        ingest_scan(scan, source_name="10.0.0.100")

        stats = build_segment_connectivity()

        # Should have segments for 10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24
        assert stats["segments_analyzed"] >= 3
        assert stats["can_reach_created"] > 0
        assert stats["gateway_hosts"] >= 1  # at least gw.corp.local

        # Verify CAN_REACH exists
        with get_session() as session:
            result = session.run(
                "MATCH ()-[r:CAN_REACH]->() RETURN count(r) AS cnt"
            )
            assert result.single()["cnt"] > 0

        # Verify reachability from gateway segment
        reachable = get_reachability_from("10.0.0.1")
        segments = [r["segment"] for r in reachable]
        assert "10.0.1.0/24" in segments
        assert "10.0.2.0/24" in segments
