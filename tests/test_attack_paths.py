"""Tests for attack path discovery and scoring engine."""

from __future__ import annotations

import pytest

from cauldron.graph.connection import clear_database, get_session, verify_connection
from cauldron.ai.attack_paths import (
    AttackPath,
    PathNode,
    _score_path,
    build_pivot_relationships,
    discover_attack_paths,
    get_path_summary,
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


def _setup_attack_graph():
    """Create a realistic attack graph in Neo4j.

    Network:
        ScanSource("192.168.1.100")
          -> WEB01 (10.0.2.20) - web_server, Apache 2.4.49 with CVE (CVSS 7.5, has exploit)
          -> WEB02 (10.0.2.21) - web_server, Tomcat
          -> DC01  (10.0.1.10) - domain_controller
          -> DB01  (10.0.1.30) - database, MySQL 5.7 with CVE (CVSS 6.5)

        Segments:
          10.0.1.0/24 (servers): DC01, DB01
          10.0.2.0/24 (DMZ): WEB01, WEB02

        CAN_REACH:
          10.0.2.0/24 -> 10.0.1.0/24
    """
    with get_session() as session:
        # Scan source
        session.run("CREATE (:ScanSource {name: '192.168.1.100'})")

        # Segments
        session.run("CREATE (:NetworkSegment {cidr: '10.0.1.0/24'})")
        session.run("CREATE (:NetworkSegment {cidr: '10.0.2.0/24'})")

        # CAN_REACH
        session.run("""
            MATCH (s1:NetworkSegment {cidr: '10.0.2.0/24'}),
                  (s2:NetworkSegment {cidr: '10.0.1.0/24'})
            CREATE (s1)-[:CAN_REACH]->(s2)
        """)

        # Hosts
        session.run("""
            CREATE (:Host {ip: '10.0.2.20', hostname: 'web01.corp.local',
                          state: 'up', role: 'web_server', role_confidence: 0.9})
        """)
        session.run("""
            CREATE (:Host {ip: '10.0.2.21', hostname: 'web02.corp.local',
                          state: 'up', role: 'web_server', role_confidence: 0.85})
        """)
        session.run("""
            CREATE (:Host {ip: '10.0.1.10', hostname: 'dc01.corp.local',
                          state: 'up', role: 'domain_controller', role_confidence: 0.95})
        """)
        session.run("""
            CREATE (:Host {ip: '10.0.1.30', hostname: 'db01.corp.local',
                          state: 'up', role: 'database', role_confidence: 0.9})
        """)

        # Link hosts to segments
        for ip, cidr in [
            ("10.0.2.20", "10.0.2.0/24"),
            ("10.0.2.21", "10.0.2.0/24"),
            ("10.0.1.10", "10.0.1.0/24"),
            ("10.0.1.30", "10.0.1.0/24"),
        ]:
            session.run(
                """
                MATCH (h:Host {ip: $ip}), (s:NetworkSegment {cidr: $cidr})
                CREATE (h)-[:IN_SEGMENT]->(s)
                """,
                ip=ip, cidr=cidr,
            )

        # Link scan source to hosts
        for ip in ["10.0.2.20", "10.0.2.21", "10.0.1.10", "10.0.1.30"]:
            session.run(
                """
                MATCH (src:ScanSource {name: '192.168.1.100'}), (h:Host {ip: $ip})
                CREATE (src)-[:SCANNED_FROM]->(h)
                """,
                ip=ip,
            )

        # Services
        session.run("""
            MATCH (h:Host {ip: '10.0.2.20'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {host_ip: '10.0.2.20', port: 80,
                   protocol: 'tcp', state: 'open', name: 'http',
                   product: 'Apache httpd', version: '2.4.49'})
        """)
        session.run("""
            MATCH (h:Host {ip: '10.0.2.20'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {host_ip: '10.0.2.20', port: 22,
                   protocol: 'tcp', state: 'open', name: 'ssh',
                   product: 'OpenSSH', version: '7.4p1'})
        """)
        session.run("""
            MATCH (h:Host {ip: '10.0.1.30'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {host_ip: '10.0.1.30', port: 3306,
                   protocol: 'tcp', state: 'open', name: 'mysql',
                   product: 'MySQL', version: '5.7.38'})
        """)
        session.run("""
            MATCH (h:Host {ip: '10.0.1.10'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {host_ip: '10.0.1.10', port: 389,
                   protocol: 'tcp', state: 'open', name: 'ldap',
                   product: 'Microsoft Windows Active Directory LDAP'})
        """)

        # Vulnerabilities
        session.run("""
            MATCH (s:Service {host_ip: '10.0.2.20', port: 80})
            CREATE (s)-[:HAS_VULN]->(:Vulnerability {
                cve_id: 'CVE-2021-41773', cvss: 7.5, severity: 'HIGH',
                has_exploit: true, description: 'Path traversal in Apache 2.4.49'
            })
        """)
        session.run("""
            MATCH (s:Service {host_ip: '10.0.1.30', port: 3306})
            CREATE (s)-[:HAS_VULN]->(:Vulnerability {
                cve_id: 'CVE-2022-21417', cvss: 6.5, severity: 'MEDIUM',
                has_exploit: false, description: 'MySQL vulnerability'
            })
        """)


class TestScorePath:
    def test_high_value_target_scores_higher(self):
        dc_path = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="dc", role="domain_controller")],
            target_role="domain_controller",
            hop_count=1,
            max_cvss=7.5,
            has_exploits=True,
        )
        web_path = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="web", role="web_server")],
            target_role="web_server",
            hop_count=1,
            max_cvss=7.5,
            has_exploits=True,
        )
        assert _score_path(dc_path) > _score_path(web_path)

    def test_exploit_availability_boosts_score(self):
        with_exploit = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="tgt", max_cvss=7.5, has_exploit=True)],
            target_role="web_server",
            hop_count=1,
            max_cvss=7.5,
            has_exploits=True,
        )
        without_exploit = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="tgt", max_cvss=7.5)],
            target_role="web_server",
            hop_count=1,
            max_cvss=7.5,
            has_exploits=False,
        )
        assert _score_path(with_exploit) > _score_path(without_exploit)

    def test_fewer_hops_scores_higher(self):
        short = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="tgt")],
            target_role="database",
            hop_count=1,
        )
        long = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="p1"), PathNode(ip="p2"), PathNode(ip="tgt")],
            target_role="database",
            hop_count=3,
        )
        assert _score_path(short) > _score_path(long)

    def test_higher_cvss_scores_higher(self):
        high_cvss = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="tgt", max_cvss=9.8)],
            target_role="web_server",
            hop_count=1,
            max_cvss=9.8,
        )
        low_cvss = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="tgt", max_cvss=3.5)],
            target_role="web_server",
            hop_count=1,
            max_cvss=3.5,
        )
        assert _score_path(high_cvss) > _score_path(low_cvss)


class TestBuildPivotRelationships:
    def test_creates_pivots(self):
        _setup_attack_graph()
        stats = build_pivot_relationships()

        assert stats["pairs_analyzed"] > 0
        # WEB01 has exploit → should create pivots
        with get_session() as session:
            result = session.run(
                "MATCH ()-[p:PIVOT_TO]->() RETURN count(p) AS cnt"
            )
            assert result.single()["cnt"] > 0

    def test_pivot_has_method_and_difficulty(self):
        _setup_attack_graph()
        build_pivot_relationships()

        with get_session() as session:
            result = session.run(
                """
                MATCH ()-[p:PIVOT_TO]->()
                RETURN p.method AS method, p.difficulty AS difficulty
                LIMIT 1
                """
            )
            record = result.single()
            assert record is not None
            assert record["method"] in ("exploit", "vuln_service", "shared_segment")
            assert record["difficulty"] in ("easy", "medium", "hard")

    def test_empty_graph(self):
        stats = build_pivot_relationships()
        assert stats["pivots_created"] == 0
        assert stats["pairs_analyzed"] == 0

    def test_idempotent(self):
        _setup_attack_graph()
        build_pivot_relationships()

        with get_session() as session:
            result = session.run("MATCH ()-[p:PIVOT_TO]->() RETURN count(p) AS cnt")
            count1 = result.single()["cnt"]

        build_pivot_relationships()

        with get_session() as session:
            result = session.run("MATCH ()-[p:PIVOT_TO]->() RETURN count(p) AS cnt")
            count2 = result.single()["cnt"]

        assert count1 == count2


class TestDiscoverAttackPaths:
    def test_finds_paths_to_dc(self):
        _setup_attack_graph()
        paths = discover_attack_paths(target_role="domain_controller")

        assert len(paths) >= 1
        assert paths[0].target_role == "domain_controller"
        assert paths[0].score > 0

    def test_finds_paths_to_specific_ip(self):
        _setup_attack_graph()
        paths = discover_attack_paths(target_ip="10.0.1.10")

        assert len(paths) >= 1
        assert paths[0].target_ip == "10.0.1.10"

    def test_finds_all_high_value_paths(self):
        _setup_attack_graph()
        paths = discover_attack_paths()

        # Should find paths to DC and DB at minimum
        target_roles = {p.target_role for p in paths}
        assert "domain_controller" in target_roles

    def test_paths_sorted_by_score(self):
        _setup_attack_graph()
        paths = discover_attack_paths()

        if len(paths) >= 2:
            for i in range(len(paths) - 1):
                assert paths[i].score >= paths[i + 1].score

    def test_no_paths_in_empty_graph(self):
        paths = discover_attack_paths()
        assert paths == []

    def test_path_has_nodes(self):
        _setup_attack_graph()
        paths = discover_attack_paths(target_role="domain_controller")

        if paths:
            path = paths[0]
            assert len(path.nodes) >= 2
            assert path.nodes[0].role == "scan_source"
            assert path.hop_count >= 1


class TestGetPathSummary:
    def test_summary_with_pivots(self):
        _setup_attack_graph()
        build_pivot_relationships()

        summary = get_path_summary()
        assert summary["total_pivots"] > 0
        assert "domain_controller" in summary["high_value_targets"]

    def test_summary_empty_graph(self):
        summary = get_path_summary()
        assert summary["total_pivots"] == 0
        assert summary["high_value_targets"] == {}


class TestFullPipeline:
    def test_brew_boil_paths_pipeline(self):
        """Test the complete pipeline with corporate_network.xml."""
        from pathlib import Path

        from cauldron.ai.classifier import classify_hosts
        from cauldron.graph.ingestion import ingest_scan
        from cauldron.graph.topology import build_segment_connectivity
        from cauldron.parsers.nmap_parser import parse_nmap_xml

        xml_path = Path(__file__).parent.parent / "data" / "samples" / "corporate_network.xml"
        if not xml_path.exists():
            pytest.skip("corporate_network.xml not found")

        # Brew
        scan = parse_nmap_xml(xml_path)
        classify_hosts(scan.hosts_up)
        ingest_scan(scan, source_name="10.0.0.100")

        # Boil (topology + pivots)
        build_segment_connectivity()
        build_pivot_relationships()

        # Paths
        paths = discover_attack_paths()

        # Should find at least one path (there are 2 DCs in the test data)
        assert len(paths) >= 1

        summary = get_path_summary()
        assert summary["high_value_targets"].get("domain_controller", 0) >= 1
