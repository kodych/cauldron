"""Tests for attack path discovery and scoring engine.

Tests the redesigned attack path system:
- Direct paths: ScanSource -> Host with vulnerability
- Scoring: target value, CVSS, exploits, hops, attack methods
- True pivoting: multi-scan overlap detection
- No PIVOT_TO relationships — paths are computed dynamically
"""

from __future__ import annotations

import pytest

from cauldron.graph.connection import clear_database, get_session, verify_connection
from cauldron.ai.attack_paths import (
    AttackPath,
    PathNode,
    VulnInfo,
    _score_path,
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
          -> WEB02 (10.0.2.21) - web_server, Tomcat (no vulns)
          -> DC01  (10.0.1.10) - domain_controller (no vulns)
          -> DB01  (10.0.1.30) - database, MySQL 5.7 with CVE (CVSS 6.5)

        Segments:
          10.0.1.0/24 (servers): DC01, DB01
          10.0.2.0/24 (DMZ): WEB01, WEB02

        CAN_REACH:
          10.0.2.0/24 -> 10.0.1.0/24
    """
    with get_session() as session:
        session.run("CREATE (:ScanSource {name: '192.168.1.100'})")

        session.run("CREATE (:NetworkSegment {cidr: '10.0.1.0/24'})")
        session.run("CREATE (:NetworkSegment {cidr: '10.0.2.0/24'})")

        session.run("""
            MATCH (s1:NetworkSegment {cidr: '10.0.2.0/24'}),
                  (s2:NetworkSegment {cidr: '10.0.1.0/24'})
            CREATE (s1)-[:CAN_REACH]->(s2)
        """)

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
                has_exploit: true, description: 'Path traversal in Apache 2.4.49',
                confidence: 'confirmed', enables_pivot: true
            })
        """)
        session.run("""
            MATCH (s:Service {host_ip: '10.0.1.30', port: 3306})
            CREATE (s)-[:HAS_VULN]->(:Vulnerability {
                cve_id: 'CVE-2022-21417', cvss: 6.5, severity: 'MEDIUM',
                has_exploit: false, description: 'MySQL vulnerability',
                confidence: 'likely'
            })
        """)


# ---------------------------------------------------------------------------
# Scoring tests
# ---------------------------------------------------------------------------


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


class TestScorePathNewRoles:
    """Test scoring for new target roles (siem, ci_cd, backup)."""

    def test_siem_scores_high(self):
        siem_path = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="siem", role="siem")],
            target_role="siem",
            hop_count=1,
            max_cvss=7.0,
            has_exploits=True,
        )
        web_path = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="web", role="web_server")],
            target_role="web_server",
            hop_count=1,
            max_cvss=7.0,
            has_exploits=True,
        )
        assert _score_path(siem_path) > _score_path(web_path)

    def test_ci_cd_scores_above_web(self):
        ci_path = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="ci", role="ci_cd")],
            target_role="ci_cd",
            hop_count=1,
        )
        web_path = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="web", role="web_server")],
            target_role="web_server",
            hop_count=1,
        )
        assert _score_path(ci_path) > _score_path(web_path)

    def test_backup_scores_above_dns(self):
        backup_path = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="bk", role="backup")],
            target_role="backup",
            hop_count=1,
        )
        dns_path = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="dns", role="dns_server")],
            target_role="dns_server",
            hop_count=1,
        )
        assert _score_path(backup_path) > _score_path(dns_path)


class TestScorePathNonLinearCVSS:
    """Test the non-linear CVSS scoring curve."""

    def test_critical_cvss_max_score(self):
        path = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="tgt", max_cvss=9.8)],
            target_role="web_server",
            hop_count=1,
            max_cvss=9.8,
        )
        score = _score_path(path)
        assert score >= 55

    def test_low_cvss_scores_low(self):
        path = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="tgt", max_cvss=2.0)],
            target_role="web_server",
            hop_count=1,
            max_cvss=2.0,
        )
        score = _score_path(path)
        assert score < 35

    def test_medium_cvss_middle_range(self):
        path = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="tgt", max_cvss=5.5)],
            target_role="web_server",
            hop_count=1,
            max_cvss=5.5,
        )
        score = _score_path(path)
        assert 35 < score < 50


class TestScorePathAttackMethods:
    """Test attack method scoring."""

    def test_exploit_method_adds_bonus(self):
        with_exploit = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="tgt")],
            target_role="database",
            hop_count=1,
            attack_methods=["exploit"],
        )
        with_cve_only = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="tgt")],
            target_role="database",
            hop_count=1,
            attack_methods=["cve"],
        )
        assert _score_path(with_exploit) > _score_path(with_cve_only)

    def test_relay_method_scores_between_exploit_and_cve(self):
        relay = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="tgt")],
            target_role="database",
            hop_count=1,
            attack_methods=["relay"],
        )
        exploit = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="tgt")],
            target_role="database",
            hop_count=1,
            attack_methods=["exploit"],
        )
        cve = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="tgt")],
            target_role="database",
            hop_count=1,
            attack_methods=["cve"],
        )
        assert _score_path(exploit) > _score_path(relay) > _score_path(cve)

    def test_method_bonus_capped(self):
        many_exploits = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="tgt")],
            target_role="database",
            hop_count=1,
            attack_methods=["exploit"] * 10,
        )
        few_exploits = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="tgt")],
            target_role="database",
            hop_count=1,
            attack_methods=["exploit"] * 3,
        )
        score_many = _score_path(many_exploits)
        score_few = _score_path(few_exploits)
        assert score_many - score_few <= 2


class TestManagementTargetValue:
    """Test that management role is scored properly in paths."""

    def test_management_scores_above_backup(self):
        mgmt_path = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="mgmt", role="management")],
            target_role="management",
            hop_count=1,
        )
        backup_path = AttackPath(
            nodes=[PathNode(ip="src"), PathNode(ip="bk", role="backup")],
            target_role="backup",
            hop_count=1,
        )
        assert _score_path(mgmt_path) > _score_path(backup_path)


# ---------------------------------------------------------------------------
# Direct attack path discovery (Neo4j integration tests)
# ---------------------------------------------------------------------------


class TestDiscoverDirectPaths:
    """Test direct path discovery: ScanSource -> vulnerable host."""

    def test_finds_path_to_vulnerable_host(self):
        _setup_attack_graph()
        paths = discover_attack_paths(target_ip="10.0.2.20")

        assert len(paths) >= 1
        path = paths[0]
        assert path.target_ip == "10.0.2.20"
        assert path.hop_count == 1
        assert path.has_exploits is True
        assert path.score > 0

    def test_finds_path_to_db_with_cve(self):
        _setup_attack_graph()
        paths = discover_attack_paths(target_ip="10.0.1.30")

        assert len(paths) >= 1
        path = paths[0]
        assert path.target_ip == "10.0.1.30"
        assert path.target_role == "database"

    def test_no_path_to_host_without_vulns(self):
        """DC01 has no vulns — no attack path should exist."""
        _setup_attack_graph()
        paths = discover_attack_paths(target_ip="10.0.1.10")

        assert len(paths) == 0

    def test_finds_all_vulnerable_hosts(self):
        _setup_attack_graph()
        paths = discover_attack_paths()

        target_ips = {p.target_ip for p in paths}
        # WEB01 (has CVE) and DB01 (has CVE) should have paths
        assert "10.0.2.20" in target_ips
        assert "10.0.1.30" in target_ips
        # DC01 (no CVE) should NOT have a path
        assert "10.0.1.10" not in target_ips

    def test_paths_sorted_by_score(self):
        _setup_attack_graph()
        paths = discover_attack_paths()

        if len(paths) >= 2:
            for i in range(len(paths) - 1):
                assert paths[i].score >= paths[i + 1].score

    def test_no_paths_in_empty_graph(self):
        paths = discover_attack_paths()
        assert paths == []

    def test_path_has_two_nodes(self):
        """Direct paths always have exactly 2 nodes: source + target."""
        _setup_attack_graph()
        paths = discover_attack_paths(target_ip="10.0.2.20")

        if paths:
            path = paths[0]
            assert len(path.nodes) == 2
            assert path.nodes[0].role == "scan_source"
            assert path.nodes[1].ip == "10.0.2.20"

    def test_path_includes_vuln_details(self):
        _setup_attack_graph()
        paths = discover_attack_paths(target_ip="10.0.2.20")

        if paths:
            target = paths[0].nodes[-1]
            assert len(target.vulns) >= 1
            cve = target.vulns[0]
            assert cve.cve_id == "CVE-2021-41773"
            assert cve.cvss == 7.5
            assert cve.has_exploit is True

    def test_filter_by_role(self):
        _setup_attack_graph()
        paths = discover_attack_paths(target_role="database")

        assert all(p.target_role == "database" for p in paths)
        assert len(paths) >= 1

    def test_smb_relay_creates_path(self):
        """SMB signing disabled = valid attack path (relay target)."""
        with get_session() as session:
            session.run("CREATE (:ScanSource {name: 'scanner'})")
            session.run("""
                CREATE (h:Host {ip: '10.0.0.5', state: 'up', role: 'file_server',
                               role_confidence: 0.9})
            """)
            session.run("""
                MATCH (src:ScanSource {name: 'scanner'}), (h:Host {ip: '10.0.0.5'})
                CREATE (src)-[:SCANNED_FROM]->(h)
            """)
            session.run("""
                MATCH (h:Host {ip: '10.0.0.5'})
                CREATE (h)-[:HAS_SERVICE]->(s:Service {host_ip: '10.0.0.5',
                       port: 445, protocol: 'tcp', state: 'open', name: 'microsoft-ds'})
                CREATE (s)-[:HAS_VULN]->(:Vulnerability {
                    cve_id: 'CAULDRON-SMB-SIGNING', cvss: 0.0,
                    has_exploit: true, enables_pivot: false,
                    description: 'SMB signing not required - NTLM relay target',
                    confidence: 'confirmed'
                })
            """)

        paths = discover_attack_paths(target_ip="10.0.0.5")
        assert len(paths) >= 1
        assert paths[0].target_ip == "10.0.0.5"


# ---------------------------------------------------------------------------
# True pivot path discovery
# ---------------------------------------------------------------------------


class TestTruePivotPaths:
    """Test multi-scan pivot detection.

    True pivot: Host appears in external scan AND is ScanSource for internal scan.
    """

    def test_pivot_path_through_compromised_host(self):
        """External scan finds web01, internal scan from web01 finds db_internal."""
        with get_session() as session:
            # External scan
            session.run("CREATE (:ScanSource {name: 'attacker'})")
            session.run("""
                CREATE (h:Host {ip: '10.0.1.5', hostname: 'web01', state: 'up',
                               role: 'web_server', role_confidence: 0.9})
            """)
            session.run("""
                MATCH (src:ScanSource {name: 'attacker'}), (h:Host {ip: '10.0.1.5'})
                CREATE (src)-[:SCANNED_FROM]->(h)
            """)
            # web01 has RCE vuln
            session.run("""
                MATCH (h:Host {ip: '10.0.1.5'})
                CREATE (h)-[:HAS_SERVICE]->(s:Service {host_ip: '10.0.1.5',
                       port: 80, protocol: 'tcp', state: 'open',
                       product: 'Apache httpd', version: '2.4.49'})
                CREATE (s)-[:HAS_VULN]->(:Vulnerability {
                    cve_id: 'CVE-2021-41773', cvss: 7.5, has_exploit: true,
                    enables_pivot: true, description: 'Apache RCE',
                    confidence: 'confirmed'
                })
            """)

            # Internal scan FROM web01 (compromised → pivot)
            session.run("CREATE (:ScanSource {name: '10.0.1.5'})")
            session.run("""
                CREATE (h:Host {ip: '192.168.1.10', hostname: 'db-internal',
                               state: 'up', role: 'database', role_confidence: 0.9})
            """)
            session.run("""
                MATCH (src:ScanSource {name: '10.0.1.5'}), (h:Host {ip: '192.168.1.10'})
                CREATE (src)-[:SCANNED_FROM]->(h)
            """)
            # Internal DB has vuln
            session.run("""
                MATCH (h:Host {ip: '192.168.1.10'})
                CREATE (h)-[:HAS_SERVICE]->(s:Service {host_ip: '192.168.1.10',
                       port: 3306, protocol: 'tcp', state: 'open',
                       product: 'MySQL', version: '5.7.38'})
                CREATE (s)-[:HAS_VULN]->(:Vulnerability {
                    cve_id: 'CVE-2022-21417', cvss: 6.5, has_exploit: false,
                    description: 'MySQL vuln', confidence: 'likely'
                })
            """)

        paths = discover_attack_paths(target_ip="192.168.1.10")

        assert len(paths) >= 1
        pivot_path = paths[0]
        assert pivot_path.hop_count == 2
        assert len(pivot_path.nodes) == 3
        assert pivot_path.nodes[0].ip == "attacker"  # source
        assert pivot_path.nodes[1].ip == "10.0.1.5"  # pivot
        assert pivot_path.nodes[2].ip == "192.168.1.10"  # target
        assert "pivot" in pivot_path.attack_methods

    def test_pivot_path_without_vulns_on_pivot_host(self):
        """Pivot works even if pivot host has no vulns — scan FROM it = compromised."""
        with get_session() as session:
            # External scan finds web01 (no vulns on it)
            session.run("CREATE (:ScanSource {name: 'attacker'})")
            session.run("""
                CREATE (h:Host {ip: '10.0.1.5', hostname: 'web01', state: 'up',
                               role: 'web_server', role_confidence: 0.9})
            """)
            session.run("""
                MATCH (src:ScanSource {name: 'attacker'}), (h:Host {ip: '10.0.1.5'})
                CREATE (src)-[:SCANNED_FROM]->(h)
            """)
            # web01 has a service but NO vulnerabilities
            session.run("""
                MATCH (h:Host {ip: '10.0.1.5'})
                CREATE (h)-[:HAS_SERVICE]->(:Service {host_ip: '10.0.1.5',
                       port: 80, protocol: 'tcp', state: 'open'})
            """)

            # Internal scan FROM web01
            session.run("CREATE (:ScanSource {name: '10.0.1.5'})")
            session.run("""
                CREATE (h:Host {ip: '192.168.1.10', hostname: 'db-internal',
                               state: 'up', role: 'database', role_confidence: 0.9})
            """)
            session.run("""
                MATCH (src:ScanSource {name: '10.0.1.5'}), (h:Host {ip: '192.168.1.10'})
                CREATE (src)-[:SCANNED_FROM]->(h)
            """)
            # Target has a vuln
            session.run("""
                MATCH (h:Host {ip: '192.168.1.10'})
                CREATE (h)-[:HAS_SERVICE]->(s:Service {host_ip: '192.168.1.10',
                       port: 3306, protocol: 'tcp', state: 'open',
                       product: 'MySQL', version: '5.7.38'})
                CREATE (s)-[:HAS_VULN]->(:Vulnerability {
                    cve_id: 'CVE-2022-21417', cvss: 6.5, has_exploit: false,
                    description: 'MySQL vuln', confidence: 'likely'
                })
            """)

        paths = discover_attack_paths(target_ip="192.168.1.10")

        assert len(paths) >= 1
        # Find the pivot path (2-hop through 10.0.1.5)
        pivot_paths = [p for p in paths if p.hop_count == 2]
        assert len(pivot_paths) >= 1, f"No pivot paths found, got: {paths}"
        pivot_path = pivot_paths[0]
        assert pivot_path.nodes[0].ip == "attacker"  # source
        assert pivot_path.nodes[1].ip == "10.0.1.5"  # pivot, no vulns
        assert pivot_path.nodes[2].ip == "192.168.1.10"  # target
        assert "pivot" in pivot_path.attack_methods

    def test_no_pivot_without_matching_scan_source(self):
        """No pivot path if no internal scan exists."""
        with get_session() as session:
            session.run("CREATE (:ScanSource {name: 'attacker'})")
            session.run("""
                CREATE (h:Host {ip: '10.0.1.5', state: 'up', role: 'web_server',
                               role_confidence: 0.9})
            """)
            session.run("""
                MATCH (src:ScanSource {name: 'attacker'}), (h:Host {ip: '10.0.1.5'})
                CREATE (src)-[:SCANNED_FROM]->(h)
            """)
            session.run("""
                MATCH (h:Host {ip: '10.0.1.5'})
                CREATE (h)-[:HAS_SERVICE]->(s:Service {host_ip: '10.0.1.5',
                       port: 80, protocol: 'tcp', state: 'open'})
                CREATE (s)-[:HAS_VULN]->(:Vulnerability {
                    cve_id: 'CVE-2021-41773', cvss: 7.5, has_exploit: true,
                    enables_pivot: true, description: 'Apache RCE'
                })
            """)

        # No internal ScanSource matching 10.0.1.5 → no pivot paths
        pivot_paths = discover_attack_paths(target_role="database")
        assert len(pivot_paths) == 0


# ---------------------------------------------------------------------------
# Path summary
# ---------------------------------------------------------------------------


class TestGetPathSummary:
    def test_summary_with_vulns(self):
        _setup_attack_graph()
        summary = get_path_summary()

        assert summary["vulnerable_hosts"] >= 2  # WEB01 + DB01
        assert summary["with_exploits"] >= 1  # WEB01
        assert "domain_controller" in summary["high_value_targets"]

    def test_summary_empty_graph(self):
        summary = get_path_summary()
        assert summary["vulnerable_hosts"] == 0
        assert summary["high_value_targets"] == {}
        assert summary["pivot_hosts"] == 0

    def test_summary_detects_pivot_hosts(self):
        """Pivot host detected when Host.ip matches ScanSource.name."""
        with get_session() as session:
            session.run("CREATE (:ScanSource {name: 'external'})")
            session.run("""
                CREATE (h:Host {ip: '10.0.1.5', state: 'up', role: 'web_server',
                               role_confidence: 0.9})
            """)
            session.run("""
                MATCH (src:ScanSource {name: 'external'}), (h:Host {ip: '10.0.1.5'})
                CREATE (src)-[:SCANNED_FROM]->(h)
            """)
            # Internal scan from 10.0.1.5
            session.run("CREATE (:ScanSource {name: '10.0.1.5'})")

        summary = get_path_summary()
        assert summary["pivot_hosts"] == 1


# ---------------------------------------------------------------------------
# Full pipeline test
# ---------------------------------------------------------------------------


class TestFullPipeline:
    def test_brew_boil_paths_pipeline(self):
        """Test the complete pipeline with corporate_network.xml."""
        from pathlib import Path

        from cauldron.ai.classifier import classify_hosts
        from cauldron.exploits.matcher import ExploitDB, upgrade_confidence_from_scripts
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

        # Boil phases: exploit DB + scripts + topology
        exploit_db = ExploitDB()
        exploit_db.match_from_graph()
        upgrade_confidence_from_scripts()
        build_segment_connectivity()

        # Paths — discovered dynamically from vulns
        paths = discover_attack_paths()

        # Should find paths to hosts with vulns
        assert len(paths) >= 1

        summary = get_path_summary()
        assert summary["high_value_targets"].get("domain_controller", 0) >= 1


# ---------------------------------------------------------------------------
# VulnInfo attack method classification
# ---------------------------------------------------------------------------


class TestVulnInfoMethod:
    """Test that VulnInfo carries attack method info."""

    def test_vuln_has_method_field(self):
        v = VulnInfo(cve_id="CVE-2021-41773", method="exploit")
        assert v.method == "exploit"

    def test_vuln_has_enables_pivot(self):
        v = VulnInfo(cve_id="CVE-2021-41773", enables_pivot=True)
        assert v.enables_pivot is True

    def test_relay_vuln(self):
        v = VulnInfo(cve_id="CAULDRON-SMB-SIGNING", method="relay", enables_pivot=False)
        assert v.method == "relay"
        assert v.enables_pivot is False
