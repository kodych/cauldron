"""Tests for the collect module — target list extraction from graph."""

from __future__ import annotations

import pytest

from cauldron.graph.connection import clear_database, get_session, verify_connection
from cauldron.collect import collect_targets, list_filters

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


def _setup_network():
    """Create a test network with various services.

    Hosts:
      - DC01 (10.0.1.10) domain_controller: 88, 389, 445, 636
      - WEB01 (10.0.1.20) web_server: 80, 443
      - DB01 (10.0.1.30) database: 3306
      - FS01 (10.0.1.40) file_server: 445, 21
      - RDP01 (10.0.1.50) remote_access: 3389
      - SSH01 (10.0.2.10) unknown: 22

    ScanSources: scanner1 -> all in 10.0.1.x, scanner2 -> SSH01 only
    """
    with get_session() as session:
        session.run("CREATE (:ScanSource {name: 'scanner1'})")
        session.run("CREATE (:ScanSource {name: 'scanner2'})")

        # DC01
        session.run("""
            CREATE (h:Host {ip: '10.0.1.10', hostname: 'DC01', role: 'domain_controller'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {port: 88, protocol: 'tcp', name: 'kerberos'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {port: 389, protocol: 'tcp', name: 'ldap'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {port: 445, protocol: 'tcp', name: 'microsoft-ds'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {port: 636, protocol: 'tcp', name: 'ldaps'})
        """)
        # WEB01
        session.run("""
            CREATE (h:Host {ip: '10.0.1.20', hostname: 'WEB01', role: 'web_server'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {port: 80, protocol: 'tcp', name: 'http'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {port: 443, protocol: 'tcp', name: 'https'})
        """)
        # DB01
        session.run("""
            CREATE (h:Host {ip: '10.0.1.30', hostname: 'DB01', role: 'database'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {port: 3306, protocol: 'tcp', name: 'mysql'})
        """)
        # FS01
        session.run("""
            CREATE (h:Host {ip: '10.0.1.40', hostname: 'FS01', role: 'file_server'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {port: 445, protocol: 'tcp', name: 'microsoft-ds'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {port: 21, protocol: 'tcp', name: 'ftp'})
        """)
        # RDP01
        session.run("""
            CREATE (h:Host {ip: '10.0.1.50', hostname: 'RDP01', role: 'remote_access'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {port: 3389, protocol: 'tcp', name: 'ms-wbt-server'})
        """)
        # SSH01 (different segment, only from scanner2)
        session.run("""
            CREATE (h:Host {ip: '10.0.2.10', hostname: 'SSH01', role: 'unknown'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {port: 22, protocol: 'tcp', name: 'ssh'})
        """)

        # SCANNED_FROM relationships
        for ip in ["10.0.1.10", "10.0.1.20", "10.0.1.30", "10.0.1.40", "10.0.1.50"]:
            session.run(
                "MATCH (src:ScanSource {name: 'scanner1'}), (h:Host {ip: $ip}) "
                "CREATE (src)-[:SCANNED_FROM]->(h)",
                ip=ip,
            )
        session.run(
            "MATCH (src:ScanSource {name: 'scanner2'}), (h:Host {ip: '10.0.2.10'}) "
            "CREATE (src)-[:SCANNED_FROM]->(h)"
        )


def _setup_vulns():
    """Add vulnerabilities to some hosts."""
    with get_session() as session:
        # Confirmed exploit on WEB01
        session.run("""
            MATCH (h:Host {ip: '10.0.1.20'})-[:HAS_SERVICE]->(s:Service {port: 80})
            CREATE (s)-[:HAS_VULN {confidence: 'confirmed'}]->(:Vulnerability {
                cve_id: 'CVE-2021-41773', cvss: 7.5,
                enables_pivot: true
            })
        """)
        # Check-level on DB01
        session.run("""
            MATCH (h:Host {ip: '10.0.1.30'})-[:HAS_SERVICE]->(s:Service {port: 3306})
            CREATE (s)-[:HAS_VULN {confidence: 'check'}]->(:Vulnerability {
                cve_id: 'CAULDRON-042', cvss: 5.0,
                enables_pivot: false
            })
        """)


class TestBuiltinFilters:
    """Test built-in filter queries."""

    def test_smb_filter(self):
        _setup_network()
        result = collect_targets(filter_name="smb")
        ips = [h.ip for h in result.hosts]
        assert "10.0.1.10" in ips  # DC01 has 445
        assert "10.0.1.40" in ips  # FS01 has 445
        assert "10.0.1.20" not in ips  # WEB01 no 445
        assert result.total == 2

    def test_smb_has_port(self):
        _setup_network()
        result = collect_targets(filter_name="smb")
        assert all(h.port == 445 for h in result.hosts)

    def test_rdp_filter(self):
        _setup_network()
        result = collect_targets(filter_name="rdp")
        assert result.total == 1
        assert result.hosts[0].ip == "10.0.1.50"
        assert result.hosts[0].port == 3389

    def test_ssh_filter(self):
        _setup_network()
        result = collect_targets(filter_name="ssh")
        assert result.total == 1
        assert result.hosts[0].ip == "10.0.2.10"

    def test_http_filter(self):
        _setup_network()
        result = collect_targets(filter_name="http")
        assert result.total == 1  # WEB01 has both 80 and 443 but should appear once
        assert result.hosts[0].ip == "10.0.1.20"

    def test_ftp_filter(self):
        _setup_network()
        result = collect_targets(filter_name="ftp")
        assert result.total == 1
        assert result.hosts[0].ip == "10.0.1.40"

    def test_mysql_filter(self):
        _setup_network()
        result = collect_targets(filter_name="mysql")
        assert result.total == 1
        assert result.hosts[0].ip == "10.0.1.30"

    def test_kerberos_filter(self):
        _setup_network()
        result = collect_targets(filter_name="kerberos")
        assert result.total == 1
        assert result.hosts[0].ip == "10.0.1.10"

    def test_ldap_filter(self):
        _setup_network()
        result = collect_targets(filter_name="ldap")
        assert result.total == 1  # DC01 has 389 + 636, should appear once
        assert result.hosts[0].ip == "10.0.1.10"

    def test_dc_filter(self):
        _setup_network()
        result = collect_targets(filter_name="dc")
        assert result.total == 1
        assert result.hosts[0].ip == "10.0.1.10"


class TestVulnFilters:
    """Test vulnerability-based filters."""

    def test_vuln_filter(self):
        _setup_network()
        _setup_vulns()
        result = collect_targets(filter_name="vuln")
        ips = [h.ip for h in result.hosts]
        assert "10.0.1.20" in ips  # WEB01 has vuln
        assert "10.0.1.30" in ips  # DB01 has vuln
        assert result.total == 2

    def test_exploitable_filter(self):
        _setup_network()
        _setup_vulns()
        result = collect_targets(filter_name="exploitable")
        ips = [h.ip for h in result.hosts]
        assert "10.0.1.20" in ips  # confirmed
        assert "10.0.1.30" not in ips  # check only
        assert result.total == 1

    def test_rce_filter(self):
        _setup_network()
        _setup_vulns()
        result = collect_targets(filter_name="rce")
        assert result.total == 1
        assert result.hosts[0].ip == "10.0.1.20"


class TestCustomFilters:
    """Test custom port and role filters."""

    def test_custom_port(self):
        _setup_network()
        result = collect_targets(port=3306)
        assert result.total == 1
        assert result.hosts[0].ip == "10.0.1.30"
        assert result.hosts[0].port == 3306

    def test_role_filter(self):
        _setup_network()
        result = collect_targets(role="database")
        assert result.total == 1
        assert result.hosts[0].ip == "10.0.1.30"

    def test_role_domain_controller(self):
        _setup_network()
        result = collect_targets(role="domain_controller")
        assert result.total == 1
        assert result.hosts[0].ip == "10.0.1.10"


class TestSourceFilter:
    """Test scan source filtering."""

    def test_source_filter_scanner1(self):
        _setup_network()
        result = collect_targets(filter_name="smb", source="scanner1")
        ips = [h.ip for h in result.hosts]
        assert "10.0.1.10" in ips
        assert "10.0.1.40" in ips
        assert result.total == 2

    def test_source_filter_scanner2(self):
        _setup_network()
        result = collect_targets(filter_name="ssh", source="scanner2")
        assert result.total == 1
        assert result.hosts[0].ip == "10.0.2.10"

    def test_source_filter_no_match(self):
        _setup_network()
        result = collect_targets(filter_name="ssh", source="scanner1")
        assert result.total == 0  # SSH01 not scanned from scanner1

    def test_source_filter_nonexistent(self):
        _setup_network()
        result = collect_targets(filter_name="smb", source="ghost")
        assert result.total == 0


class TestResultFields:
    """Test result metadata and host entry fields."""

    def test_hostname_populated(self):
        _setup_network()
        result = collect_targets(filter_name="rdp")
        assert result.hosts[0].hostname == "RDP01"

    def test_role_populated(self):
        _setup_network()
        result = collect_targets(filter_name="rdp")
        assert result.hosts[0].role == "remote_access"

    def test_filter_used_label(self):
        _setup_network()
        assert collect_targets(filter_name="smb").filter_used == "smb"
        assert collect_targets(port=22).filter_used == "port:22"
        assert collect_targets(role="database").filter_used == "role:database"

    def test_results_sorted_by_ip(self):
        _setup_network()
        result = collect_targets(filter_name="smb")
        ips = [h.ip for h in result.hosts]
        assert ips == sorted(ips)

    def test_unknown_filter_raises(self):
        with pytest.raises(ValueError, match="Unknown filter"):
            collect_targets(filter_name="nonexistent")


class TestListFilters:
    """Test filter listing."""

    def test_list_filters_not_empty(self):
        filters = list_filters()
        assert len(filters) > 10

    def test_list_filters_has_smb(self):
        filters = list_filters()
        names = [f["name"] for f in filters]
        assert "smb" in names

    def test_list_filters_has_brute(self):
        filters = list_filters()
        names = [f["name"] for f in filters]
        assert "brute" in names

    def test_list_filters_has_descriptions(self):
        filters = list_filters()
        for f in filters:
            assert "name" in f
            assert "description" in f
            assert len(f["description"]) > 5


class TestBruteFilter:
    """Test the brute collect filter."""

    def test_brute_filter_returns_bruteforceable_sockets(self):
        """Brute filter should return services marked as bruteforceable."""
        _setup_network()
        # Mark some services as bruteforceable
        with get_session() as session:
            session.run(
                "MATCH (s:Service) WHERE s.port IN [22, 445, 3389, 3306, 21] "
                "SET s.bruteforceable = true"
            )
        result = collect_targets(filter_name="brute")
        # Should have multiple sockets (per_service mode)
        assert result.total >= 5
        # Each entry should have a port
        for h in result.hosts:
            assert h.port is not None

    def test_brute_filter_includes_manual(self):
        """Brute filter should also pick up manually-marked services."""
        _setup_network()
        with get_session() as session:
            session.run(
                "MATCH (s:Service {port: 80}) SET s.bruteforceable_manual = true"
            )
        result = collect_targets(filter_name="brute")
        ips = [(h.ip, h.port) for h in result.hosts]
        assert ("10.0.1.20", 80) in ips

    def test_brute_filter_empty_when_no_marks(self):
        """Brute filter returns nothing when no services are marked."""
        _setup_network()
        result = collect_targets(filter_name="brute")
        assert result.total == 0


class TestNoDuplicates:
    """Ensure hosts with multiple matching services appear only once."""

    def test_host_with_multiple_matching_ports(self):
        """DC01 has both 389 and 636 (LDAP) — should appear once."""
        _setup_network()
        result = collect_targets(filter_name="ldap")
        ips = [h.ip for h in result.hosts]
        assert ips.count("10.0.1.10") == 1

    def test_host_with_http_and_https(self):
        """WEB01 has 80 and 443 — should appear once."""
        _setup_network()
        result = collect_targets(filter_name="http")
        assert result.total == 1


class TestFalsePositiveExclusion:
    """Regression: once an operator marks a finding as false_positive, it
    must drop out of every vuln-based collect filter. Enforced at the
    match_vuln level in the query builder so a new vuln filter can't
    silently re-introduce the leak.
    """

    def _setup_fp_fixture(self):
        """WEB01: RCE vuln, operator marked as false_positive.
        DB01: separate vuln, untouched."""
        _setup_network()
        with get_session() as session:
            session.run("""
                MATCH (h:Host {ip: '10.0.1.20'})-[:HAS_SERVICE]->(s:Service {port: 80})
                CREATE (s)-[:HAS_VULN {confidence: 'confirmed',
                                      checked_status: 'false_positive',
                                      ai_fp_reason: 'Patched — operator verified'}]
                      ->(:Vulnerability {
                    cve_id: 'CVE-2024-FP-TEST', cvss: 9.8,
                    enables_pivot: true, has_exploit: true
                })
            """)
            # DB01 gets a real (non-FP) confirmed vuln so the test asserts
            # the filter returns what it should AND only what it should.
            session.run("""
                MATCH (h:Host {ip: '10.0.1.30'})-[:HAS_SERVICE]->(s:Service {port: 3306})
                CREATE (s)-[:HAS_VULN {confidence: 'confirmed'}]->(:Vulnerability {
                    cve_id: 'CVE-2024-REAL-TEST', cvss: 8.0,
                    enables_pivot: true, has_exploit: true
                })
            """)

    def test_vuln_filter_excludes_false_positive(self):
        self._setup_fp_fixture()
        result = collect_targets(filter_name="vuln")
        ips = [h.ip for h in result.hosts]
        assert "10.0.1.20" not in ips, "WEB01's FP vuln must be excluded"
        assert "10.0.1.30" in ips, "DB01's real vuln still returned"

    def test_exploitable_filter_excludes_false_positive(self):
        self._setup_fp_fixture()
        result = collect_targets(filter_name="exploitable")
        ips = [h.ip for h in result.hosts]
        assert "10.0.1.20" not in ips
        assert "10.0.1.30" in ips

    def test_rce_filter_excludes_false_positive(self):
        self._setup_fp_fixture()
        result = collect_targets(filter_name="rce")
        ips = [h.ip for h in result.hosts]
        assert "10.0.1.20" not in ips
        assert "10.0.1.30" in ips

    def test_other_checked_statuses_stay(self):
        """Only 'false_positive' is dismissed. 'exploited' and 'mitigated'
        are engagement verdicts, not disqualifications — keep them."""
        _setup_network()
        with get_session() as session:
            session.run("""
                MATCH (h:Host {ip: '10.0.1.20'})-[:HAS_SERVICE]->(s:Service {port: 80})
                CREATE (s)-[:HAS_VULN {confidence: 'confirmed',
                                      checked_status: 'exploited'}]
                      ->(:Vulnerability {
                    cve_id: 'CVE-2024-EXPL-TEST', cvss: 9.8,
                    enables_pivot: true, has_exploit: true
                })
            """)
        result = collect_targets(filter_name="exploitable")
        assert "10.0.1.20" in [h.ip for h in result.hosts]


class TestEngagementFilters:
    """New filters for the post-boil pentester workflow: KEV targets,
    engagement state (owned / target), and targets that don't have any
    actionable vuln to attack through.
    """

    def test_kev_filter_returns_only_kev_hosts(self):
        _setup_network()
        # WEB01 gets a KEV vuln, DB01 gets a non-KEV vuln, DC01 nothing.
        with get_session() as session:
            session.run("""
                MATCH (h:Host {ip: '10.0.1.20'})-[:HAS_SERVICE]->(s:Service {port: 80})
                CREATE (s)-[:HAS_VULN {confidence: 'confirmed'}]->(:Vulnerability {
                    cve_id: 'CVE-2021-44228', cvss: 10.0, in_cisa_kev: true
                })
            """)
            session.run("""
                MATCH (h:Host {ip: '10.0.1.30'})-[:HAS_SERVICE]->(s:Service {port: 3306})
                CREATE (s)-[:HAS_VULN {confidence: 'check'}]->(:Vulnerability {
                    cve_id: 'CVE-2024-PLAIN', cvss: 6.0, in_cisa_kev: false
                })
            """)
        result = collect_targets(filter_name="kev")
        ips = [h.ip for h in result.hosts]
        assert "10.0.1.20" in ips
        assert "10.0.1.30" not in ips
        assert "10.0.1.10" not in ips

    def test_kev_filter_still_excludes_false_positive(self):
        """The match_vuln auto-exclusion of FP-marked findings must still
        apply to the KEV filter — operator-dismissed findings do not
        count even if they were KEV."""
        _setup_network()
        with get_session() as session:
            session.run("""
                MATCH (h:Host {ip: '10.0.1.20'})-[:HAS_SERVICE]->(s:Service {port: 80})
                CREATE (s)-[:HAS_VULN {confidence: 'confirmed',
                                      checked_status: 'false_positive'}]
                      ->(:Vulnerability {
                    cve_id: 'CVE-2021-44228', cvss: 10.0, in_cisa_kev: true
                })
            """)
        result = collect_targets(filter_name="kev")
        assert "10.0.1.20" not in [h.ip for h in result.hosts]

    def test_owned_filter(self):
        _setup_network()
        with get_session() as session:
            session.run("MATCH (h:Host {ip: '10.0.1.20'}) SET h.owned = true")
        result = collect_targets(filter_name="owned")
        ips = [h.ip for h in result.hosts]
        assert ips == ["10.0.1.20"]

    def test_target_filter(self):
        _setup_network()
        with get_session() as session:
            session.run("MATCH (h:Host {ip: '10.0.1.10'}) SET h.target = true")
            session.run("MATCH (h:Host {ip: '10.0.1.30'}) SET h.target = true")
        result = collect_targets(filter_name="target")
        ips = sorted(h.ip for h in result.hosts)
        assert ips == ["10.0.1.10", "10.0.1.30"]

    def test_target_blocked_returns_targets_with_no_vulns(self):
        """Engagement blockers: targets without any active finding we
        can attack. Targets WITH a vuln (even if only 'check' confidence)
        are NOT blocked — operator still has something to try."""
        _setup_network()
        with get_session() as session:
            # DC01: target, zero vulns → blocked
            session.run("MATCH (h:Host {ip: '10.0.1.10'}) SET h.target = true")
            # DB01: target, but has an active vuln → NOT blocked
            session.run("MATCH (h:Host {ip: '10.0.1.30'}) SET h.target = true")
            session.run("""
                MATCH (h:Host {ip: '10.0.1.30'})-[:HAS_SERVICE]->(s:Service {port: 3306})
                CREATE (s)-[:HAS_VULN {confidence: 'check'}]->(:Vulnerability {
                    cve_id: 'CVE-2024-X', cvss: 5.0
                })
            """)
            # WEB01: NOT a target at all → excluded regardless
            session.run("""
                MATCH (h:Host {ip: '10.0.1.20'})-[:HAS_SERVICE]->(s:Service {port: 80})
                CREATE (s)-[:HAS_VULN {confidence: 'check'}]->(:Vulnerability {
                    cve_id: 'CVE-2024-Y', cvss: 5.0
                })
            """)
        result = collect_targets(filter_name="target-blocked")
        ips = [h.ip for h in result.hosts]
        assert ips == ["10.0.1.10"]

    def test_target_blocked_ignores_false_positive_vulns(self):
        """A target with only FP-marked vulns is still blocked — FPs are
        not actionable."""
        _setup_network()
        with get_session() as session:
            session.run("MATCH (h:Host {ip: '10.0.1.10'}) SET h.target = true")
            session.run("""
                MATCH (h:Host {ip: '10.0.1.10'})-[:HAS_SERVICE]->(s:Service {port: 445})
                CREATE (s)-[:HAS_VULN {confidence: 'check',
                                      checked_status: 'false_positive'}]
                      ->(:Vulnerability {cve_id: 'CVE-FP-ONLY', cvss: 5.0})
            """)
        result = collect_targets(filter_name="target-blocked")
        assert "10.0.1.10" in [h.ip for h in result.hosts]
