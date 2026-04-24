"""Integration tests for Neo4j ingestion.

These tests require a running Neo4j instance.
They use a real database connection and clean up after themselves.

Run with: pytest tests/test_ingestion.py -v
Skip if Neo4j is not available: pytest tests/test_ingestion.py -v -k "not integration"
"""

from __future__ import annotations

import pytest

from cauldron.graph.connection import clear_database, get_session, verify_connection
from cauldron.graph.ingestion import (
    get_graph_stats,
    get_host_role_distribution,
    ingest_scan,
)
from cauldron.graph.models import Host, ScanResult, Service, TracerouteHop
from cauldron.parsers.nmap_parser import parse_nmap_xml

# Skip all tests in this module if Neo4j is not available
pytestmark = pytest.mark.skipif(
    not verify_connection(),
    reason="Neo4j is not running",
)


@pytest.fixture(autouse=True)
def clean_db():
    """Clear the database before and after each test."""
    clear_database()
    yield
    clear_database()


def _make_scan(hosts: list[Host], source: str | None = None) -> ScanResult:
    """Helper to create a ScanResult."""
    return ScanResult(hosts=hosts, scan_source=source)


def _make_host(ip: str, services: list[tuple[int, str]] | None = None, hostname: str | None = None) -> Host:
    """Helper to create a Host with services.

    services: list of (port, service_name) tuples.
    """
    svcs = []
    if services:
        for port, name in services:
            svcs.append(Service(port=port, protocol="tcp", state="open", name=name))
    return Host(ip=ip, hostname=hostname, state="up", services=svcs)


class TestBasicIngestion:
    """Test basic import functionality."""

    def test_ingest_single_host(self):
        host = _make_host("10.0.0.1", [(22, "ssh"), (80, "http")])
        scan = _make_scan([host])
        stats = ingest_scan(scan, source_name="test-scanner")

        assert stats["hosts_imported"] == 1
        assert stats["services_imported"] == 2
        assert stats["hosts_skipped"] == 0

    def test_ingest_multiple_hosts(self):
        hosts = [
            _make_host("10.0.0.1", [(22, "ssh")]),
            _make_host("10.0.0.2", [(80, "http"), (443, "https")]),
            _make_host("10.0.0.3", [(3306, "mysql")]),
        ]
        scan = _make_scan(hosts)
        stats = ingest_scan(scan, source_name="scanner")

        assert stats["hosts_imported"] == 3
        assert stats["services_imported"] == 4

    def test_ingest_skips_down_hosts(self):
        hosts = [
            _make_host("10.0.0.1", [(22, "ssh")]),
            Host(ip="10.0.0.2", state="down"),
        ]
        scan = _make_scan(hosts)
        stats = ingest_scan(scan, source_name="scanner")

        assert stats["hosts_imported"] == 1

    def test_graph_stats_after_ingest(self):
        hosts = [
            _make_host("10.0.0.1", [(22, "ssh"), (80, "http")]),
            _make_host("10.0.0.2", [(443, "https")]),
        ]
        scan = _make_scan(hosts)
        ingest_scan(scan, source_name="scanner")

        stats = get_graph_stats()
        assert stats["hosts"] == 2
        assert stats["services"] == 3
        assert stats["segments"] == 1  # both in 10.0.0.0/24
        assert stats["scan_sources"] == 1


class TestMergeBehavior:
    """Test that re-importing doesn't create duplicates."""

    def test_reimport_same_scan_no_duplicates(self):
        host = _make_host("10.0.0.1", [(22, "ssh"), (80, "http")])
        scan = _make_scan([host])

        ingest_scan(scan, source_name="scanner")
        ingest_scan(scan, source_name="scanner")

        stats = get_graph_stats()
        assert stats["hosts"] == 1
        assert stats["services"] == 2

    def test_reimport_updates_existing_host(self):
        # First import: host without hostname
        host1 = _make_host("10.0.0.1", [(22, "ssh")])
        scan1 = _make_scan([host1])
        ingest_scan(scan1, source_name="scanner")

        # Second import: same host with hostname and new service
        host2 = _make_host("10.0.0.1", [(22, "ssh"), (80, "http")], hostname="server1.local")
        scan2 = _make_scan([host2])
        ingest_scan(scan2, source_name="scanner")

        stats = get_graph_stats()
        assert stats["hosts"] == 1
        assert stats["services"] == 2  # ssh + http

        # Verify hostname was updated
        with get_session() as session:
            result = session.run(
                "MATCH (h:Host {ip: '10.0.0.1'}) RETURN h.hostname AS hostname"
            )
            record = result.single()
            assert record["hostname"] == "server1.local"


class TestMultiSourceImport:
    """Test importing from multiple scan sources."""

    def test_two_sources_same_hosts(self):
        host = _make_host("10.0.0.1", [(22, "ssh")])
        scan = _make_scan([host])

        ingest_scan(scan, source_name="scanner-1")
        ingest_scan(scan, source_name="scanner-2")

        stats = get_graph_stats()
        assert stats["hosts"] == 1  # no duplicate hosts
        assert stats["scan_sources"] == 2

        # Verify both SCANNED_FROM edges exist
        with get_session() as session:
            result = session.run(
                "MATCH (src:ScanSource)-[:SCANNED_FROM]->(h:Host {ip: '10.0.0.1'}) "
                "RETURN src.name AS name ORDER BY name"
            )
            sources = [r["name"] for r in result]
            assert sources == ["scanner-1", "scanner-2"]

    def test_different_sources_different_hosts(self):
        host1 = _make_host("10.0.0.1", [(22, "ssh")])
        host2 = _make_host("10.0.1.1", [(80, "http")])

        ingest_scan(_make_scan([host1]), source_name="external")
        ingest_scan(_make_scan([host2]), source_name="internal-pivot")

        stats = get_graph_stats()
        assert stats["hosts"] == 2
        assert stats["scan_sources"] == 2
        assert stats["segments"] == 2  # 10.0.0.0/24 and 10.0.1.0/24


class TestNetworkSegments:
    """Test network segment detection and linking."""

    def test_same_segment(self):
        hosts = [
            _make_host("10.0.0.1", [(22, "ssh")]),
            _make_host("10.0.0.2", [(80, "http")]),
        ]
        scan = _make_scan(hosts)
        ingest_scan(scan, source_name="scanner")

        with get_session() as session:
            result = session.run(
                "MATCH (seg:NetworkSegment) RETURN seg.cidr AS cidr"
            )
            segments = [r["cidr"] for r in result]
            assert segments == ["10.0.0.0/24"]

    def test_multiple_segments(self):
        hosts = [
            _make_host("10.0.0.1", [(22, "ssh")]),
            _make_host("10.0.1.1", [(80, "http")]),
            _make_host("192.168.1.1", [(443, "https")]),
        ]
        scan = _make_scan(hosts)
        ingest_scan(scan, source_name="scanner")

        with get_session() as session:
            result = session.run(
                "MATCH (seg:NetworkSegment) RETURN seg.cidr AS cidr ORDER BY cidr"
            )
            segments = [r["cidr"] for r in result]
            assert len(segments) == 3
            assert "10.0.0.0/24" in segments
            assert "10.0.1.0/24" in segments
            assert "192.168.1.0/24" in segments

    def test_host_linked_to_segment(self):
        host = _make_host("10.0.0.1", [(22, "ssh")])
        ingest_scan(_make_scan([host]), source_name="scanner")

        with get_session() as session:
            result = session.run(
                "MATCH (h:Host {ip: '10.0.0.1'})-[:IN_SEGMENT]->(seg:NetworkSegment) "
                "RETURN seg.cidr AS cidr"
            )
            record = result.single()
            assert record["cidr"] == "10.0.0.0/24"


class TestTraceroute:
    """Test traceroute data ingestion."""

    def test_traceroute_creates_route_through(self):
        host = Host(
            ip="10.0.1.100",
            state="up",
            services=[Service(port=80, state="open", name="http")],
            traceroute=[
                TracerouteHop(ttl=1, ip="10.0.0.1", hostname="gateway"),
                TracerouteHop(ttl=2, ip="10.0.1.1"),
                TracerouteHop(ttl=3, ip="10.0.1.100"),
            ],
        )
        ingest_scan(_make_scan([host]), source_name="scanner")

        with get_session() as session:
            result = session.run(
                "MATCH (target:Host {ip: '10.0.1.100'})-[:ROUTE_THROUGH]->(hop:Host) "
                "RETURN hop.ip AS ip ORDER BY ip"
            )
            hops = [r["ip"] for r in result]
            assert "10.0.0.1" in hops
            assert "10.0.1.1" in hops


class TestRealNmapFile:
    """Test with the sample corporate network XML."""

    def test_corporate_network_import(self):
        scan = parse_nmap_xml("data/samples/corporate_network.xml")
        stats = ingest_scan(scan, source_name="pentest-laptop")

        assert stats["hosts_imported"] == 17  # 18 total, 1 down
        assert stats["services_imported"] > 50

        graph_stats = get_graph_stats()
        # 17 scanned hosts + 2 traceroute hops (gateway + DMZ switch)
        assert graph_stats["hosts"] == 19
        assert graph_stats["scan_sources"] == 1

    def test_corporate_network_segments(self):
        scan = parse_nmap_xml("data/samples/corporate_network.xml")
        ingest_scan(scan, source_name="pentest-laptop")

        with get_session() as session:
            result = session.run(
                "MATCH (seg:NetworkSegment) RETURN seg.cidr AS cidr ORDER BY cidr"
            )
            segments = [r["cidr"] for r in result]
            # Should have 10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24, 10.0.3.0/24
            assert "10.0.1.0/24" in segments
            assert "10.0.2.0/24" in segments
            assert "10.0.3.0/24" in segments

    def test_corporate_network_dc_services(self):
        scan = parse_nmap_xml("data/samples/corporate_network.xml")
        ingest_scan(scan, source_name="pentest-laptop")

        with get_session() as session:
            # DC01 should have Kerberos, LDAP, SMB
            result = session.run(
                "MATCH (h:Host {ip: '10.0.1.10'})-[:HAS_SERVICE]->(s:Service) "
                "RETURN s.port AS port ORDER BY port"
            )
            ports = [r["port"] for r in result]
            assert 88 in ports   # Kerberos
            assert 389 in ports  # LDAP
            assert 445 in ports  # SMB
            assert 636 in ports  # LDAPS

    def test_servicefp_persisted(self):
        """Raw servicefp from nmap must round-trip to Neo4j so a later
        analysis pass can read it without re-scanning.
        """
        fp = 'SF-Port8080-TCP:V=7.92%r(GetRequest,"Set-Cookie: JSESSIONID=X")'
        host = Host(
            ip="10.0.99.1",
            state="up",
            services=[
                Service(port=8080, protocol="tcp", state="open",
                        name="http-proxy", servicefp=fp),
                # No servicefp on this one — confirms absence is also preserved.
                Service(port=22, protocol="tcp", state="open",
                        name="ssh", product="OpenSSH", version="8.9"),
            ],
        )
        ingest_scan(_make_scan([host]), source_name="scanner")

        with get_session() as session:
            result = session.run(
                "MATCH (s:Service {host_ip: '10.0.99.1'}) "
                "RETURN s.port AS port, s.servicefp AS servicefp "
                "ORDER BY port"
            )
            rows = {r["port"]: r["servicefp"] for r in result}
            assert rows[8080] == fp
            assert rows[22] is None


class TestScanDiff:
    """Test scan diff — new/stale detection via timestamps.

    Uses datetime.now() internally (wall-clock), so each ingest_scan()
    call produces a unique timestamp even for the same scan file.
    """

    def test_service_gets_timestamps_on_create(self):
        """Services should have first_seen/last_seen after ingestion."""
        host = _make_host("10.0.0.1", [(22, "ssh"), (80, "http")])
        ingest_scan(_make_scan([host]), source_name="scanner")

        with get_session() as session:
            result = session.run(
                "MATCH (s:Service {host_ip: '10.0.0.1'}) "
                "RETURN s.port AS port, s.first_seen AS first_seen, s.last_seen AS last_seen "
                "ORDER BY port"
            )
            records = list(result)
            assert len(records) == 2
            for r in records:
                assert r["first_seen"] is not None
                assert r["last_seen"] is not None
                assert r["first_seen"] == r["last_seen"]  # is_new

    def test_service_last_seen_updates_on_reimport(self):
        """Re-importing updates last_seen but keeps first_seen."""
        import time

        host = _make_host("10.0.0.1", [(22, "ssh")])
        ingest_scan(_make_scan([host]), source_name="scanner")

        time.sleep(0.01)  # ensure distinct wall-clock timestamps

        ingest_scan(_make_scan([host]), source_name="scanner")

        with get_session() as session:
            r = session.run(
                "MATCH (s:Service {host_ip: '10.0.0.1', port: 22}) "
                "RETURN s.first_seen AS first_seen, s.last_seen AS last_seen"
            ).single()
            assert r["first_seen"] != r["last_seen"]  # NOT new anymore
            assert r["first_seen"] < r["last_seen"]

    def test_new_service_on_rescan(self):
        """A new port appearing on rescan has first_seen == last_seen."""
        import time

        host1 = _make_host("10.0.0.1", [(22, "ssh")])
        ingest_scan(_make_scan([host1]), source_name="scanner")

        time.sleep(0.01)

        # Second scan adds port 80
        host2 = _make_host("10.0.0.1", [(22, "ssh"), (80, "http")])
        ingest_scan(_make_scan([host2]), source_name="scanner")

        with get_session() as session:
            # SSH: existed before → first_seen != last_seen
            r = session.run(
                "MATCH (s:Service {host_ip: '10.0.0.1', port: 22}) "
                "RETURN s.first_seen AS fs, s.last_seen AS ls"
            ).single()
            assert r["fs"] != r["ls"]

            # HTTP: new → first_seen == last_seen
            r = session.run(
                "MATCH (s:Service {host_ip: '10.0.0.1', port: 80}) "
                "RETURN s.first_seen AS fs, s.last_seen AS ls"
            ).single()
            assert r["fs"] == r["ls"]

    def test_stale_service_detection(self):
        """Service not in second scan has last_seen < host.last_seen (stale)."""
        import time

        # First scan: host has SSH + HTTP
        host1 = _make_host("10.0.0.1", [(22, "ssh"), (80, "http")])
        ingest_scan(_make_scan([host1]), source_name="scanner")

        time.sleep(0.01)

        # Second scan: host only has SSH (HTTP gone)
        host2 = _make_host("10.0.0.1", [(22, "ssh")])
        ingest_scan(_make_scan([host2]), source_name="scanner")

        with get_session() as session:
            # SSH: re-scanned → last_seen == host.last_seen
            ssh = session.run(
                "MATCH (s:Service {host_ip: '10.0.0.1', port: 22}) "
                "RETURN s.last_seen AS ls"
            ).single()
            host = session.run(
                "MATCH (h:Host {ip: '10.0.0.1'}) RETURN h.last_seen AS ls"
            ).single()
            assert ssh["ls"] == host["ls"]

            # HTTP: stale → last_seen < host.last_seen
            http = session.run(
                "MATCH (s:Service {host_ip: '10.0.0.1', port: 80}) "
                "RETURN s.last_seen AS ls"
            ).single()
            assert http["ls"] < host["ls"]

    def test_new_host_detection(self):
        """Host appearing for the first time has first_seen == last_seen."""
        import time

        host1 = _make_host("10.0.0.1", [(22, "ssh")])
        ingest_scan(_make_scan([host1]), source_name="scanner")

        time.sleep(0.01)

        # Second scan: original host + new host
        host2a = _make_host("10.0.0.1", [(22, "ssh")])
        host2b = _make_host("10.0.0.2", [(80, "http")])
        ingest_scan(_make_scan([host2a, host2b]), source_name="scanner")

        with get_session() as session:
            # Old host: first_seen != last_seen
            r = session.run(
                "MATCH (h:Host {ip: '10.0.0.1'}) RETURN h.first_seen AS fs, h.last_seen AS ls"
            ).single()
            assert r["fs"] != r["ls"]

            # New host: first_seen == last_seen
            r = session.run(
                "MATCH (h:Host {ip: '10.0.0.2'}) RETURN h.first_seen AS fs, h.last_seen AS ls"
            ).single()
            assert r["fs"] == r["ls"]


class TestRoleDistribution:
    """Test role distribution query."""

    def test_all_unknown_before_classification(self):
        hosts = [
            _make_host("10.0.0.1", [(22, "ssh"), (80, "http")]),
            _make_host("10.0.0.2", [(445, "microsoft-ds")]),
        ]
        ingest_scan(_make_scan(hosts), source_name="scanner")

        roles = get_host_role_distribution()
        assert roles.get("unknown", 0) == 2

    def test_empty_graph_returns_empty(self):
        roles = get_host_role_distribution()
        assert roles == {}


class TestDomainControllerAutoTarget:
    """Regression: classify_graph_hosts must respect the operator's explicit
    target decisions for domain controllers.

    The old behaviour re-set ``target = true`` on every DC on every boil,
    stomping over anyone who deliberately untargeted one. The fix tracks
    operator intent via ``target_manual``: once the operator has touched
    the target flag, the classifier leaves it alone.
    """

    def _ingest_dc(self, ip: str = "10.0.0.10") -> None:
        dc = _make_host(
            ip,
            [(88, "kerberos"), (389, "ldap"), (445, "microsoft-ds"), (636, "ldaps")],
        )
        ingest_scan(_make_scan([dc]), source_name="scanner")

    def test_dc_auto_targets_on_first_classification(self):
        from cauldron.graph.ingestion import classify_graph_hosts

        self._ingest_dc()
        classify_graph_hosts()

        with get_session() as session:
            r = session.run(
                "MATCH (h:Host {ip: '10.0.0.10'}) "
                "RETURN h.target AS target, h.target_manual AS manual",
            ).single()
            assert r["target"] is True
            # target_manual untouched — auto-defaulted, operator can override.
            assert r["manual"] is None

    def test_manual_untarget_survives_reclassification(self):
        from cauldron.graph.ingestion import classify_graph_hosts, set_host_target

        self._ingest_dc()
        classify_graph_hosts()  # auto-targets the DC

        set_host_target("10.0.0.10", False)  # operator says "not a target"
        classify_graph_hosts()  # boil again

        with get_session() as session:
            r = session.run(
                "MATCH (h:Host {ip: '10.0.0.10'}) "
                "RETURN h.target AS target, h.target_manual AS manual",
            ).single()
            assert r["target"] is False
            assert r["manual"] is True

    def test_manual_retarget_also_sticky(self):
        from cauldron.graph.ingestion import classify_graph_hosts, set_host_target

        self._ingest_dc()
        classify_graph_hosts()
        set_host_target("10.0.0.10", False)
        set_host_target("10.0.0.10", True)  # operator flips back
        classify_graph_hosts()

        with get_session() as session:
            r = session.run(
                "MATCH (h:Host {ip: '10.0.0.10'}) "
                "RETURN h.target AS target, h.target_manual AS manual",
            ).single()
            assert r["target"] is True
            assert r["manual"] is True

    def test_owning_a_dc_locks_target_off(self):
        """set_host_owned(True) clears target AND raises target_manual so
        the next boil does not auto-retarget a host the operator already
        compromised."""
        from cauldron.graph.ingestion import classify_graph_hosts, set_host_owned

        self._ingest_dc()
        classify_graph_hosts()  # auto-target
        set_host_owned("10.0.0.10", True)  # goal achieved
        classify_graph_hosts()  # boil should NOT re-target

        with get_session() as session:
            r = session.run(
                "MATCH (h:Host {ip: '10.0.0.10'}) "
                "RETURN h.target AS target, h.target_manual AS manual, "
                "h.owned AS owned",
            ).single()
            assert r["owned"] is True
            assert r["target"] is False
            assert r["manual"] is True


class TestVersionChangeInvalidatesVulns:
    """Regression: on re-import, a service whose product or version changed
    must lose its stale auto-derived vulnerability links. User-annotated
    edges (exploited / false_positive / mitigated) survive — those are
    historical engagement verdicts, not re-derivable from the scan.
    """

    def _fixture(self):
        """Host with Apache 2.4.49 on :80, two vulns attached: one NVD
        auto-derived, one operator-marked as exploited."""
        host = _make_host("10.0.0.20")
        host.services = [
            Service(port=80, protocol="tcp", state="open",
                    name="http", product="Apache httpd", version="2.4.49"),
        ]
        ingest_scan(_make_scan([host]), source_name="scanner")

        with get_session() as session:
            session.run(
                """
                MATCH (s:Service {host_ip: '10.0.0.20', port: 80})
                MERGE (v1:Vulnerability {cve_id: 'CVE-2021-41773'})
                  ON CREATE SET v1.source = 'nvd', v1.cvss = 9.8
                MERGE (v2:Vulnerability {cve_id: 'CVE-2021-42013'})
                  ON CREATE SET v2.source = 'nvd', v2.cvss = 9.8
                MERGE (s)-[:HAS_VULN]->(v1)
                MERGE (s)-[r:HAS_VULN]->(v2)
                  SET r.checked_status = 'exploited'
                """,
            )

    def _reimport_patched(self, new_version: str):
        """Re-ingest the same service with a newer (patched) version."""
        host = _make_host("10.0.0.20")
        host.services = [
            Service(port=80, protocol="tcp", state="open",
                    name="http", product="Apache httpd", version=new_version),
        ]
        ingest_scan(_make_scan([host]), source_name="scanner")

    def test_version_change_drops_stale_auto_vulns(self):
        self._fixture()
        self._reimport_patched("2.4.54")

        with get_session() as session:
            r = session.run(
                "MATCH (s:Service {host_ip: '10.0.0.20', port: 80}) "
                "RETURN s.version AS version",
            ).single()
            assert r["version"] == "2.4.54"

            # Auto-derived CVE-2021-41773 was cleared.
            rows = list(session.run(
                """
                MATCH (s:Service {host_ip: '10.0.0.20'})-[:HAS_VULN]->(v:Vulnerability)
                RETURN v.cve_id AS id
                """,
            ))
            cves = {row["id"] for row in rows}
            assert "CVE-2021-41773" not in cves, \
                "stale auto-vuln must be cleared on version change"

    def test_operator_annotated_vulns_survive(self):
        self._fixture()
        self._reimport_patched("2.4.54")

        with get_session() as session:
            rows = list(session.run(
                """
                MATCH (s:Service {host_ip: '10.0.0.20'})-[r:HAS_VULN]->(v:Vulnerability)
                RETURN v.cve_id AS id, r.checked_status AS status
                """,
            ))
            surviving = {row["id"]: row["status"] for row in rows}
            # Operator-marked 'exploited' is engagement history — must survive.
            assert surviving.get("CVE-2021-42013") == "exploited"

    def test_same_version_keeps_all_vulns(self):
        """Re-import with identical product+version is a no-op for vuln
        invalidation — nothing changed, nothing to clear."""
        self._fixture()
        self._reimport_patched("2.4.49")  # same version

        with get_session() as session:
            rows = list(session.run(
                """
                MATCH (s:Service {host_ip: '10.0.0.20'})-[:HAS_VULN]->(v:Vulnerability)
                RETURN v.cve_id AS id
                """,
            ))
            cves = {row["id"] for row in rows}
            assert cves == {"CVE-2021-41773", "CVE-2021-42013"}

    def test_version_detection_lost_keeps_old_vulns(self):
        """Edge case: new scan failed to detect version (nmap returned None).
        COALESCE preserves the old version, and since the stored product/
        version didn't actually change, vuln links are not invalidated.
        Prevents losing intel when a scan is less thorough than the last one.
        """
        self._fixture()

        host = _make_host("10.0.0.20")
        host.services = [
            Service(port=80, protocol="tcp", state="open",
                    name="http", product="Apache httpd", version=None),
        ]
        ingest_scan(_make_scan([host]), source_name="scanner")

        with get_session() as session:
            r = session.run(
                "MATCH (s:Service {host_ip: '10.0.0.20', port: 80}) "
                "RETURN s.version AS version",
            ).single()
            assert r["version"] == "2.4.49"  # old value preserved

            rows = list(session.run(
                """
                MATCH (s:Service {host_ip: '10.0.0.20'})-[:HAS_VULN]->(v:Vulnerability)
                RETURN v.cve_id AS id
                """,
            ))
            cves = {row["id"] for row in rows}
            assert cves == {"CVE-2021-41773", "CVE-2021-42013"}


class TestScriptConfidenceIsPerEdge:
    """Regression: script-confirmed confidence must NOT leak across hosts.

    Before: v.confidence lived on the Vulnerability node, shared by cve_id.
    An ms17-010 script confirming on host A set v.confidence='confirmed'
    globally, so host B (never scripted) also showed 'confirmed'.

    After: confidence lives on the HAS_VULN edge. Upgrade on host A
    stays on host A; host B keeps its original rule-level confidence.
    """

    def _two_hosts_sharing_cve(self):
        with get_session() as session:
            session.run("""
                CREATE (a:Host {ip: '10.0.0.101', state: 'up'})
                CREATE (a)-[:HAS_SERVICE]->(sa:Service {
                    host_ip: '10.0.0.101', port: 445, protocol: 'tcp'
                })
                CREATE (b:Host {ip: '10.0.0.102', state: 'up'})
                CREATE (b)-[:HAS_SERVICE]->(sb:Service {
                    host_ip: '10.0.0.102', port: 445, protocol: 'tcp'
                })
                MERGE (v:Vulnerability {cve_id: 'CVE-2017-0144'})
                  ON CREATE SET v.source = 'nvd', v.has_exploit = true
                MERGE (sa)-[ra:HAS_VULN]->(v)
                  ON CREATE SET ra.confidence = 'check'
                MERGE (sb)-[rb:HAS_VULN]->(v)
                  ON CREATE SET rb.confidence = 'check'
                SET sa.`script_smb_vuln_ms17_010` = 'VULNERABLE'
            """)

    def test_script_upgrade_does_not_leak_to_sibling_host(self):
        from cauldron.exploits.matcher import upgrade_confidence_from_scripts

        self._two_hosts_sharing_cve()
        upgrade_confidence_from_scripts()

        with get_session() as session:
            r = session.run("""
                MATCH (sa:Service {host_ip: '10.0.0.101'})-[ra:HAS_VULN]->(:Vulnerability {cve_id: 'CVE-2017-0144'})
                MATCH (sb:Service {host_ip: '10.0.0.102'})-[rb:HAS_VULN]->(:Vulnerability {cve_id: 'CVE-2017-0144'})
                RETURN ra.confidence AS a_conf, rb.confidence AS b_conf
            """).single()

            assert r["a_conf"] == "confirmed"
            assert r["b_conf"] == "check"

    def test_migration_backfills_existing_node_confidence(self):
        """Old graphs stored confidence on the Vulnerability node. At the
        start of every match_from_graph run we copy node → edge for any
        edge that doesn't have confidence yet — idempotent, safe."""
        from cauldron.exploits.matcher import ExploitDB

        with get_session() as session:
            session.run("""
                CREATE (h:Host {ip: '10.0.0.200', state: 'up'})
                CREATE (h)-[:HAS_SERVICE]->(s:Service {
                    host_ip: '10.0.0.200', port: 443, protocol: 'tcp'
                })
                CREATE (v:Vulnerability {cve_id: 'CVE-LEGACY-1',
                                         source: 'nvd', confidence: 'likely'})
                CREATE (s)-[:HAS_VULN]->(v)
            """)

        ExploitDB().match_from_graph()

        with get_session() as session:
            r = session.run("""
                MATCH ()-[r:HAS_VULN]->(:Vulnerability {cve_id: 'CVE-LEGACY-1'})
                RETURN r.confidence AS conf
            """).single()
            assert r["conf"] == "likely"
