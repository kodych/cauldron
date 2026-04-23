"""Tests for the REST API (FastAPI)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cauldron.graph.connection import clear_database, get_session, verify_connection

# Only run if Neo4j is available
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


@pytest.fixture()
def client():
    """FastAPI test client."""
    from cauldron.api.server import app
    return TestClient(app)


def _setup_test_network():
    """Create a small test network for API testing.

    Hosts:
      - DC01 (10.0.1.10): 88, 389, 445 — domain_controller
      - WEB01 (10.0.1.20): 80, 443 — web_server
      - DB01 (10.0.1.30): 3306 — database
    ScanSource: scanner1 -> all hosts
    Vulnerability on WEB01 port 80
    """
    with get_session() as session:
        session.run("CREATE (:ScanSource {name: 'scanner1'})")

        session.run("""
            CREATE (h:Host {ip: '10.0.1.10', hostname: 'DC01', role: 'domain_controller',
                           role_confidence: 0.95, os_name: 'Windows Server 2019', state: 'up'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {host_ip: '10.0.1.10', port: 88, protocol: 'tcp', state: 'open', name: 'kerberos'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {host_ip: '10.0.1.10', port: 389, protocol: 'tcp', state: 'open', name: 'ldap'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {host_ip: '10.0.1.10', port: 445, protocol: 'tcp', state: 'open', name: 'microsoft-ds'})
        """)

        session.run("""
            CREATE (h:Host {ip: '10.0.1.20', hostname: 'WEB01', role: 'web_server',
                           role_confidence: 0.90, os_name: 'Ubuntu 22.04', state: 'up'})
            CREATE (h)-[:HAS_SERVICE]->(s:Service {host_ip: '10.0.1.20', port: 80, protocol: 'tcp', state: 'open', name: 'http', product: 'Apache httpd', version: '2.4.49'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {host_ip: '10.0.1.20', port: 443, protocol: 'tcp', state: 'open', name: 'https'})
            CREATE (s)-[:HAS_VULN]->(:Vulnerability {
                cve_id: 'CVE-2021-41773', cvss: 7.5, has_exploit: true,
                confidence: 'confirmed', enables_pivot: true,
                description: 'Apache path traversal and RCE'
            })
        """)

        session.run("""
            CREATE (h:Host {ip: '10.0.1.30', hostname: 'DB01', role: 'database',
                           role_confidence: 0.85, state: 'up'})
            CREATE (h)-[:HAS_SERVICE]->(:Service {host_ip: '10.0.1.30', port: 3306, protocol: 'tcp', state: 'open', name: 'mysql', product: 'MySQL', version: '5.7.40'})
        """)

        # Network segment
        session.run("CREATE (:NetworkSegment {cidr: '10.0.1.0/24'})")
        for ip in ["10.0.1.10", "10.0.1.20", "10.0.1.30"]:
            session.run(
                "MATCH (h:Host {ip: $ip}), (seg:NetworkSegment {cidr: '10.0.1.0/24'}) "
                "CREATE (h)-[:IN_SEGMENT]->(seg)",
                ip=ip,
            )

        # SCANNED_FROM
        for ip in ["10.0.1.10", "10.0.1.20", "10.0.1.30"]:
            session.run(
                "MATCH (src:ScanSource {name: 'scanner1'}), (h:Host {ip: $ip}) "
                "CREATE (src)-[:SCANNED_FROM]->(h)",
                ip=ip,
            )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestStats:
    def test_stats_empty(self, client):
        resp = client.get("/api/v1/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["hosts"] == 0
        assert data["services"] == 0

    def test_stats_with_data(self, client):
        _setup_test_network()
        resp = client.get("/api/v1/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["hosts"] == 3
        assert data["services"] == 6  # DC01: 3, WEB01: 2, DB01: 1
        assert data["segments"] == 1
        assert data["scan_sources"] == 1
        assert "domain_controller" in data["roles"]


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------

class TestHosts:
    def test_list_hosts_empty(self, client):
        resp = client.get("/api/v1/hosts")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_list_hosts(self, client):
        _setup_test_network()
        resp = client.get("/api/v1/hosts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(data["hosts"]) == 3

    def test_list_hosts_filter_role(self, client):
        _setup_test_network()
        resp = client.get("/api/v1/hosts?role=database")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["hosts"][0]["ip"] == "10.0.1.30"

    def test_list_hosts_pagination(self, client):
        _setup_test_network()
        resp = client.get("/api/v1/hosts?limit=2&offset=0")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(data["hosts"]) == 2

    def test_get_host_detail(self, client):
        _setup_test_network()
        resp = client.get("/api/v1/hosts/10.0.1.20")
        assert resp.status_code == 200
        host = resp.json()
        assert host["ip"] == "10.0.1.20"
        assert host["hostname"] == "WEB01"
        assert host["role"] == "web_server"
        assert len(host["services"]) == 2
        assert len(host["vulnerabilities"]) == 1
        assert host["vulnerabilities"][0]["cve_id"] == "CVE-2021-41773"

    def test_get_host_not_found(self, client):
        resp = client.get("/api/v1/hosts/192.168.99.99")
        assert resp.status_code == 404

    def test_host_has_segment(self, client):
        _setup_test_network()
        resp = client.get("/api/v1/hosts/10.0.1.10")
        assert resp.json()["segment"] == "10.0.1.0/24"


# ---------------------------------------------------------------------------
# Attack Paths
# ---------------------------------------------------------------------------

class TestAttackPaths:
    def test_paths_empty(self, client):
        resp = client.get("/api/v1/attack-paths")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["paths"]) == 0

    def test_paths_with_vuln(self, client):
        _setup_test_network()
        resp = client.get("/api/v1/attack-paths")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["paths"]) >= 1
        # WEB01 should appear as target
        target_ips = [p["nodes"][-1]["ip"] for p in data["paths"]]
        assert "10.0.1.20" in target_ips

    def test_paths_summary_populated(self, client):
        _setup_test_network()
        resp = client.get("/api/v1/attack-paths")
        data = resp.json()
        assert "vulnerable_hosts" in data["summary"]
        assert data["summary"]["vulnerable_hosts"] >= 1

    def test_paths_filter_role(self, client):
        _setup_test_network()
        resp = client.get("/api/v1/attack-paths?role=web_server")
        data = resp.json()
        for path in data["paths"]:
            assert path["target_role"] == "web_server"

    def test_paths_include_check(self, client):
        _setup_test_network()
        # Add a check-level vuln
        with get_session() as session:
            session.run("""
                MATCH (h:Host {ip: '10.0.1.30'})-[:HAS_SERVICE]->(s:Service {port: 3306})
                CREATE (s)-[:HAS_VULN]->(:Vulnerability {
                    cve_id: 'CAULDRON-042', cvss: 5.0,
                    confidence: 'check', has_exploit: false
                })
            """)
        # Without include_check: only confirmed/likely
        resp1 = client.get("/api/v1/attack-paths")
        # With include_check
        resp2 = client.get("/api/v1/attack-paths?include_check=true")
        assert len(resp2.json()["paths"]) >= len(resp1.json()["paths"])


# ---------------------------------------------------------------------------
# Collect
# ---------------------------------------------------------------------------

class TestCollect:
    def test_collect_no_params(self, client):
        resp = client.get("/api/v1/collect")
        assert resp.status_code == 400

    def test_collect_smb(self, client):
        _setup_test_network()
        resp = client.get("/api/v1/collect?filter=smb")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["hosts"][0]["ip"] == "10.0.1.10"

    def test_collect_http(self, client):
        _setup_test_network()
        resp = client.get("/api/v1/collect?filter=http")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_collect_by_port(self, client):
        _setup_test_network()
        resp = client.get("/api/v1/collect?port=3306")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["filter_used"] == "port:3306"

    def test_collect_by_role(self, client):
        _setup_test_network()
        resp = client.get("/api/v1/collect?role=database")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_collect_invalid_filter(self, client):
        resp = client.get("/api/v1/collect?filter=nonexistent")
        assert resp.status_code == 400

    def test_collect_filters_list(self, client):
        resp = client.get("/api/v1/collect/filters")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) > 10
        names = [f["name"] for f in data]
        assert "smb" in names


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------

class TestGraph:
    def test_graph_empty(self, client):
        resp = client.get("/api/v1/graph")
        assert resp.status_code == 200
        data = resp.json()
        assert data["nodes"] == []
        assert data["edges"] == []

    def test_graph_with_data(self, client):
        _setup_test_network()
        resp = client.get("/api/v1/graph")
        assert resp.status_code == 200
        data = resp.json()
        # Should have host nodes, segment node, source node
        types = {n["type"] for n in data["nodes"]}
        assert "host" in types
        assert "segment" in types
        assert "scan_source" in types
        # Should have edges
        edge_types = {e["type"] for e in data["edges"]}
        assert "IN_SEGMENT" in edge_types
        assert "SCANNED_FROM" in edge_types

    def test_graph_limit(self, client):
        _setup_test_network()
        resp = client.get("/api/v1/graph?limit=1")
        assert resp.status_code == 200
        host_nodes = [n for n in resp.json()["nodes"] if n["type"] == "host"]
        assert len(host_nodes) == 1

    def test_graph_merges_pivot_host_with_scan_source(self, client):
        """When ScanSource.name matches Host.ip, they merge into one node."""
        with get_session() as session:
            # External scan finds host 10.0.1.10
            session.run("""
                CREATE (src:ScanSource {name: 'external'})
                CREATE (h:Host {ip: '10.0.1.10', role: 'web_server', state: 'up'})
                CREATE (src)-[:SCANNED_FROM]->(h)
            """)
            # Internal scan FROM 10.0.1.10 finds host 10.0.2.20
            session.run("""
                CREATE (src:ScanSource {name: '10.0.1.10'})
                CREATE (h:Host {ip: '10.0.2.20', role: 'database', state: 'up'})
                CREATE (src)-[:SCANNED_FROM]->(h)
            """)
            # External scan also scanned 10.0.2.20 (edge case)
            session.run("""
                MATCH (src:ScanSource {name: 'external'}), (h:Host {ip: '10.0.2.20'})
                CREATE (src)-[:SCANNED_FROM]->(h)
            """)

        resp = client.get("/api/v1/graph")
        data = resp.json()

        # Should NOT have a separate scan_source node for "10.0.1.10"
        node_ids = [n["id"] for n in data["nodes"]]
        assert "source:10.0.1.10" not in node_ids
        # Host node should exist and be marked as scan source
        host_node = next(n for n in data["nodes"] if n["id"] == "host:10.0.1.10")
        assert host_node["properties"]["is_scan_source"] is True
        # External scanner should still be a separate scan_source
        assert "source:external" in node_ids
        # No self-edge from host:10.0.1.10 to host:10.0.1.10
        for edge in data["edges"]:
            assert not (edge["source"] == "host:10.0.1.10" and edge["target"] == "host:10.0.1.10")


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------

class TestTopology:
    def test_topology_empty(self, client):
        resp = client.get("/api/v1/topology")
        assert resp.status_code == 200
        data = resp.json()
        assert data["segments"] == []

    def test_topology_with_data(self, client):
        _setup_test_network()
        resp = client.get("/api/v1/topology")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["segments"]) >= 1
        assert data["segments"][0]["cidr"] == "10.0.1.0/24"
        assert data["segments"][0]["hosts"] == 3


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------

class TestImport:
    def test_import_nmap_xml(self, client):
        """Test importing a simple nmap XML via API."""
        xml_content = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV 10.0.1.0/24" start="1700000000">
  <host starttime="1700000000" endtime="1700000001">
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.1.100" addrtype="ipv4"/>
    <hostnames><hostname name="APITEST" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        resp = client.post(
            "/api/v1/import",
            files={"file": ("test.xml", xml_content, "application/xml")},
            params={"source": "api_test"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["hosts_imported"] == 1
        assert data["services_imported"] == 1

        # Verify host is in the graph
        host_resp = client.get("/api/v1/hosts/10.0.1.100")
        assert host_resp.status_code == 200
        assert host_resp.json()["hostname"] == "APITEST"

    def test_import_empty_file(self, client):
        resp = client.post(
            "/api/v1/import",
            files={"file": ("empty.xml", b"", "application/xml")},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Analyze
# ---------------------------------------------------------------------------

class TestAnalyze:
    def test_analyze_empty_graph(self, client):
        """Analysis on empty graph should succeed with zero counts."""
        resp = client.post("/api/v1/analyze")
        assert resp.status_code == 200
        data = resp.json()
        assert data["classification"]["total"] == 0
        assert data["exploits"]["exploits_found"] == 0

    def test_analyze_with_data(self, client):
        _setup_test_network()
        resp = client.post("/api/v1/analyze")
        assert resp.status_code == 200
        data = resp.json()
        assert data["classification"]["total"] == 3
        assert data["path_summary"]["vulnerable_hosts"] >= 1


# ---------------------------------------------------------------------------
# OpenAPI docs
# ---------------------------------------------------------------------------

class TestDocs:
    def test_openapi_schema(self, client):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        assert schema["info"]["title"] == "Cauldron API"
        assert "/api/v1/stats" in schema["paths"]

    def test_docs_page(self, client):
        resp = client.get("/docs")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Vulnerability checked status
# ---------------------------------------------------------------------------

class TestVulnStatus:
    def test_update_vuln_status(self, client):
        _setup_test_network()
        resp = client.patch(
            "/api/v1/hosts/10.0.1.20/vulns/CVE-2021-41773/status",
            json={"status": "exploited"},
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        # Verify status persisted
        resp = client.get("/api/v1/hosts/10.0.1.20")
        assert resp.status_code == 200
        vulns = resp.json()["vulnerabilities"]
        assert any(v["checked_status"] == "exploited" for v in vulns)

    def test_clear_vuln_status(self, client):
        _setup_test_network()
        # Set then clear
        client.patch(
            "/api/v1/hosts/10.0.1.20/vulns/CVE-2021-41773/status",
            json={"status": "exploited"},
        )
        resp = client.patch(
            "/api/v1/hosts/10.0.1.20/vulns/CVE-2021-41773/status",
            json={"status": None},
        )
        assert resp.status_code == 200

        resp = client.get("/api/v1/hosts/10.0.1.20")
        vulns = resp.json()["vulnerabilities"]
        for v in vulns:
            if v["cve_id"] == "CVE-2021-41773":
                assert v["checked_status"] is None

    def test_update_nonexistent_vuln(self, client):
        _setup_test_network()
        resp = client.patch(
            "/api/v1/hosts/10.0.1.20/vulns/CVE-9999-9999/status",
            json={"status": "exploited"},
        )
        assert resp.status_code == 404

    def test_invalid_status_value(self, client):
        _setup_test_network()
        resp = client.patch(
            "/api/v1/hosts/10.0.1.20/vulns/CVE-2021-41773/status",
            json={"status": "invalid_status"},
        )
        assert resp.status_code == 400


class TestBruteforceable:
    def test_toggle_bruteforceable(self, client):
        _setup_test_network()
        # Mark SMB port 445 on DC01 as bruteforceable
        resp = client.patch(
            "/api/v1/hosts/10.0.1.10/services/445/bruteforceable",
            json={"bruteforceable": True},
        )
        assert resp.status_code == 200

        # Verify via host detail
        resp = client.get("/api/v1/hosts/10.0.1.10")
        services = resp.json()["services"]
        smb = [s for s in services if s["port"] == 445]
        assert len(smb) == 1
        assert smb[0]["bruteforceable"] is True

    def test_unmark_bruteforceable(self, client):
        _setup_test_network()
        # Mark then unmark
        client.patch(
            "/api/v1/hosts/10.0.1.10/services/445/bruteforceable",
            json={"bruteforceable": True},
        )
        resp = client.patch(
            "/api/v1/hosts/10.0.1.10/services/445/bruteforceable",
            json={"bruteforceable": False},
        )
        assert resp.status_code == 200

        resp = client.get("/api/v1/hosts/10.0.1.10")
        services = resp.json()["services"]
        smb = [s for s in services if s["port"] == 445]
        assert smb[0]["bruteforceable"] is False

    def test_bruteforceable_nonexistent_service(self, client):
        _setup_test_network()
        resp = client.patch(
            "/api/v1/hosts/10.0.1.10/services/9999/bruteforceable",
            json={"bruteforceable": True},
        )
        assert resp.status_code == 404


class TestScanDiff:
    """Test is_new / is_stale / has_changes fields in API responses.

    Diff indicators only appear when a source has been re-used (imported
    more than once).  First import = baseline, no badges.
    """

    def test_no_badges_on_first_import(self, client):
        """First import is baseline — no NEW/GONE/CHANGED badges."""
        with get_session() as session:
            session.run("""
                CREATE (src:ScanSource {name: 'scanner1',
                                        first_seen: '2026-01-01', last_seen: '2026-01-01'})
                CREATE (h:Host {ip: '10.0.0.1', role: 'unknown', role_confidence: 0.0,
                                first_seen: '2026-01-01', last_seen: '2026-01-01'})
                CREATE (src)-[:SCANNED_FROM]->(h)
                CREATE (h)-[:HAS_SERVICE]->(:Service {
                    host_ip: '10.0.0.1', port: 22, protocol: 'tcp', name: 'ssh',
                    first_seen: '2026-01-01', last_seen: '2026-01-01'
                })
            """)
        resp = client.get("/api/v1/hosts/10.0.0.1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_new"] is False
        assert data["is_stale"] is False
        assert data["has_changes"] is False
        assert data["services"][0]["is_new"] is False
        assert data["services"][0]["is_stale"] is False

    def test_host_not_new_after_rescan(self, client):
        """Hosts seen in multiple scans have is_new=False."""
        with get_session() as session:
            session.run("""
                CREATE (src:ScanSource {name: 'scanner1',
                                        first_seen: '2026-01-01', last_seen: '2026-01-02'})
                CREATE (h:Host {ip: '10.0.0.1', role: 'unknown', role_confidence: 0.0,
                                first_seen: '2026-01-01', last_seen: '2026-01-02'})
                CREATE (src)-[:SCANNED_FROM]->(h)
                CREATE (h)-[:HAS_SERVICE]->(:Service {
                    host_ip: '10.0.0.1', port: 22, protocol: 'tcp', name: 'ssh',
                    first_seen: '2026-01-01', last_seen: '2026-01-02'
                })
            """)
        resp = client.get("/api/v1/hosts/10.0.0.1")
        data = resp.json()
        assert data["is_new"] is False
        assert data["services"][0]["is_new"] is False

    def test_new_host_on_rescan(self, client):
        """Host appearing only in second scan has is_new=True."""
        with get_session() as session:
            session.run("""
                CREATE (src:ScanSource {name: 'scanner1',
                                        first_seen: '2026-01-01', last_seen: '2026-01-02'})
                CREATE (h1:Host {ip: '10.0.0.1', role: 'unknown', role_confidence: 0.0,
                                first_seen: '2026-01-01', last_seen: '2026-01-02'})
                CREATE (h2:Host {ip: '10.0.0.2', role: 'unknown', role_confidence: 0.0,
                                first_seen: '2026-01-02', last_seen: '2026-01-02'})
                CREATE (src)-[:SCANNED_FROM]->(h1)
                CREATE (src)-[:SCANNED_FROM]->(h2)
            """)
        resp = client.get("/api/v1/hosts/10.0.0.2")
        data = resp.json()
        assert data["is_new"] is True
        assert data["is_stale"] is False

    def test_stale_host_detection(self, client):
        """Host not in latest scan has is_stale=True."""
        with get_session() as session:
            # Same scan source scanned both hosts, then re-scanned only host A
            session.run("""
                CREATE (src:ScanSource {name: 'scanner1',
                                        first_seen: '2026-01-01', last_seen: '2026-01-02'})
                CREATE (h1:Host {ip: '10.0.0.1', role: 'unknown', role_confidence: 0.0,
                               first_seen: '2026-01-01', last_seen: '2026-01-02'})
                CREATE (h2:Host {ip: '10.0.0.2', role: 'unknown', role_confidence: 0.0,
                               first_seen: '2026-01-01', last_seen: '2026-01-01'})
                CREATE (src)-[:SCANNED_FROM]->(h1)
                CREATE (src)-[:SCANNED_FROM]->(h2)
            """)
        resp = client.get("/api/v1/hosts/10.0.0.2")
        data = resp.json()
        assert data["is_stale"] is True
        assert data["is_new"] is False

    def test_service_is_stale(self, client):
        """Service not re-scanned has is_stale=True."""
        with get_session() as session:
            session.run("""
                CREATE (src:ScanSource {name: 'scanner1',
                                        first_seen: '2026-01-01', last_seen: '2026-01-02'})
                CREATE (h:Host {ip: '10.0.0.1', role: 'unknown', role_confidence: 0.0,
                                first_seen: '2026-01-01', last_seen: '2026-01-02'})
                CREATE (src)-[:SCANNED_FROM]->(h)
                CREATE (h)-[:HAS_SERVICE]->(:Service {
                    host_ip: '10.0.0.1', port: 22, protocol: 'tcp', name: 'ssh',
                    first_seen: '2026-01-01', last_seen: '2026-01-02'
                })
                CREATE (h)-[:HAS_SERVICE]->(:Service {
                    host_ip: '10.0.0.1', port: 80, protocol: 'tcp', name: 'http',
                    first_seen: '2026-01-01', last_seen: '2026-01-01'
                })
            """)
        resp = client.get("/api/v1/hosts/10.0.0.1")
        data = resp.json()
        services = {s["port"]: s for s in data["services"]}
        assert services[22]["is_stale"] is False  # re-scanned
        assert services[80]["is_stale"] is True   # gone
        assert data["has_changes"] is True  # host has stale service

    def test_new_service_on_existing_host(self, client):
        """New port on re-scanned host: service is_new=True, host has_changes=True."""
        with get_session() as session:
            session.run("""
                CREATE (src:ScanSource {name: 'scanner1',
                                        first_seen: '2026-01-01', last_seen: '2026-01-02'})
                CREATE (h:Host {ip: '10.0.0.1', role: 'unknown', role_confidence: 0.0,
                                first_seen: '2026-01-01', last_seen: '2026-01-02'})
                CREATE (src)-[:SCANNED_FROM]->(h)
                CREATE (h)-[:HAS_SERVICE]->(:Service {
                    host_ip: '10.0.0.1', port: 22, protocol: 'tcp', name: 'ssh',
                    first_seen: '2026-01-01', last_seen: '2026-01-02'
                })
                CREATE (h)-[:HAS_SERVICE]->(:Service {
                    host_ip: '10.0.0.1', port: 80, protocol: 'tcp', name: 'http',
                    first_seen: '2026-01-02', last_seen: '2026-01-02'
                })
            """)
        resp = client.get("/api/v1/hosts/10.0.0.1")
        data = resp.json()
        assert data["is_new"] is False
        assert data["has_changes"] is True
        services = {s["port"]: s for s in data["services"]}
        assert services[22]["is_new"] is False  # existed before
        assert services[80]["is_new"] is True   # new port

    def test_pivot_hosts_show_as_new(self, client):
        """Hosts from a pivot (new source) are NEW to the graph."""
        with get_session() as session:
            # Source A imported Jan 1 (baseline), Source B (pivot) imported Jan 2
            session.run("""
                CREATE (srcA:ScanSource {name: 'scannerA',
                                         first_seen: '2026-01-01', last_seen: '2026-01-01'})
                CREATE (srcB:ScanSource {name: 'scannerB',
                                         first_seen: '2026-01-02', last_seen: '2026-01-02'})
                CREATE (h1:Host {ip: '10.0.0.1', role: 'unknown', role_confidence: 0.0,
                                 first_seen: '2026-01-01', last_seen: '2026-01-01'})
                CREATE (h2:Host {ip: '10.0.1.1', role: 'unknown', role_confidence: 0.0,
                                 first_seen: '2026-01-02', last_seen: '2026-01-02'})
                CREATE (srcA)-[:SCANNED_FROM]->(h1)
                CREATE (srcB)-[:SCANNED_FROM]->(h2)
            """)
        resp = client.get("/api/v1/hosts")
        hosts = {h["ip"]: h for h in resp.json()["hosts"]}
        # Source A hosts = baseline → not new
        assert hosts["10.0.0.1"]["is_new"] is False
        assert hosts["10.0.0.1"]["is_stale"] is False
        # Source B hosts = new to the graph (first_seen > baseline)
        assert hosts["10.0.1.1"]["is_new"] is True
        assert hosts["10.0.1.1"]["is_stale"] is False

    def test_pivot_does_not_mark_other_source_as_gone(self, client):
        """Importing from source B must not mark source A hosts as GONE."""
        with get_session() as session:
            session.run("""
                CREATE (srcA:ScanSource {name: 'scannerA',
                                         first_seen: '2026-01-01', last_seen: '2026-01-01'})
                CREATE (srcB:ScanSource {name: 'scannerB',
                                         first_seen: '2026-01-02', last_seen: '2026-01-02'})
                CREATE (h1:Host {ip: '10.0.0.1', role: 'unknown', role_confidence: 0.0,
                                 first_seen: '2026-01-01', last_seen: '2026-01-01'})
                CREATE (h2:Host {ip: '10.0.1.1', role: 'unknown', role_confidence: 0.0,
                                 first_seen: '2026-01-02', last_seen: '2026-01-02'})
                CREATE (srcA)-[:SCANNED_FROM]->(h1)
                CREATE (srcB)-[:SCANNED_FROM]->(h2)
            """)
        resp = client.get("/api/v1/hosts/10.0.0.1")
        data = resp.json()
        assert data["is_stale"] is False, "Pivot must not mark other source's hosts as GONE"

    def test_rescan_shows_gone_and_new(self, client):
        """Re-scanning same source: missing host=GONE, new host=NEW."""
        with get_session() as session:
            session.run("""
                CREATE (src:ScanSource {name: 'scanner1',
                                        first_seen: '2026-01-01', last_seen: '2026-01-02'})
                CREATE (h1:Host {ip: '10.0.0.1', role: 'unknown', role_confidence: 0.0,
                                 first_seen: '2026-01-01', last_seen: '2026-01-02'})
                CREATE (h2:Host {ip: '10.0.0.2', role: 'unknown', role_confidence: 0.0,
                                 first_seen: '2026-01-01', last_seen: '2026-01-01'})
                CREATE (h3:Host {ip: '10.0.0.3', role: 'unknown', role_confidence: 0.0,
                                 first_seen: '2026-01-02', last_seen: '2026-01-02'})
                CREATE (src)-[:SCANNED_FROM]->(h1)
                CREATE (src)-[:SCANNED_FROM]->(h2)
                CREATE (src)-[:SCANNED_FROM]->(h3)
            """)
        resp = client.get("/api/v1/hosts")
        hosts = {h["ip"]: h for h in resp.json()["hosts"]}
        assert hosts["10.0.0.1"]["is_new"] is False   # rescanned, not new
        assert hosts["10.0.0.1"]["is_stale"] is False
        assert hosts["10.0.0.2"]["is_stale"] is True   # GONE
        assert hosts["10.0.0.3"]["is_new"] is True     # NEW (first_seen > baseline)

    def test_pivot_host_not_stale(self, client):
        """Host used as scan source (pivot) is never stale — it's alive."""
        with get_session() as session:
            # Source "scanner1" scanned 10.0.0.1 twice (re-used)
            # Then user scanned FROM 10.0.0.1 (pivot) — source name = host IP
            # 10.0.0.1 wasn't in the rescan, but it's a pivot → not stale
            session.run("""
                CREATE (src:ScanSource {name: 'scanner1',
                                        first_seen: '2026-01-01', last_seen: '2026-01-02'})
                CREATE (pivot_src:ScanSource {name: '10.0.0.1',
                                              first_seen: '2026-01-03', last_seen: '2026-01-03'})
                CREATE (h1:Host {ip: '10.0.0.1', role: 'unknown', role_confidence: 0.0,
                                 first_seen: '2026-01-01', last_seen: '2026-01-01'})
                CREATE (h2:Host {ip: '10.0.0.2', role: 'unknown', role_confidence: 0.0,
                                 first_seen: '2026-01-01', last_seen: '2026-01-02'})
                CREATE (h3:Host {ip: '10.0.1.1', role: 'unknown', role_confidence: 0.0,
                                 first_seen: '2026-01-03', last_seen: '2026-01-03'})
                CREATE (src)-[:SCANNED_FROM]->(h1)
                CREATE (src)-[:SCANNED_FROM]->(h2)
                CREATE (pivot_src)-[:SCANNED_FROM]->(h3)
            """)
        resp = client.get("/api/v1/hosts")
        hosts = {h["ip"]: h for h in resp.json()["hosts"]}
        # 10.0.0.1: would be stale (not in rescan) BUT it's a pivot → not stale
        assert hosts["10.0.0.1"]["is_stale"] is False
        assert hosts["10.0.0.1"]["has_changes"] is False
        # 10.0.0.2: rescanned normally
        assert hosts["10.0.0.2"]["is_stale"] is False
        # 10.0.1.1: discovered via pivot → new to graph
        assert hosts["10.0.1.1"]["is_new"] is True

    def test_pivot_host_services_not_changed(self, client):
        """Pivot host with services from original scan must not show CHANGED.

        When host 10.0.0.1 is used as pivot and also appears in the pivot scan,
        its last_seen updates but original services weren't rescanned —
        they must NOT appear as GONE.
        """
        with get_session() as session:
            session.run("""
                CREATE (src:ScanSource {name: 'scanner1',
                                        first_seen: '2026-01-01', last_seen: '2026-01-01'})
                CREATE (pivot_src:ScanSource {name: '10.0.0.1',
                                              first_seen: '2026-01-02', last_seen: '2026-01-02'})
                CREATE (h1:Host {ip: '10.0.0.1', role: 'web_server', role_confidence: 0.8,
                                 first_seen: '2026-01-01', last_seen: '2026-01-02'})
                CREATE (src)-[:SCANNED_FROM]->(h1)
                CREATE (pivot_src)-[:SCANNED_FROM]->(h1)
                CREATE (h1)-[:HAS_SERVICE]->(:Service {
                    host_ip: '10.0.0.1', port: 443, protocol: 'tcp', name: 'https',
                    first_seen: '2026-01-01', last_seen: '2026-01-01'
                })
                CREATE (h1)-[:HAS_SERVICE]->(:Service {
                    host_ip: '10.0.0.1', port: 80, protocol: 'tcp', name: 'http',
                    first_seen: '2026-01-01', last_seen: '2026-01-01'
                })
            """)
        resp = client.get("/api/v1/hosts/10.0.0.1")
        data = resp.json()
        # Pivot host: not stale, not changed (services from original scan preserved)
        assert data["is_stale"] is False
        assert data["has_changes"] is False
        assert data["is_new"] is False


class TestReset:
    def test_reset_clears_database(self, client):
        _setup_test_network()
        # Verify data exists
        resp = client.get("/api/v1/stats")
        assert resp.json()["hosts"] > 0

        # Reset
        resp = client.delete("/api/v1/reset")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        # Verify empty
        resp = client.get("/api/v1/stats")
        assert resp.json()["hosts"] == 0
