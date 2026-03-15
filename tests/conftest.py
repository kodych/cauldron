"""Shared test fixtures for Cauldron test suite."""

from __future__ import annotations

import pytest

from cauldron.graph.connection import clear_database, verify_connection
from cauldron.graph.models import Host, ScanResult, Service


# ---------------------------------------------------------------------------
# Neo4j fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def neo4j_available():
    """Skip test if Neo4j is not reachable."""
    if not verify_connection():
        pytest.skip("Neo4j not available")


@pytest.fixture()
def clean_db(neo4j_available):
    """Clear database before and after a test (non-autouse)."""
    clear_database()
    yield
    clear_database()


# ---------------------------------------------------------------------------
# Model factories
# ---------------------------------------------------------------------------

@pytest.fixture()
def sample_host_dc() -> Host:
    """Domain controller with typical ports and products."""
    return Host(
        ip="10.0.1.10",
        hostname="dc01.corp.local",
        state="up",
        os_name="Windows Server 2019",
        services=[
            Service(port=53, protocol="tcp", state="open", name="domain"),
            Service(port=88, protocol="tcp", state="open", name="kerberos-sec",
                    product="Microsoft Windows Kerberos"),
            Service(port=135, protocol="tcp", state="open", name="msrpc"),
            Service(port=389, protocol="tcp", state="open", name="ldap",
                    product="Microsoft Windows Active Directory LDAP"),
            Service(port=445, protocol="tcp", state="open", name="microsoft-ds"),
            Service(port=464, protocol="tcp", state="open", name="kpasswd5"),
            Service(port=636, protocol="tcp", state="open", name="ldapssl"),
            Service(port=3268, protocol="tcp", state="open", name="globalcatLDAP"),
            Service(port=3389, protocol="tcp", state="open", name="ms-wbt-server"),
        ],
    )


@pytest.fixture()
def sample_host_web() -> Host:
    """Web server with Apache and known-vulnerable version."""
    return Host(
        ip="10.0.2.20",
        hostname="web01.corp.local",
        state="up",
        os_name="Ubuntu 20.04",
        services=[
            Service(port=22, protocol="tcp", state="open", name="ssh",
                    product="OpenSSH", version="7.4p1"),
            Service(port=80, protocol="tcp", state="open", name="http",
                    product="Apache httpd", version="2.4.49"),
            Service(port=443, protocol="tcp", state="open", name="https",
                    product="Apache httpd", version="2.4.49"),
        ],
    )


@pytest.fixture()
def sample_host_db() -> Host:
    """Database server with MySQL."""
    return Host(
        ip="10.0.1.30",
        hostname="db01.corp.local",
        state="up",
        os_name="Ubuntu 22.04",
        services=[
            Service(port=22, protocol="tcp", state="open", name="ssh",
                    product="OpenSSH", version="8.9p1"),
            Service(port=3306, protocol="tcp", state="open", name="mysql",
                    product="MySQL", version="5.7.38"),
        ],
    )


@pytest.fixture()
def sample_scan(sample_host_dc, sample_host_web, sample_host_db) -> ScanResult:
    """A scan result with DC, web server, and database."""
    return ScanResult(
        hosts=[sample_host_dc, sample_host_web, sample_host_db],
        scan_source="192.168.1.100",
    )
