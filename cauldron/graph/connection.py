"""Neo4j database connection manager."""

from __future__ import annotations

import time
import warnings
from contextlib import contextmanager
from typing import Generator

from neo4j import Driver, GraphDatabase, Session

from cauldron.config import settings

# Suppress Neo4j driver deprecation warnings (NotificationDisabledCategory)
warnings.filterwarnings("ignore", category=DeprecationWarning, module="neo4j")

_driver: Driver | None = None
# verify_connection() cache. ``driver.verify_connectivity()`` does a full
# Bolt handshake on first call after each new TCP connection and can take
# ~2 s on Windows even against a healthy local Neo4j. Every API endpoint
# guards itself with ``_check_neo4j()``, so without caching every request
# without keep-alive pays that 2 s — which is exactly what made the
# HostDetail refetch after Mark-as-Owned appear "stuck" until the
# operator hit F5. A 30 s TTL is safe: Neo4j outages are caught the next
# time the cache expires and a fresh ping is attempted.
_VERIFY_TTL_SECONDS = 30.0
_verify_cached_at: float = 0.0
_verify_cached_result: bool = False


def get_driver() -> Driver:
    """Get or create the Neo4j driver singleton."""
    global _driver
    if _driver is None:
        # Disable "property does not exist" warnings from Neo4j
        # These fire when querying notes/owned/target before first SET
        try:
            from neo4j import NotificationDisabledClassification
            disabled = [NotificationDisabledClassification.UNRECOGNIZED]
        except ImportError:
            disabled = None
        _driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
            **({"notifications_disabled_classifications": disabled} if disabled else {}),
        )
    return _driver


def close_driver() -> None:
    """Close the Neo4j driver."""
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None


@contextmanager
def get_session() -> Generator[Session, None, None]:
    """Get a Neo4j session as a context manager."""
    driver = get_driver()
    session = driver.session()
    try:
        yield session
    finally:
        session.close()


def verify_connection() -> bool:
    """Check if Neo4j is reachable.

    Result is cached for ``_VERIFY_TTL_SECONDS`` after a successful ping.
    A failed ping is NOT cached — the next caller re-tries immediately
    so a recovered Neo4j is picked up without waiting for the TTL.
    """
    global _verify_cached_at, _verify_cached_result
    now = time.monotonic()
    if _verify_cached_result and (now - _verify_cached_at) < _VERIFY_TTL_SECONDS:
        return True
    try:
        driver = get_driver()
        driver.verify_connectivity()
    except Exception:
        _verify_cached_result = False
        return False
    _verify_cached_at = now
    _verify_cached_result = True
    return True


def init_schema() -> None:
    """Create indexes and constraints for the Cauldron graph schema."""
    constraints = [
        "CREATE CONSTRAINT host_ip IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE",
        "CREATE CONSTRAINT segment_cidr IF NOT EXISTS FOR (s:NetworkSegment) REQUIRE s.cidr IS UNIQUE",
        "CREATE CONSTRAINT vuln_cve IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE",
        "CREATE CONSTRAINT scan_source_name IF NOT EXISTS FOR (s:ScanSource) REQUIRE s.name IS UNIQUE",
    ]

    indexes = [
        "CREATE INDEX host_role IF NOT EXISTS FOR (h:Host) ON (h.role)",
        "CREATE INDEX service_port IF NOT EXISTS FOR (s:Service) ON (s.port)",
        "CREATE INDEX service_name IF NOT EXISTS FOR (s:Service) ON (s.name)",
    ]

    with get_session() as session:
        for query in constraints + indexes:
            session.run(query)


def clear_database() -> None:
    """Delete all nodes and relationships. Use with caution!"""
    with get_session() as session:
        session.run("MATCH (n) DETACH DELETE n")
