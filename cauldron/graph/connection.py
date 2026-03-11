"""Neo4j database connection manager."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from neo4j import Driver, GraphDatabase, Session

from cauldron.config import settings

_driver: Driver | None = None


def get_driver() -> Driver:
    """Get or create the Neo4j driver singleton."""
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
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
    """Check if Neo4j is reachable."""
    try:
        driver = get_driver()
        driver.verify_connectivity()
        return True
    except Exception:
        return False


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
