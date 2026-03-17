"""Cauldron REST API — FastAPI backend.

Serves all graph data for the web UI and external integrations.
Start with: cauldron serve
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Cauldron API",
    description="Network Attack Path Discovery — REST API",
    version="0.1.0",
)

# CORS — allow any origin in dev, restrict in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Pydantic response models
# ---------------------------------------------------------------------------

class StatsResponse(BaseModel):
    hosts: int
    services: int
    segments: int
    vulnerabilities: int
    scan_sources: int
    roles: dict[str, int]


class ServiceOut(BaseModel):
    port: int
    protocol: str
    state: str | None = None
    name: str | None = None
    product: str | None = None
    version: str | None = None


class VulnOut(BaseModel):
    cve_id: str
    cvss: float = 0.0
    has_exploit: bool = False
    confidence: str = "check"
    description: str | None = None
    enables_pivot: bool | None = None


class HostOut(BaseModel):
    ip: str
    hostname: str | None = None
    role: str = "unknown"
    role_confidence: float = 0.0
    os_name: str | None = None
    segment: str | None = None
    services: list[ServiceOut] = []
    vulnerabilities: list[VulnOut] = []


class HostListResponse(BaseModel):
    hosts: list[HostOut]
    total: int


class VulnInfoOut(BaseModel):
    cve_id: str
    cvss: float = 0.0
    has_exploit: bool = False
    title: str = ""
    confidence: str = "check"
    enables_pivot: bool | None = None
    method: str = ""


class PathNodeOut(BaseModel):
    ip: str
    hostname: str | None = None
    role: str = "unknown"
    segment: str | None = None
    vulns: list[VulnInfoOut] = []


class AttackPathOut(BaseModel):
    nodes: list[PathNodeOut]
    target_role: str = "unknown"
    score: float = 0.0
    hop_count: int = 0
    max_cvss: float = 0.0
    has_exploits: bool = False
    attack_methods: list[str] = []
    max_confidence: str = "check"


class PathsResponse(BaseModel):
    paths: list[AttackPathOut]
    summary: dict[str, Any]


class CollectHostOut(BaseModel):
    ip: str
    hostname: str | None = None
    port: int | None = None
    role: str | None = None


class CollectResponse(BaseModel):
    hosts: list[CollectHostOut]
    filter_used: str
    total: int


class ImportResponse(BaseModel):
    hosts_imported: int
    hosts_skipped: int
    services_imported: int
    segments_created: int
    relationships_created: int


class AnalyzeResponse(BaseModel):
    classification: dict[str, Any]
    exploits: dict[str, Any]
    scripts: dict[str, Any]
    cve_enrichment: dict[str, Any]
    topology: dict[str, Any]
    path_summary: dict[str, Any]


class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # host, service, segment, scan_source
    properties: dict[str, Any] = {}


class GraphEdge(BaseModel):
    source: str
    target: str
    type: str  # HAS_SERVICE, IN_SEGMENT, SCANNED_FROM, etc.
    properties: dict[str, Any] = {}


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class TopologySegment(BaseModel):
    cidr: str
    hosts: int
    reaches: int


class TopologyResponse(BaseModel):
    segments: list[TopologySegment]
    gateways: int
    total_reach_edges: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_neo4j():
    """Raise 503 if Neo4j is not reachable."""
    from cauldron.graph.connection import verify_connection
    if not verify_connection():
        raise HTTPException(status_code=503, detail="Neo4j is not available")


def _parse_vuln_record(v: dict) -> VulnOut:
    """Safely convert a Neo4j vuln dict to VulnOut, handling None values."""
    return VulnOut(
        cve_id=v["cve_id"],
        cvss=v.get("cvss") or 0.0,
        has_exploit=bool(v.get("has_exploit")),
        confidence=v.get("confidence") or "check",
        description=v.get("description"),
        enables_pivot=v.get("enables_pivot"),
    )


def _parse_service_record(s: dict) -> ServiceOut:
    """Safely convert a Neo4j service dict to ServiceOut, handling None values."""
    return ServiceOut(
        port=s["port"],
        protocol=s.get("protocol") or "tcp",
        state=s.get("state"),
        name=s.get("name"),
        product=s.get("product"),
        version=s.get("version"),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    """API root — health check and links."""
    return {
        "name": "Cauldron API",
        "version": "0.1.0",
        "docs": "/docs",
        "api": "/api/v1/stats",
    }

@app.get("/api/v1/stats", response_model=StatsResponse)
def get_stats():
    """Graph statistics overview."""
    _check_neo4j()
    from cauldron.graph.ingestion import get_graph_stats, get_host_role_distribution
    stats = get_graph_stats()
    roles = get_host_role_distribution()
    return StatsResponse(
        hosts=stats["hosts"],
        services=stats["services"],
        segments=stats["segments"],
        vulnerabilities=stats["vulnerabilities"],
        scan_sources=stats["scan_sources"],
        roles=roles,
    )


@app.get("/api/v1/hosts", response_model=HostListResponse)
def list_hosts(
    role: str | None = Query(None, description="Filter by host role"),
    segment: str | None = Query(None, description="Filter by network segment CIDR"),
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
):
    """List hosts with optional filters."""
    _check_neo4j()
    from cauldron.graph.connection import get_session

    # Build host-level WHERE clauses
    host_where: list[str] = []
    params: dict[str, Any] = {}

    if role:
        host_where.append("h.role = $role")
        params["role"] = role

    host_where_str = "WHERE " + " AND ".join(host_where) if host_where else ""

    # Segment filter requires a mandatory MATCH
    if segment:
        seg_match = "MATCH (h)-[:IN_SEGMENT]->(seg:NetworkSegment {cidr: $segment})"
        params["segment"] = segment
    else:
        seg_match = "OPTIONAL MATCH (h)-[:IN_SEGMENT]->(seg:NetworkSegment)"

    with get_session() as session:
        # Get total count
        count_result = session.run(
            f"""
            MATCH (h:Host)
            {host_where_str}
            {seg_match}
            RETURN count(DISTINCT h) AS total
            """,
            **params,
        )
        total = count_result.single()["total"]

        # Get hosts with services and vulns
        result = session.run(
            f"""
            MATCH (h:Host)
            {host_where_str}
            {seg_match}
            WITH DISTINCT h, seg
            ORDER BY h.ip
            SKIP $offset LIMIT $limit
            OPTIONAL MATCH (h)-[:HAS_SERVICE]->(s:Service)
            OPTIONAL MATCH (s)-[:HAS_VULN]->(v:Vulnerability)
            RETURN h.ip AS ip, h.hostname AS hostname, h.role AS role,
                   h.role_confidence AS role_confidence, h.os_name AS os_name,
                   seg.cidr AS segment,
                   collect(DISTINCT {{
                       port: s.port, protocol: s.protocol, state: s.state,
                       name: s.name, product: s.product, version: s.version
                   }}) AS services,
                   collect(DISTINCT {{
                       cve_id: v.cve_id, cvss: v.cvss, has_exploit: v.has_exploit,
                       confidence: v.confidence, description: v.description,
                       enables_pivot: v.enables_pivot
                   }}) AS vulns
            """,
            **params,
            offset=offset,
            limit=limit,
        )

        hosts = []
        for record in result:
            services = [
                _parse_service_record(s) for s in record["services"]
                if s.get("port") is not None
            ]
            vulns = [
                _parse_vuln_record(v) for v in record["vulns"]
                if v.get("cve_id") is not None
            ]
            hosts.append(HostOut(
                ip=record["ip"],
                hostname=record["hostname"],
                role=record["role"] or "unknown",
                role_confidence=record["role_confidence"] or 0.0,
                os_name=record["os_name"],
                segment=record["segment"],
                services=services,
                vulnerabilities=vulns,
            ))

    return HostListResponse(hosts=hosts, total=total)


@app.get("/api/v1/hosts/{ip}", response_model=HostOut)
def get_host(ip: str):
    """Get detailed information about a specific host."""
    _check_neo4j()
    from cauldron.graph.connection import get_session

    with get_session() as session:
        result = session.run(
            """
            MATCH (h:Host {ip: $ip})
            OPTIONAL MATCH (h)-[:IN_SEGMENT]->(seg:NetworkSegment)
            OPTIONAL MATCH (h)-[:HAS_SERVICE]->(s:Service)
            OPTIONAL MATCH (s)-[:HAS_VULN]->(v:Vulnerability)
            RETURN h.ip AS ip, h.hostname AS hostname, h.role AS role,
                   h.role_confidence AS role_confidence, h.os_name AS os_name,
                   seg.cidr AS segment,
                   collect(DISTINCT {
                       port: s.port, protocol: s.protocol, state: s.state,
                       name: s.name, product: s.product, version: s.version
                   }) AS services,
                   collect(DISTINCT {
                       cve_id: v.cve_id, cvss: v.cvss, has_exploit: v.has_exploit,
                       confidence: v.confidence, description: v.description,
                       enables_pivot: v.enables_pivot
                   }) AS vulns
            """,
            ip=ip,
        )
        record = result.single()
        if not record or not record["ip"]:
            raise HTTPException(status_code=404, detail=f"Host {ip} not found")

        services = [
            ServiceOut(**s) for s in record["services"]
            if s.get("port") is not None
        ]
        vulns = [
            VulnOut(**v) for v in record["vulns"]
            if v.get("cve_id") is not None
        ]

        return HostOut(
            ip=record["ip"],
            hostname=record["hostname"],
            role=record["role"] or "unknown",
            role_confidence=record["role_confidence"] or 0.0,
            os_name=record["os_name"],
            segment=record["segment"],
            services=services,
            vulnerabilities=vulns,
        )


@app.get("/api/v1/attack-paths", response_model=PathsResponse)
def get_attack_paths(
    target: str | None = Query(None, description="Target IP"),
    role: str | None = Query(None, description="Target role filter"),
    top: int = Query(20, ge=1, le=100),
    include_check: bool = Query(False, description="Include check-level paths"),
):
    """Discover and return ranked attack paths."""
    _check_neo4j()
    from cauldron.ai.attack_paths import discover_attack_paths, get_path_summary

    paths = discover_attack_paths(target_role=role, target_ip=target)
    summary = get_path_summary()

    # Filter by confidence
    if not include_check:
        paths = [p for p in paths if p.max_confidence in ("confirmed", "likely")]

    # Limit
    paths = paths[:top]

    path_out = []
    for p in paths:
        nodes = [
            PathNodeOut(
                ip=n.ip,
                hostname=n.hostname,
                role=n.role,
                segment=n.segment,
                vulns=[VulnInfoOut(
                    cve_id=v.cve_id, cvss=v.cvss, has_exploit=v.has_exploit,
                    title=v.title, confidence=v.confidence,
                    enables_pivot=v.enables_pivot, method=v.method,
                ) for v in n.vulns],
            )
            for n in p.nodes
        ]
        path_out.append(AttackPathOut(
            nodes=nodes,
            target_role=p.target_role,
            score=p.score,
            hop_count=p.hop_count,
            max_cvss=p.max_cvss,
            has_exploits=p.has_exploits,
            attack_methods=p.attack_methods,
            max_confidence=p.max_confidence,
        ))

    return PathsResponse(paths=path_out, summary=summary)


@app.get("/api/v1/collect", response_model=CollectResponse)
def collect(
    filter: str | None = Query(None, alias="filter", description="Built-in filter name"),
    port: int | None = Query(None, description="Custom port filter"),
    role: str | None = Query(None, description="Filter by host role"),
    source: str | None = Query(None, description="Scan source filter"),
):
    """Collect target lists (same as CLI collect)."""
    _check_neo4j()
    from cauldron.collect import collect_targets

    if not filter and not port and not role:
        raise HTTPException(status_code=400, detail="Specify filter, port, or role parameter")

    try:
        result = collect_targets(filter_name=filter, port=port, role=role, source=source)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    hosts = [
        CollectHostOut(ip=h.ip, hostname=h.hostname, port=h.port, role=h.role)
        for h in result.hosts
    ]
    return CollectResponse(hosts=hosts, filter_used=result.filter_used, total=result.total)


@app.get("/api/v1/collect/filters")
def list_collect_filters():
    """List available collect filters."""
    from cauldron.collect import list_filters
    return list_filters()


@app.get("/api/v1/graph", response_model=GraphResponse)
def get_graph(
    limit: int = Query(500, ge=1, le=5000, description="Max hosts to include"),
):
    """Full graph data for visualization (nodes + edges)."""
    _check_neo4j()
    from cauldron.graph.connection import get_session

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    seen_nodes: set[str] = set()

    with get_session() as session:
        # Hosts (limited)
        result = session.run(
            """
            MATCH (h:Host)
            WITH h ORDER BY h.ip LIMIT $limit
            OPTIONAL MATCH (h)-[:IN_SEGMENT]->(seg:NetworkSegment)
            RETURN h.ip AS ip, h.hostname AS hostname, h.role AS role,
                   h.os_name AS os_name, seg.cidr AS segment
            """,
            limit=limit,
        )
        for r in result:
            node_id = f"host:{r['ip']}"
            nodes.append(GraphNode(
                id=node_id,
                label=r["hostname"] or r["ip"],
                type="host",
                properties={
                    "ip": r["ip"],
                    "hostname": r["hostname"],
                    "role": r["role"] or "unknown",
                    "os_name": r["os_name"],
                    "segment": r["segment"],
                },
            ))
            seen_nodes.add(node_id)

            # Host -> Segment edge
            if r["segment"]:
                seg_id = f"segment:{r['segment']}"
                if seg_id not in seen_nodes:
                    nodes.append(GraphNode(
                        id=seg_id, label=r["segment"],
                        type="segment", properties={"cidr": r["segment"]},
                    ))
                    seen_nodes.add(seg_id)
                edges.append(GraphEdge(source=node_id, target=seg_id, type="IN_SEGMENT"))

        # Scan sources — only those connected to hosts we included
        host_ips = [n.properties["ip"] for n in nodes if n.type == "host"]
        result = session.run(
            """
            MATCH (src:ScanSource)-[:SCANNED_FROM]->(h:Host)
            WHERE h.ip IN $ips
            RETURN DISTINCT src.name AS name
            """,
            ips=host_ips,
        )
        for r in result:
            src_id = f"source:{r['name']}"
            if src_id not in seen_nodes:
                nodes.append(GraphNode(
                    id=src_id, label=r["name"],
                    type="scan_source", properties={"name": r["name"]},
                ))
                seen_nodes.add(src_id)

        # SCANNED_FROM edges
        result = session.run(
            """
            MATCH (src:ScanSource)-[:SCANNED_FROM]->(h:Host)
            RETURN src.name AS source, h.ip AS host_ip
            """,
        )
        for r in result:
            src_id = f"source:{r['source']}"
            host_id = f"host:{r['host_ip']}"
            if src_id in seen_nodes and host_id in seen_nodes:
                edges.append(GraphEdge(source=src_id, target=host_id, type="SCANNED_FROM"))

        # CAN_REACH edges between segments
        result = session.run(
            "MATCH (s1:NetworkSegment)-[:CAN_REACH]->(s2:NetworkSegment) RETURN s1.cidr AS src, s2.cidr AS dst"
        )
        for r in result:
            src_id = f"segment:{r['src']}"
            dst_id = f"segment:{r['dst']}"
            if src_id in seen_nodes and dst_id in seen_nodes:
                edges.append(GraphEdge(source=src_id, target=dst_id, type="CAN_REACH"))

    return GraphResponse(nodes=nodes, edges=edges)


@app.get("/api/v1/topology", response_model=TopologyResponse)
def get_topology():
    """Network topology statistics."""
    _check_neo4j()
    from cauldron.graph.topology import get_topology_stats

    stats = get_topology_stats()
    segments = [
        TopologySegment(cidr=s["cidr"], hosts=s["hosts"], reaches=s["reaches"])
        for s in stats["segments"]
    ]
    return TopologyResponse(
        segments=segments,
        gateways=stats["gateways"],
        total_reach_edges=stats["total_reach_edges"],
    )


@app.post("/api/v1/import", response_model=ImportResponse)
async def import_scan(
    file: UploadFile = File(..., description="Nmap XML file"),
    source: str | None = Query(None, description="Scan source name"),
):
    """Import an Nmap XML scan file."""
    _check_neo4j()

    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    # Read uploaded file to a temp location
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        from cauldron.parsers.nmap_parser import parse_nmap_xml
        from cauldron.ai.classifier import classify_hosts
        from cauldron.graph.ingestion import ingest_scan

        scan = parse_nmap_xml(tmp_path)
        if not scan.hosts_up:
            raise HTTPException(status_code=400, detail="No live hosts found in scan")

        classify_hosts(scan.hosts_up)
        source_name = source or (file.filename.rsplit(".", 1)[0] if file.filename else "upload")
        stats = ingest_scan(scan, source_name=source_name)

        return ImportResponse(**stats)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Import failed")
        raise HTTPException(status_code=400, detail=f"Import failed: {e}")
    finally:
        tmp_path.unlink(missing_ok=True)


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
def run_analysis(ai: bool = Query(False, description="Enable AI analysis")):
    """Run the full analysis pipeline (equivalent to 'cauldron boil')."""
    _check_neo4j()

    from cauldron.graph.ingestion import classify_graph_hosts
    from cauldron.exploits.matcher import ExploitDB, upgrade_confidence_from_scripts
    from cauldron.ai.cve_enricher import enrich_services_from_graph
    from cauldron.graph.topology import build_segment_connectivity
    from cauldron.ai.attack_paths import get_path_summary

    # Phase 1: Classification
    classification = classify_graph_hosts()

    # Phase 2: Local exploit DB
    exploit_db = ExploitDB()
    exploit_stats = exploit_db.match_from_graph()

    # Phase 2.5: Script confidence
    script_stats = upgrade_confidence_from_scripts()

    # Phase 3: CVE enrichment
    cve_stats = enrich_services_from_graph()

    # Phase 4: Topology
    topo_stats = build_segment_connectivity()

    # Phase 5: Path summary
    summary = get_path_summary()

    # Phase 6: AI (optional)
    if ai:
        from cauldron.ai.analyzer import analyze_graph, is_ai_available
        if is_ai_available():
            analyze_graph()

    return AnalyzeResponse(
        classification=classification,
        exploits=exploit_stats,
        scripts=script_stats,
        cve_enrichment=cve_stats,
        topology=topo_stats,
        path_summary=summary,
    )
