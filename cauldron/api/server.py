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
    findings: int
    scan_sources: int
    roles: dict[str, int]


class ServiceOut(BaseModel):
    port: int
    protocol: str
    state: str | None = None
    name: str | None = None
    product: str | None = None
    version: str | None = None
    bruteforceable: bool = False
    notes: str | None = None
    is_new: bool = False
    is_stale: bool = False


class VulnOut(BaseModel):
    cve_id: str
    cvss: float = 0.0
    has_exploit: bool = False
    exploit_url: str | None = None
    exploit_module: str | None = None
    confidence: str = "check"
    description: str | None = None
    enables_pivot: bool | None = None
    checked_status: str | None = None
    port: int | None = None
    source: str | None = None  # exploit_db, nvd, ai


class HostOut(BaseModel):
    ip: str
    hostname: str | None = None
    role: str = "unknown"
    role_confidence: float = 0.0
    os_name: str | None = None
    segment: str | None = None
    is_new: bool = False
    is_stale: bool = False
    has_changes: bool = False
    owned: bool = False
    target: bool = False
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
    ai_false_positives: int = 0
    ai_vulns_kept: int = 0
    ai_vulns_dismissed: int = 0


class VulnStatusUpdate(BaseModel):
    status: str | None = None  # exploited, false_positive, mitigated, or null to clear
    port: int | None = None  # port to scope status to (same CVE on different ports = independent)


class HostMarkerUpdate(BaseModel):
    value: bool


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
        exploit_url=v.get("exploit_url"),
        exploit_module=v.get("exploit_module"),
        confidence=v.get("confidence") or "check",
        description=v.get("description"),
        enables_pivot=v.get("enables_pivot"),
        checked_status=v.get("checked_status"),
        port=v.get("port"),
        source=v.get("source"),
    )


def _get_graph_baseline() -> str | None:
    """Return the earliest first_seen across all hosts (= graph baseline).

    Hosts whose first_seen > baseline are "new to the graph."
    On the very first import all hosts share the baseline → none are new.
    """
    from cauldron.graph.connection import get_session
    with get_session() as session:
        result = session.run("MATCH (h:Host) RETURN min(h.first_seen) AS ts")
        record = result.single()
        return record["ts"] if record else None


def _compute_host_diff(h_first: str | None, h_last: str | None,
                       source_first: str | None, source_latest: str | None,
                       baseline: str | None,
                       services: list[ServiceOut],
                       is_pivot: bool = False) -> tuple[bool, bool, bool]:
    """Compute is_new / is_stale / has_changes for a host.

    is_new uses a global baseline: host is NEW if it first appeared after the
    earliest host in the graph (= not part of the first import baseline).
    is_stale uses per-source comparison: host is GONE only when its own scan
    source was re-used and the host wasn't in the latest scan.
    Pivot hosts (host IP = ScanSource name) are never stale — scanning from
    a host proves it's alive.
    """
    # is_new: host appeared after the graph baseline (new to the graph)
    h_is_new = bool(baseline and h_first and h_last
                    and h_first == h_last and h_first > baseline)
    # is_stale: source re-used AND host not in latest scan from that source
    # Pivot hosts are exempt — they're alive (we scanned from them)
    source_reused = bool(source_first and source_latest
                         and source_first != source_latest)
    h_is_stale = bool(not is_pivot and source_reused
                      and h_last and source_latest
                      and h_last < source_latest)
    # Pivot hosts skip service diffs — we used the host as a scanner,
    # we didn't rescan its own services from the original scan
    h_has_changes = bool(not is_pivot
                         and any(s.is_new or s.is_stale for s in services))
    return h_is_new, h_is_stale, h_has_changes


def _parse_service_record(s: dict, host_first_seen: str | None = None,
                          host_last_seen: str | None = None) -> ServiceOut:
    """Safely convert a Neo4j service dict to ServiceOut, handling None values."""
    svc_first = s.get("first_seen")
    svc_last = s.get("last_seen")
    # Only compute diffs when the host was actually rescanned (not first import)
    host_rescanned = bool(host_first_seen and host_last_seen
                          and host_first_seen != host_last_seen)
    # is_new: service first appeared in the latest scan of this host
    is_new = bool(host_rescanned and svc_first and svc_last
                  and svc_first == svc_last and svc_last >= host_last_seen)
    # is_stale: host was re-scanned but this service wasn't in the latest scan
    is_stale = bool(host_rescanned and svc_last and host_last_seen
                    and svc_last < host_last_seen)
    return ServiceOut(
        port=s["port"],
        protocol=s.get("protocol") or "tcp",
        state=s.get("state"),
        name=s.get("name"),
        product=s.get("product"),
        version=s.get("version"),
        bruteforceable=bool(s.get("bruteforceable") or s.get("bruteforceable_manual")),
        notes=s.get("notes"),
        is_new=is_new,
        is_stale=is_stale,
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
        findings=stats["findings"],
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

        # Get hosts with services, vulns, and per-source latest timestamp
        result = session.run(
            f"""
            MATCH (h:Host)
            {host_where_str}
            {seg_match}
            WITH DISTINCT h, seg
            ORDER BY h.ip
            SKIP $offset LIMIT $limit
            OPTIONAL MATCH (scan_src:ScanSource)-[:SCANNED_FROM]->(h)
            OPTIONAL MATCH (pivot_src:ScanSource {{name: h.ip}})
            WITH h, seg,
                 min(scan_src.first_seen) AS source_first,
                 max(scan_src.last_seen) AS source_latest,
                 pivot_src IS NOT NULL AS is_pivot
            OPTIONAL MATCH (h)-[:HAS_SERVICE]->(s:Service)
            OPTIONAL MATCH (s)-[r:HAS_VULN]->(v:Vulnerability)
            RETURN h.ip AS ip, h.hostname AS hostname, h.role AS role,
                   h.role_confidence AS role_confidence, h.os_name AS os_name,
                   h.first_seen AS h_first_seen, h.last_seen AS h_last_seen,
                   h.owned AS owned, h.target AS target,
                   seg.cidr AS segment, source_first, source_latest, is_pivot,
                   collect(DISTINCT {{
                       port: s.port, protocol: s.protocol, state: s.state,
                       name: s.name, product: s.product, version: s.version,
                       bruteforceable: s.bruteforceable, bruteforceable_manual: s.bruteforceable_manual, notes: s.notes,
                       first_seen: s.first_seen, last_seen: s.last_seen
                   }}) AS services,
                   collect(DISTINCT {{
                       cve_id: v.cve_id, cvss: v.cvss, has_exploit: v.has_exploit,
                       exploit_url: v.exploit_url, exploit_module: v.exploit_module,
                       confidence: v.confidence, description: v.description,
                       enables_pivot: v.enables_pivot, checked_status: r.checked_status,
                       port: s.port, source: v.source
                   }}) AS vulns
            """,
            **params,
            offset=offset,
            limit=limit,
        )

        baseline = _get_graph_baseline()

        hosts = []
        for record in result:
            h_first = record.get("h_first_seen")
            h_last = record.get("h_last_seen")
            src_first = record.get("source_first")
            src_latest = record.get("source_latest")
            is_pivot = bool(record.get("is_pivot"))
            services = [
                _parse_service_record(s, host_first_seen=h_first,
                                     host_last_seen=h_last)
                for s in record["services"] if s.get("port") is not None
            ]
            vulns = [
                _parse_vuln_record(v) for v in record["vulns"]
                if v.get("cve_id") is not None
            ]
            h_is_new, h_is_stale, h_has_changes = _compute_host_diff(
                h_first, h_last, src_first, src_latest, baseline, services,
                is_pivot=is_pivot)
            hosts.append(HostOut(
                ip=record["ip"],
                hostname=record["hostname"],
                role=record["role"] or "unknown",
                role_confidence=record["role_confidence"] or 0.0,
                os_name=record["os_name"],
                segment=record["segment"],
                is_new=h_is_new,
                is_stale=h_is_stale,
                has_changes=h_has_changes,
                owned=bool(record.get("owned")),
                target=bool(record.get("target")),
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
            OPTIONAL MATCH (scan_src:ScanSource)-[:SCANNED_FROM]->(h)
            OPTIONAL MATCH (pivot_src:ScanSource {name: h.ip})
            WITH h, seg,
                 min(scan_src.first_seen) AS source_first,
                 max(scan_src.last_seen) AS source_latest,
                 pivot_src IS NOT NULL AS is_pivot
            OPTIONAL MATCH (h)-[:HAS_SERVICE]->(s:Service)
            OPTIONAL MATCH (s)-[r:HAS_VULN]->(v:Vulnerability)
            RETURN h.ip AS ip, h.hostname AS hostname, h.role AS role,
                   h.role_confidence AS role_confidence, h.os_name AS os_name,
                   h.first_seen AS h_first_seen, h.last_seen AS h_last_seen,
                   h.owned AS owned, h.target AS target,
                   seg.cidr AS segment, source_first, source_latest, is_pivot,
                   collect(DISTINCT {
                       port: s.port, protocol: s.protocol, state: s.state,
                       name: s.name, product: s.product, version: s.version,
                       bruteforceable: s.bruteforceable, bruteforceable_manual: s.bruteforceable_manual, notes: s.notes,
                       first_seen: s.first_seen, last_seen: s.last_seen
                   }) AS services,
                   collect(DISTINCT {
                       cve_id: v.cve_id, cvss: v.cvss, has_exploit: v.has_exploit,
                       exploit_url: v.exploit_url, exploit_module: v.exploit_module,
                       confidence: v.confidence, description: v.description,
                       enables_pivot: v.enables_pivot, checked_status: r.checked_status,
                       port: s.port, source: v.source
                   }) AS vulns
            """,
            ip=ip,
        )
        record = result.single()
        if not record or not record["ip"]:
            raise HTTPException(status_code=404, detail=f"Host {ip} not found")

        h_first = record.get("h_first_seen")
        h_last = record.get("h_last_seen")
        src_first = record.get("source_first")
        src_latest = record.get("source_latest")
        is_pivot = bool(record.get("is_pivot"))
        services = [
            _parse_service_record(s, host_first_seen=h_first,
                                 host_last_seen=h_last)
            for s in record["services"] if s.get("port") is not None
        ]
        vulns = [
            _parse_vuln_record(v) for v in record["vulns"]
            if v.get("cve_id") is not None
        ]
        baseline = _get_graph_baseline()
        h_is_new, h_is_stale, h_has_changes = _compute_host_diff(
            h_first, h_last, src_first, src_latest, baseline, services,
            is_pivot=is_pivot)

        return HostOut(
            ip=record["ip"],
            hostname=record["hostname"],
            role=record["role"] or "unknown",
            role_confidence=record["role_confidence"] or 0.0,
            os_name=record["os_name"],
            segment=record["segment"],
            is_new=h_is_new,
            is_stale=h_is_stale,
            has_changes=h_has_changes,
            owned=bool(record.get("owned")),
            target=bool(record.get("target")),
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
                   h.os_name AS os_name, h.owned AS owned, h.target AS target,
                   seg.cidr AS segment
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
                    "owned": bool(r.get("owned")),
                    "target": bool(r.get("target")),
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
        # If a ScanSource.name matches a Host.ip, merge into the host node
        # (this is a true pivot point — same machine is both host and scanner)
        host_ips = [n.properties["ip"] for n in nodes if n.type == "host"]
        host_ip_set = set(host_ips)
        source_to_node: dict[str, str] = {}  # source name -> graph node id

        result = session.run(
            """
            MATCH (src:ScanSource)-[:SCANNED_FROM]->(h:Host)
            WHERE h.ip IN $ips
            RETURN DISTINCT src.name AS name
            """,
            ips=host_ips,
        )
        for r in result:
            src_name = r["name"]
            if src_name in host_ip_set:
                # Merge: ScanSource maps to existing host node (pivot point)
                host_node_id = f"host:{src_name}"
                source_to_node[src_name] = host_node_id
                # Mark host as also being a scan source
                for n in nodes:
                    if n.id == host_node_id:
                        n.properties["is_scan_source"] = True
                        break
            else:
                # Standalone scan source (external scanner, not in scan results)
                src_id = f"source:{src_name}"
                if src_id not in seen_nodes:
                    nodes.append(GraphNode(
                        id=src_id, label=src_name,
                        type="scan_source", properties={"name": src_name},
                    ))
                    seen_nodes.add(src_id)
                source_to_node[src_name] = src_id

        # SCANNED_FROM edges
        result = session.run(
            """
            MATCH (src:ScanSource)-[:SCANNED_FROM]->(h:Host)
            RETURN src.name AS source, h.ip AS host_ip
            """,
        )
        for r in result:
            src_node_id = source_to_node.get(r["source"])
            host_id = f"host:{r['host_ip']}"
            # Skip self-edges (pivot host pointing to itself)
            if src_node_id and host_id in seen_nodes and src_node_id != host_id:
                edges.append(GraphEdge(source=src_node_id, target=host_id, type="SCANNED_FROM"))

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
    file: UploadFile = File(..., description="Nmap XML or Masscan (XML/JSON) file"),
    source: str | None = Query(None, description="Scan source name"),
    fmt: str = Query("auto", description="Format: auto, nmap, masscan"),
):
    """Import a scan file (Nmap XML or Masscan XML/JSON)."""
    _check_neo4j()

    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")

    suffix = ".json" if file.filename and file.filename.endswith(".json") else ".xml"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        from cauldron.parsers.nmap_parser import parse_nmap_xml
        from cauldron.parsers.masscan_parser import parse_masscan
        from cauldron.ai.classifier import classify_hosts
        from cauldron.graph.ingestion import ingest_scan

        # Auto-detect or use explicit format
        if fmt == "masscan":
            scan = parse_masscan(tmp_path)
        elif fmt == "nmap":
            scan = parse_nmap_xml(tmp_path)
        else:
            text_head = content[:2000].decode("utf-8", errors="ignore").strip()
            if text_head.startswith(("[", "{")) or 'scanner="masscan"' in text_head:
                scan = parse_masscan(tmp_path)
            else:
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
def run_analysis(
    nvd: bool = Query(False, description="Enable NVD CVE enrichment"),
    ai: bool = Query(False, description="Enable AI analysis"),
):
    """Run the analysis pipeline (equivalent to 'cauldron boil').

    By default runs only local analysis (exploit DB, topology, attack paths).
    Use ?nvd=true for NVD enrichment, ?ai=true for AI analysis.
    """
    _check_neo4j()

    from cauldron.graph.ingestion import classify_graph_hosts
    from cauldron.exploits.matcher import (
        ExploitDB, upgrade_confidence_from_scripts, mark_bruteforceable_services,
    )
    from cauldron.graph.topology import build_segment_connectivity
    from cauldron.ai.attack_paths import get_path_summary

    # Phase 1: Classification
    classification = classify_graph_hosts()

    # Phase 2: Local exploit DB
    exploit_db = ExploitDB()
    exploit_stats = exploit_db.match_from_graph()

    # Phase 2.5: Script confidence
    script_stats = upgrade_confidence_from_scripts()

    # Phase 2.7: Bruteforceable service detection
    mark_bruteforceable_services()

    # Phase 3: CVE enrichment (optional)
    cve_stats: dict = {"services_checked": 0, "services_with_cves": 0, "total_cves_found": 0}
    if nvd:
        from cauldron.ai.cve_enricher import enrich_services_from_graph
        cve_stats = enrich_services_from_graph()

    # Phase 4: Topology
    topo_stats = build_segment_connectivity()

    # Phase 5: Path summary
    summary = get_path_summary()

    # Phase 6: AI (optional)
    ai_fp_count = 0
    ai_kept = 0
    ai_dismissed = 0
    if ai:
        from cauldron.ai.analyzer import analyze_graph, is_ai_available
        if is_ai_available():
            ai_result = analyze_graph()
            ai_fp_count = ai_result.false_positives_found
            ai_kept = ai_result.vulns_kept
            ai_dismissed = ai_result.vulns_dismissed

    return AnalyzeResponse(
        classification=classification,
        exploits=exploit_stats,
        scripts=script_stats,
        cve_enrichment=cve_stats,
        topology=topo_stats,
        path_summary=summary,
        ai_false_positives=ai_fp_count,
        ai_vulns_kept=ai_kept,
        ai_vulns_dismissed=ai_dismissed,
    )


@app.get("/api/v1/hosts/{ip}/services/{port}/default-creds")
def get_default_creds(ip: str, port: int):
    """Get known default credentials for a service."""
    from cauldron.exploits.default_creds import get_creds_for_graph_service

    creds = get_creds_for_graph_service(ip, port)
    return {"ip": ip, "port": port, "creds": creds}


@app.patch("/api/v1/hosts/{ip}/owned")
def update_host_owned(ip: str, body: HostMarkerUpdate):
    """Mark/unmark a host as owned (compromised)."""
    _check_neo4j()
    from cauldron.graph.ingestion import set_host_owned

    if not set_host_owned(ip, body.value):
        raise HTTPException(status_code=404, detail=f"Host {ip} not found")
    return {"ok": True}


@app.patch("/api/v1/hosts/{ip}/target")
def update_host_target(ip: str, body: HostMarkerUpdate):
    """Mark/unmark a host as target (engagement goal)."""
    _check_neo4j()
    from cauldron.graph.ingestion import set_host_target

    if not set_host_target(ip, body.value):
        raise HTTPException(status_code=404, detail=f"Host {ip} not found")
    return {"ok": True}


@app.patch("/api/v1/hosts/{ip}/vulns/{vuln_id}/status")
def update_vuln_status(ip: str, vuln_id: str, body: VulnStatusUpdate):
    """Update checked status for a vulnerability on a specific host."""
    _check_neo4j()
    from cauldron.graph.connection import get_session

    valid_statuses = {"exploited", "false_positive", "mitigated", None}
    if body.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status: {body.status}")

    with get_session() as session:
        # Status is stored on the HAS_VULN relationship so the same CVE
        # on different ports can have independent checked status
        if body.port is not None:
            result = session.run(
                """
                MATCH (h:Host {ip: $ip})-[:HAS_SERVICE]->(s:Service {port: $port})-[r:HAS_VULN]->(v:Vulnerability {cve_id: $vuln_id})
                SET r.checked_status = $status
                RETURN v.cve_id AS cve_id
                """,
                ip=ip,
                port=body.port,
                vuln_id=vuln_id,
                status=body.status,
            )
        else:
            # No port specified — update all relationships for this CVE on this host
            result = session.run(
                """
                MATCH (h:Host {ip: $ip})-[:HAS_SERVICE]->(s:Service)-[r:HAS_VULN]->(v:Vulnerability {cve_id: $vuln_id})
                SET r.checked_status = $status
                RETURN v.cve_id AS cve_id
                """,
                ip=ip,
                vuln_id=vuln_id,
                status=body.status,
            )
        record = result.single()
        if not record:
            raise HTTPException(status_code=404, detail=f"Vulnerability {vuln_id} not found on host {ip}")

    return {"ok": True}


class BruteforceableUpdate(BaseModel):
    bruteforceable: bool


@app.patch("/api/v1/hosts/{ip}/services/{port}/bruteforceable")
def update_service_bruteforceable(ip: str, port: int, body: BruteforceableUpdate):
    """Toggle bruteforceable flag on a service (manual override)."""
    _check_neo4j()
    from cauldron.graph.connection import get_session

    with get_session() as session:
        result = session.run(
            """
            MATCH (:Host {ip: $ip})-[:HAS_SERVICE]->(s:Service {port: $port})
            SET s.bruteforceable_manual = $brute,
                s.bruteforceable = $brute
            RETURN s.port AS port
            """,
            ip=ip,
            port=port,
            brute=body.bruteforceable,
        )
        record = result.single()
        if not record:
            raise HTTPException(
                status_code=404,
                detail=f"Service port {port} not found on host {ip}",
            )

    return {"ok": True}


class ServiceNotesUpdate(BaseModel):
    notes: str | None = None


@app.patch("/api/v1/hosts/{ip}/services/{port}/notes")
def update_service_notes(ip: str, port: int, body: ServiceNotesUpdate):
    """Update notes on a service (pentester's working notes)."""
    _check_neo4j()
    from cauldron.graph.connection import get_session

    with get_session() as session:
        result = session.run(
            """
            MATCH (:Host {ip: $ip})-[:HAS_SERVICE]->(s:Service {port: $port})
            SET s.notes = $notes
            RETURN s.port AS port
            """,
            ip=ip, port=port, notes=body.notes,
        )
        if not result.single():
            raise HTTPException(status_code=404, detail=f"Service port {port} not found on host {ip}")

    return {"ok": True}


@app.get("/api/v1/report")
def get_report(
    fmt: str = Query("md", description="Format: md, json, html"),
    top: int = Query(20, description="Number of top findings"),
):
    """Generate and download scan report."""
    _check_neo4j()
    from cauldron.report import generate_markdown, generate_json, generate_html
    from fastapi.responses import PlainTextResponse

    if fmt == "json":
        content = generate_json(top=top)
        return PlainTextResponse(content, media_type="application/json")
    elif fmt == "html":
        content = generate_html(top=top)
        return PlainTextResponse(content, media_type="text/html")
    else:
        content = generate_markdown(top=top)
        return PlainTextResponse(content, media_type="text/markdown")


@app.delete("/api/v1/reset")
def reset_database():
    """Clear all nodes and relationships from the database."""
    _check_neo4j()
    from cauldron.graph.connection import clear_database

    clear_database()
    return {"ok": True, "message": "Database cleared"}
