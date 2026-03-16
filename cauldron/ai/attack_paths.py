"""Attack path discovery and scoring engine.

Discovers DIRECT attack paths from scan sources to vulnerable hosts.
Each path is one hop: ScanSource -> Target Host with vulnerability.

Three distinct concepts (never conflated):
1. Reachability — ScanSource->SCANNED_FROM->Host (what we can see)
2. Attack paths — ScanSource -> Host with vulnerability (what we can exploit)
3. True pivoting — host compromised via RCE bridges to a new network
   (detected when Host.ip matches ScanSource.name across different scans)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from cauldron.graph.connection import get_session

logger = logging.getLogger(__name__)

# High-value target roles (ordered by priority for an attacker)
HIGH_VALUE_ROLES = [
    "domain_controller",
    "database",
    "mail_server",
    "file_server",
    "hypervisor",
    "siem",
    "ci_cd",
    "backup",
    "management",
]


@dataclass
class VulnInfo:
    """Lightweight vulnerability info attached to a path node."""

    cve_id: str
    cvss: float = 0.0
    has_exploit: bool = False
    title: str = ""
    confidence: str = "check"  # confirmed | likely | check
    enables_pivot: bool | None = None  # True = RCE/shell, False = relay/misconfig
    method: str = ""  # exploit | relay | credential | cve


@dataclass
class PathNode:
    """A single node in an attack path."""

    ip: str
    hostname: str | None = None
    role: str = "unknown"
    segment: str | None = None
    max_cvss: float = 0.0
    has_exploit: bool = False
    service_count: int = 0
    vulns: list[VulnInfo] = field(default_factory=list)


@dataclass
class AttackPath:
    """A discovered attack path from source to target.

    Direct paths: [ScanSource, Target] — 1 hop
    Pivot paths:  [ScanSource, PivotHost, Target] — 2 hops (true pivot only)
    """

    nodes: list[PathNode] = field(default_factory=list)
    target_role: str = "unknown"
    score: float = 0.0
    hop_count: int = 0
    max_cvss: float = 0.0
    has_exploits: bool = False
    attack_methods: list[str] = field(default_factory=list)

    @property
    def source_ip(self) -> str:
        return self.nodes[0].ip if self.nodes else ""

    @property
    def target_ip(self) -> str:
        return self.nodes[-1].ip if self.nodes else ""

    @property
    def max_confidence(self) -> str:
        """Best confidence level across all vulns in the path."""
        best = "check"
        order = {"confirmed": 0, "likely": 1, "check": 2}
        for node in self.nodes:
            for vuln in node.vulns:
                if order.get(vuln.confidence, 2) < order.get(best, 2):
                    best = vuln.confidence
        return best


def discover_attack_paths(
    target_role: str | None = None,
    target_ip: str | None = None,
) -> list[AttackPath]:
    """Discover direct attack paths from scan sources to vulnerable hosts.

    Every path is DIRECT: ScanSource -> Target with vulnerability.
    Multi-hop paths only exist through true pivot hosts (Phase 2, future).

    Args:
        target_role: Filter paths to targets with this role.
        target_ip: Find paths to a specific host IP.

    Returns:
        List of AttackPath objects, sorted by score (highest first).
    """
    paths = []

    with get_session() as session:
        # Find all direct attack paths (scanner -> vulnerable host)
        paths = _find_direct_paths(session, target_role, target_ip)

        # Find pivot paths (scanner -> pivot host -> hosts in pivot's scan)
        pivot_paths = _find_pivot_paths(session, target_role, target_ip)
        paths.extend(pivot_paths)

    # Score all paths
    for path in paths:
        path.score = _score_path(path)

    # Deduplicate by (source_ip, target_ip, top_vuln), keep highest scoring
    seen: dict[tuple, AttackPath] = {}
    for path in paths:
        key = tuple(n.ip for n in path.nodes)
        if key not in seen or path.score > seen[key].score:
            seen[key] = path

    paths = list(seen.values())
    paths.sort(key=lambda p: p.score, reverse=True)
    return paths


def _find_direct_paths(
    session, target_role: str | None, target_ip: str | None
) -> list[AttackPath]:
    """Find all direct attack paths: ScanSource -> Host with vulnerability.

    This is the core path discovery. A path exists when:
    1. ScanSource scanned the host (SCANNED_FROM)
    2. Host has at least one vulnerability (HAS_VULN)
    3. Host matches target filter (role or IP)
    """
    # Build target filter
    where_clauses = []
    params: dict = {}

    if target_ip:
        where_clauses.append("h.ip = $target_ip")
        params["target_ip"] = target_ip
    elif target_role:
        where_clauses.append("h.role = $target_role")
        params["target_role"] = target_role

    where_str = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

    result = session.run(
        f"""
        MATCH (src:ScanSource)-[:SCANNED_FROM]->(h:Host)
        MATCH (h)-[:HAS_SERVICE]->(s:Service)-[:HAS_VULN]->(v:Vulnerability)
        {where_str}
        WITH src, h,
             collect(DISTINCT {{
                 cve: v.cve_id, cvss: v.cvss,
                 has_exploit: v.has_exploit, desc: v.description,
                 confidence: v.confidence, enables_pivot: v.enables_pivot
             }}) AS vulns,
             max(v.cvss) AS max_cvss,
             max(CASE WHEN v.has_exploit = true THEN 1 ELSE 0 END) AS has_exploit
        OPTIONAL MATCH (h)-[:IN_SEGMENT]->(seg:NetworkSegment)
        OPTIONAL MATCH (h)-[:HAS_SERVICE]->(svc:Service)
        WITH src, h, vulns, max_cvss, has_exploit, seg,
             count(DISTINCT svc) AS service_count
        RETURN src.name AS source,
               h.ip AS ip, h.hostname AS hostname, h.role AS role,
               seg.cidr AS segment, service_count,
               max_cvss, has_exploit, vulns
        """,
        **params,
    )

    paths = []
    for record in result:
        # Parse vulns
        vuln_list = _parse_vulns(record["vulns"])
        if not vuln_list:
            continue

        target_node = PathNode(
            ip=record["ip"],
            hostname=record["hostname"],
            role=record["role"] or "unknown",
            segment=record["segment"],
            max_cvss=record["max_cvss"] or 0.0,
            has_exploit=bool(record["has_exploit"]),
            service_count=record["service_count"] or 0,
            vulns=vuln_list,
        )

        source_node = PathNode(ip=record["source"], role="scan_source")

        # Determine attack methods from vulns
        methods = _get_attack_methods(vuln_list)

        path = AttackPath(
            nodes=[source_node, target_node],
            target_role=target_node.role,
            hop_count=1,
            max_cvss=target_node.max_cvss,
            has_exploits=target_node.has_exploit,
            attack_methods=methods,
        )
        paths.append(path)

    return paths


def _find_pivot_paths(
    session, target_role: str | None, target_ip: str | None
) -> list[AttackPath]:
    """Find attack paths through true pivot hosts.

    A true pivot exists when:
    - Host X was scanned by ScanSource A (external scan)
    - Host X.ip matches ScanSource B.name (internal scan from compromised X)
    - Host X has RCE vulnerability (enables_pivot = true)
    - ScanSource B discovered additional hosts not in ScanSource A

    Path: ScanSource A -> Host X (pivot) -> Target (discovered by ScanSource B)
    """
    # Find pivot hosts: Host.ip == ScanSource.name for a different scan
    pivot_result = session.run(
        """
        MATCH (src_ext:ScanSource)-[:SCANNED_FROM]->(pivot:Host)
        MATCH (src_int:ScanSource)
        WHERE pivot.ip = src_int.name AND src_ext.name <> src_int.name
        MATCH (pivot)-[:HAS_SERVICE]->(s:Service)-[:HAS_VULN]->(v:Vulnerability)
        WHERE v.enables_pivot = true OR v.enables_pivot IS NULL
        RETURN DISTINCT src_ext.name AS external_source,
               pivot.ip AS pivot_ip,
               src_int.name AS internal_source,
               max(v.cvss) AS pivot_cvss
        """
    )

    pivot_hosts = list(pivot_result)
    if not pivot_hosts:
        return []

    paths = []
    for pivot_rec in pivot_hosts:
        ext_source = pivot_rec["external_source"]
        pivot_ip = pivot_rec["pivot_ip"]
        int_source = pivot_rec["internal_source"]

        # Get pivot host info
        pivot_info = _get_host_info(session, pivot_ip)
        if not pivot_info:
            continue

        # Build target filter for hosts discovered by the internal scan
        where_clauses = [
            "h.ip <> $pivot_ip",
        ]
        params: dict = {
            "int_source": int_source,
            "pivot_ip": pivot_ip,
        }

        if target_ip:
            where_clauses.append("h.ip = $target_ip")
            params["target_ip"] = target_ip
        elif target_role:
            where_clauses.append("h.role = $target_role")
            params["target_role"] = target_role

        where_str = " AND ".join(where_clauses)

        # Find targets discovered by the internal scan that have vulns
        target_result = session.run(
            f"""
            MATCH (src:ScanSource {{name: $int_source}})-[:SCANNED_FROM]->(h:Host)
            MATCH (h)-[:HAS_SERVICE]->(s:Service)-[:HAS_VULN]->(v:Vulnerability)
            WHERE {where_str}
            WITH h,
                 collect(DISTINCT {{
                     cve: v.cve_id, cvss: v.cvss,
                     has_exploit: v.has_exploit, desc: v.description,
                     confidence: v.confidence, enables_pivot: v.enables_pivot
                 }}) AS vulns,
                 max(v.cvss) AS max_cvss,
                 max(CASE WHEN v.has_exploit = true THEN 1 ELSE 0 END) AS has_exploit
            OPTIONAL MATCH (h)-[:IN_SEGMENT]->(seg:NetworkSegment)
            OPTIONAL MATCH (h)-[:HAS_SERVICE]->(svc:Service)
            WITH h, vulns, max_cvss, has_exploit, seg,
                 count(DISTINCT svc) AS service_count
            RETURN h.ip AS ip, h.hostname AS hostname, h.role AS role,
                   seg.cidr AS segment, service_count,
                   max_cvss, has_exploit, vulns
            """,
            **params,
        )

        for target_rec in target_result:
            vuln_list = _parse_vulns(target_rec["vulns"])
            if not vuln_list:
                continue

            target_node = PathNode(
                ip=target_rec["ip"],
                hostname=target_rec["hostname"],
                role=target_rec["role"] or "unknown",
                segment=target_rec["segment"],
                max_cvss=target_rec["max_cvss"] or 0.0,
                has_exploit=bool(target_rec["has_exploit"]),
                service_count=target_rec["service_count"] or 0,
                vulns=vuln_list,
            )

            source_node = PathNode(ip=ext_source, role="scan_source")
            methods = ["pivot"] + _get_attack_methods(vuln_list)

            path = AttackPath(
                nodes=[source_node, pivot_info, target_node],
                target_role=target_node.role,
                hop_count=2,
                max_cvss=max(pivot_info.max_cvss, target_node.max_cvss),
                has_exploits=pivot_info.has_exploit or target_node.has_exploit,
                attack_methods=methods,
            )
            paths.append(path)

    return paths


def _parse_vulns(raw_vulns: list[dict]) -> list[VulnInfo]:
    """Parse raw vulnerability dicts into VulnInfo objects."""
    vulns = []
    for v in raw_vulns:
        if not v.get("cve"):
            continue
        method = _classify_attack_method(v)
        vulns.append(VulnInfo(
            cve_id=v["cve"],
            cvss=v.get("cvss") or 0.0,
            has_exploit=bool(v.get("has_exploit")),
            title=(v.get("desc") or "")[:80],
            confidence=v.get("confidence") or "check",
            enables_pivot=v.get("enables_pivot"),
            method=method,
        ))
    # Sort by confidence (confirmed first), then exploitable, then CVSS
    conf_order = {"confirmed": 0, "likely": 1, "check": 2}
    vulns.sort(key=lambda v: (conf_order.get(v.confidence, 2), -int(v.has_exploit), -v.cvss))
    return vulns


def _classify_attack_method(vuln: dict) -> str:
    """Classify the attack method based on vulnerability properties."""
    cve_id = vuln.get("cve", "")
    desc = (vuln.get("desc") or "").lower()

    # Script-detected findings
    if "relay" in desc or "signing" in desc.lower():
        return "relay"
    if "default" in desc and ("cred" in desc or "password" in desc):
        return "credential"
    if "anonymous" in desc or "anon" in desc:
        return "credential"

    # Exploit DB or NVD with exploit
    if vuln.get("has_exploit"):
        return "exploit"

    # CVE without known exploit
    if cve_id.startswith("CVE-"):
        return "cve"

    return "exploit"


def _get_attack_methods(vulns: list[VulnInfo]) -> list[str]:
    """Get unique attack methods from vulnerability list."""
    methods = []
    seen = set()
    for v in vulns:
        if v.method and v.method not in seen:
            methods.append(v.method)
            seen.add(v.method)
    return methods or ["direct"]


def _get_host_info(session, ip: str) -> PathNode | None:
    """Get enriched info about a host including vulnerability details."""
    result = session.run(
        """
        MATCH (h:Host {ip: $ip})
        OPTIONAL MATCH (h)-[:IN_SEGMENT]->(seg:NetworkSegment)
        OPTIONAL MATCH (h)-[:HAS_SERVICE]->(s:Service)
        OPTIONAL MATCH (s)-[:HAS_VULN]->(v:Vulnerability)
        RETURN h.ip AS ip, h.hostname AS hostname, h.role AS role,
               seg.cidr AS segment,
               count(DISTINCT s) AS service_count,
               max(v.cvss) AS max_cvss,
               max(CASE WHEN v.has_exploit = true THEN 1 ELSE 0 END) AS has_exploit,
               collect(DISTINCT {cve: v.cve_id, cvss: v.cvss,
                       has_exploit: v.has_exploit, desc: v.description,
                       confidence: v.confidence,
                       enables_pivot: v.enables_pivot}) AS vulns
        """,
        ip=ip,
    )
    record = result.single()
    if not record or not record["ip"]:
        return None

    vulns = _parse_vulns(record["vulns"])

    return PathNode(
        ip=record["ip"],
        hostname=record["hostname"],
        role=record["role"] or "unknown",
        segment=record["segment"],
        max_cvss=record["max_cvss"] or 0.0,
        has_exploit=bool(record["has_exploit"]),
        service_count=record["service_count"] or 0,
        vulns=vulns,
    )


def _score_path(path: AttackPath) -> float:
    """Score an attack path. Higher = more dangerous / easier to exploit.

    Scoring factors (max ~115):
    - Target value (0-30): DC highest, then DB, SIEM, CI/CD, etc.
    - CVSS contribution (0-35): non-linear -- critical vulns score much higher
    - Exploit availability (0-25): bonus for known exploits
    - Hop bonus (0-15): fewer hops = easier path
    - Attack method quality (0-10): exploit > relay > cve
    """
    score = 0.0

    # 1. Target value (0-30 points)
    target_value = {
        "domain_controller": 30.0,
        "database": 25.0,
        "siem": 24.0,
        "ci_cd": 23.0,
        "hypervisor": 22.0,
        "mail_server": 20.0,
        "management": 19.0,
        "backup": 18.0,
        "file_server": 15.0,
        "web_server": 10.0,
        "dns_server": 8.0,
    }
    score += target_value.get(path.target_role, 5.0)

    # 2. CVSS contribution (0-35 points) -- non-linear curve
    max_cvss = max((n.max_cvss for n in path.nodes), default=0.0)
    if max_cvss >= 9.0:
        score += 35.0
    elif max_cvss >= 7.0:
        score += 25.0 + (max_cvss - 7.0) * 5.0
    elif max_cvss >= 4.0:
        score += 10.0 + (max_cvss - 4.0) * 5.0
    else:
        score += max_cvss * 2.5

    # 3. Exploit availability (0-25 points) -- scaled by confidence
    if path.has_exploits:
        confidence = path.max_confidence
        if confidence == "confirmed":
            score += 25.0
        elif confidence == "likely":
            score += 15.0
        else:  # check
            score += 5.0

    # 4. Hop bonus (0-15 points) -- steeper penalty for multi-hop
    hop_bonus = {1: 15.0, 2: 8.0, 3: 3.0}.get(path.hop_count, 0.0)
    score += hop_bonus

    # 5. Attack method quality (0-10 points)
    method_scores = {"exploit": 3.0, "relay": 2.5, "credential": 2.0, "cve": 1.0}
    method_bonus = sum(method_scores.get(m, 0.0) for m in path.attack_methods)
    score += min(method_bonus, 10.0)

    return round(score, 1)


def get_path_summary() -> dict:
    """Get attack path statistics for display."""
    with get_session() as session:
        # Count vulnerable hosts (hosts with at least one vuln)
        vuln_result = session.run(
            """
            MATCH (src:ScanSource)-[:SCANNED_FROM]->(h:Host)
                  -[:HAS_SERVICE]->(s:Service)-[:HAS_VULN]->(v:Vulnerability)
            WITH DISTINCT h, max(v.cvss) AS max_cvss,
                 max(CASE WHEN v.has_exploit = true THEN 1 ELSE 0 END) AS has_exploit,
                 max(CASE WHEN v.confidence = 'confirmed' THEN 3
                          WHEN v.confidence = 'likely' THEN 2
                          ELSE 1 END) AS conf_level
            RETURN count(h) AS total,
                   count(CASE WHEN has_exploit = 1 THEN 1 END) AS with_exploits,
                   count(CASE WHEN conf_level >= 3 THEN 1 END) AS confirmed,
                   count(CASE WHEN conf_level = 2 THEN 1 END) AS likely
            """
        )
        vuln_record = vuln_result.single()

        # Count high-value targets
        target_result = session.run(
            """
            MATCH (h:Host)
            WHERE h.role IN $roles
            RETURN h.role AS role, count(h) AS cnt
            """,
            roles=HIGH_VALUE_ROLES,
        )
        targets = {r["role"]: r["cnt"] for r in target_result}

        # Detect true pivot hosts
        pivot_result = session.run(
            """
            MATCH (h:Host), (src:ScanSource)
            WHERE h.ip = src.name
            MATCH (ext:ScanSource)-[:SCANNED_FROM]->(h)
            WHERE ext.name <> src.name
            RETURN count(DISTINCT h.ip) AS pivot_hosts
            """
        )
        pivot_record = pivot_result.single()

        return {
            "vulnerable_hosts": vuln_record["total"] if vuln_record else 0,
            "with_exploits": vuln_record["with_exploits"] if vuln_record else 0,
            "confirmed": vuln_record["confirmed"] if vuln_record else 0,
            "likely": vuln_record["likely"] if vuln_record else 0,
            "high_value_targets": targets,
            "pivot_hosts": pivot_record["pivot_hosts"] if pivot_record else 0,
        }
