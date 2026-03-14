"""Attack path discovery and scoring engine.

Finds paths through the network graph from scan sources to high-value
targets (Domain Controllers, databases, etc.), scores them by
exploitability, and creates PIVOT_TO relationships.
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
]

# Roles that are good pivot points
PIVOT_ROLES = {
    "web_server",
    "remote_access",
    "mail_server",
    "file_server",
    "voip",
    "printer",
}

# Difficulty ratings for pivot methods
PIVOT_DIFFICULTY = {
    "exploit": "easy",      # known exploit available
    "vuln_service": "medium",  # vulnerable service, no known exploit
    "shared_segment": "hard",  # same segment, no known vuln
}


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


@dataclass
class AttackPath:
    """A discovered attack path from source to target."""

    nodes: list[PathNode] = field(default_factory=list)
    target_role: str = "unknown"
    score: float = 0.0
    hop_count: int = 0
    max_cvss: float = 0.0
    has_exploits: bool = False
    pivot_methods: list[str] = field(default_factory=list)

    @property
    def source_ip(self) -> str:
        return self.nodes[0].ip if self.nodes else ""

    @property
    def target_ip(self) -> str:
        return self.nodes[-1].ip if self.nodes else ""


def discover_attack_paths(
    target_role: str | None = None,
    target_ip: str | None = None,
    max_depth: int = 6,
) -> list[AttackPath]:
    """Discover attack paths from scan sources to high-value targets.

    Args:
        target_role: Filter paths to targets with this role (e.g. "domain_controller").
        target_ip: Find paths to a specific host IP.
        max_depth: Maximum path length (hops).

    Returns:
        List of AttackPath objects, sorted by score (highest first).
    """
    paths = []

    with get_session() as session:
        if target_ip:
            # Paths to a specific host
            paths = _find_paths_to_host(session, target_ip, max_depth)
        elif target_role:
            # Paths to all hosts with a specific role
            paths = _find_paths_to_role(session, target_role, max_depth)
        else:
            # Paths to all high-value targets
            for role in HIGH_VALUE_ROLES:
                role_paths = _find_paths_to_role(session, role, max_depth)
                paths.extend(role_paths)

    # Add paths discovered via PIVOT_TO chains (including AI-created)
    with get_session() as session:
        pivot_paths = _find_pivot_chain_paths(session, target_ip, target_role)
        paths.extend(pivot_paths)

    # Score all paths
    for path in paths:
        path.score = _score_path(path)

    # Deduplicate by full path (sequence of IPs), keep highest scoring
    seen: dict[tuple, AttackPath] = {}
    for path in paths:
        key = tuple(n.ip for n in path.nodes)
        if key not in seen or path.score > seen[key].score:
            seen[key] = path

    paths = list(seen.values())
    paths.sort(key=lambda p: p.score, reverse=True)
    return paths


def _find_paths_to_role(session, role: str, max_depth: int) -> list[AttackPath]:
    """Find paths from scan sources to all hosts with given role."""
    # Find target hosts
    result = session.run(
        "MATCH (h:Host {role: $role}) RETURN h.ip AS ip",
        role=role,
    )
    target_ips = [r["ip"] for r in result]

    paths = []
    for ip in target_ips:
        paths.extend(_find_paths_to_host(session, ip, max_depth))
    return paths


def _find_paths_to_host(session, target_ip: str, max_depth: int) -> list[AttackPath]:
    """Find paths from scan sources to a specific host.

    Strategy:
    1. Segment-level paths via CAN_REACH (fast, coarse)
    2. Host-level paths via shared segments (detailed)
    """
    paths = []

    # Get target info
    target_info = _get_host_info(session, target_ip)
    if not target_info:
        return []

    # Find scan sources
    sources = session.run(
        "MATCH (s:ScanSource) RETURN s.name AS name"
    )
    source_names = [r["name"] for r in sources]

    for source_name in source_names:
        # Get hosts the source scanned that are in the same segment as target
        # or in segments that CAN_REACH the target's segment
        path = _build_path(session, source_name, target_ip, target_info, max_depth)
        if path and len(path.nodes) >= 2:
            paths.append(path)

    return paths


def _build_path(
    session, source_name: str, target_ip: str, target_info: PathNode, max_depth: int
) -> AttackPath | None:
    """Build a single attack path from source to target.

    Uses the graph to find intermediate hosts that could serve as pivots.
    """
    target_segment = target_info.segment

    # Get all hosts scanned by this source, grouped by segment
    result = session.run(
        """
        MATCH (src:ScanSource {name: $source})-[:SCANNED_FROM]->(h:Host)
        OPTIONAL MATCH (h)-[:IN_SEGMENT]->(seg:NetworkSegment)
        OPTIONAL MATCH (h)-[:HAS_SERVICE]->(s:Service)
        OPTIONAL MATCH (s)-[:HAS_VULN]->(v:Vulnerability)
        RETURN h.ip AS ip, h.hostname AS hostname, h.role AS role,
               seg.cidr AS segment,
               count(DISTINCT s) AS service_count,
               max(v.cvss) AS max_cvss,
               max(CASE WHEN v.has_exploit = true THEN 1 ELSE 0 END) AS has_exploit
        """,
        source=source_name,
    )

    hosts_by_segment: dict[str, list[PathNode]] = {}
    all_hosts: dict[str, PathNode] = {}

    for record in result:
        node = PathNode(
            ip=record["ip"],
            hostname=record["hostname"],
            role=record["role"] or "unknown",
            segment=record["segment"],
            max_cvss=record["max_cvss"] or 0.0,
            has_exploit=bool(record["has_exploit"]),
            service_count=record["service_count"] or 0,
        )
        all_hosts[node.ip] = node
        if node.segment:
            hosts_by_segment.setdefault(node.segment, []).append(node)

    # If target is directly scanned by this source
    if target_ip in all_hosts:
        source_node = PathNode(ip=source_name, role="scan_source")
        path = AttackPath(
            nodes=[source_node, all_hosts[target_ip]],
            target_role=target_info.role,
            hop_count=1,
            max_cvss=target_info.max_cvss,
            has_exploits=target_info.has_exploit,
            pivot_methods=["direct"],
        )
        return path

    # Find a pivot: host in a segment that can reach the target's segment
    if not target_segment:
        return None

    # Check if any scanned host is in the same segment as target
    same_segment_hosts = hosts_by_segment.get(target_segment, [])
    if same_segment_hosts:
        # Direct segment access — pick best pivot
        pivot = _pick_best_pivot(same_segment_hosts)
        source_node = PathNode(ip=source_name, role="scan_source")
        path = AttackPath(
            nodes=[source_node, pivot, target_info],
            target_role=target_info.role,
            hop_count=2,
            max_cvss=max(pivot.max_cvss, target_info.max_cvss),
            has_exploits=pivot.has_exploit or target_info.has_exploit,
            pivot_methods=_determine_pivot_methods(pivot, target_info),
        )
        return path

    # Try to find a multi-hop path via CAN_REACH segments
    result = session.run(
        """
        MATCH (src_seg:NetworkSegment)<-[:IN_SEGMENT]-(pivot:Host)<-[:SCANNED_FROM]-(ss:ScanSource {name: $source})
        MATCH path = (src_seg)-[:CAN_REACH*1..3]->(tgt_seg:NetworkSegment {cidr: $target_seg})
        OPTIONAL MATCH (pivot)-[:HAS_SERVICE]->(s:Service)-[:HAS_VULN]->(v:Vulnerability)
        RETURN DISTINCT pivot.ip AS pivot_ip, pivot.hostname AS pivot_hostname,
               pivot.role AS pivot_role, src_seg.cidr AS pivot_segment,
               max(v.cvss) AS pivot_max_cvss,
               max(CASE WHEN v.has_exploit = true THEN 1 ELSE 0 END) AS pivot_has_exploit,
               length(path) AS seg_hops
        ORDER BY seg_hops
        LIMIT 5
        """,
        source=source_name,
        target_seg=target_segment,
    )

    for record in result:
        pivot_node = PathNode(
            ip=record["pivot_ip"],
            hostname=record["pivot_hostname"],
            role=record["pivot_role"] or "unknown",
            segment=record["pivot_segment"],
            max_cvss=record["pivot_max_cvss"] or 0.0,
            has_exploit=bool(record["pivot_has_exploit"]),
        )
        source_node = PathNode(ip=source_name, role="scan_source")
        path = AttackPath(
            nodes=[source_node, pivot_node, target_info],
            target_role=target_info.role,
            hop_count=1 + (record["seg_hops"] or 1),
            max_cvss=max(pivot_node.max_cvss, target_info.max_cvss),
            has_exploits=pivot_node.has_exploit or target_info.has_exploit,
            pivot_methods=_determine_pivot_methods(pivot_node, target_info),
        )
        return path  # Return first (shortest) path found

    return None


def _find_pivot_chain_paths(
    session, target_ip: str | None, target_role: str | None
) -> list[AttackPath]:
    """Find multi-hop attack paths by traversing PIVOT_TO relationships.

    This picks up AI-created chains and exploit-based pivots that
    segment-level path discovery misses.
    """
    # Build target filter
    if target_ip:
        target_clause = "AND target.ip = $target_ip"
        params = {"target_ip": target_ip, "roles": HIGH_VALUE_ROLES}
    elif target_role:
        target_clause = "AND target.role = $target_role"
        params = {"target_role": target_role, "roles": [target_role]}
    else:
        target_clause = "AND target.role IN $roles"
        params = {"roles": HIGH_VALUE_ROLES}

    result = session.run(
        f"""
        MATCH (src:ScanSource)-[:SCANNED_FROM]->(entry:Host)
        MATCH path = (entry)-[:PIVOT_TO*1..4]->(target:Host)
        WHERE target.role IN $roles {target_clause}
        AND entry.ip <> target.ip
        WITH src, entry, target, path,
             [n IN nodes(path) | n.ip] AS ips,
             [r IN relationships(path) | r.method] AS methods,
             [r IN relationships(path) | r.difficulty] AS difficulties
        RETURN DISTINCT
            src.name AS source,
            ips,
            methods,
            difficulties,
            target.role AS target_role
        ORDER BY size(ips)
        LIMIT 20
        """,
        **params,
    )

    paths = []
    for record in result:
        ips = record["ips"]
        methods = record["methods"]
        source_name = record["source"]

        # Build path nodes with enriched info
        nodes = [PathNode(ip=source_name, role="scan_source")]
        max_cvss = 0.0
        has_exploits = False

        for ip in ips:
            info = _get_host_info(session, ip)
            if info:
                nodes.append(info)
                max_cvss = max(max_cvss, info.max_cvss)
                if info.has_exploit:
                    has_exploits = True
            else:
                nodes.append(PathNode(ip=ip))

        path = AttackPath(
            nodes=nodes,
            target_role=record["target_role"] or "unknown",
            hop_count=len(ips),  # source->entry is 1 hop + PIVOT_TO hops
            max_cvss=max_cvss,
            has_exploits=has_exploits or any(m == "exploit" for m in methods),
            pivot_methods=methods,
        )
        paths.append(path)

    return paths


def _get_host_info(session, ip: str) -> PathNode | None:
    """Get enriched info about a host."""
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
               max(CASE WHEN v.has_exploit = true THEN 1 ELSE 0 END) AS has_exploit
        """,
        ip=ip,
    )
    record = result.single()
    if not record or not record["ip"]:
        return None

    return PathNode(
        ip=record["ip"],
        hostname=record["hostname"],
        role=record["role"] or "unknown",
        segment=record["segment"],
        max_cvss=record["max_cvss"] or 0.0,
        has_exploit=bool(record["has_exploit"]),
        service_count=record["service_count"] or 0,
    )


def _pick_best_pivot(hosts: list[PathNode]) -> PathNode:
    """Pick the best pivot host from a list (most exploitable)."""
    return max(hosts, key=lambda h: (
        h.has_exploit,
        h.max_cvss,
        h.role in PIVOT_ROLES,
        h.service_count,
    ))


def _determine_pivot_methods(pivot: PathNode, target: PathNode) -> list[str]:
    """Determine how an attacker could pivot from one host to another."""
    methods = []
    if pivot.has_exploit:
        methods.append("exploit")
    if pivot.max_cvss > 0:
        methods.append("vuln_service")
    if not methods:
        methods.append("shared_segment")
    return methods


def _score_path(path: AttackPath) -> float:
    """Score an attack path. Higher = more dangerous / easier to exploit.

    Scoring factors:
    - CVSS of vulnerabilities along the path (higher = easier to exploit)
    - Exploit availability (big bonus)
    - Fewer hops = easier path
    - Target value (DC > DB > mail > file_server)
    """
    score = 0.0

    # Target value score (0-30 points)
    target_value = {
        "domain_controller": 30.0,
        "database": 25.0,
        "hypervisor": 22.0,
        "mail_server": 20.0,
        "file_server": 15.0,
        "web_server": 10.0,
        "dns_server": 8.0,
    }
    score += target_value.get(path.target_role, 5.0)

    # CVSS score contribution (0-30 points)
    # Max CVSS across all nodes in the path
    max_cvss = max((n.max_cvss for n in path.nodes), default=0.0)
    score += max_cvss * 3.0  # Scale: 10.0 CVSS → 30 points

    # Exploit availability (0-25 points)
    if path.has_exploits:
        score += 25.0

    # Hop penalty (fewer hops = better)
    # 1 hop = 15 bonus, 2 hops = 10, 3 = 5, 4+ = 0
    hop_bonus = max(0.0, 15.0 - (path.hop_count - 1) * 5.0)
    score += hop_bonus

    return round(score, 1)


def build_pivot_relationships() -> dict:
    """Create PIVOT_TO relationships between hosts in adjacent segments.

    A host can pivot to another if:
    - They share a network segment, OR
    - The source host has a vulnerability with an exploit, AND
    - The target host is in a reachable segment

    Returns:
        Dict with pivot relationship statistics.
    """
    stats = {"pivots_created": 0, "pairs_analyzed": 0}

    with get_session() as session:
        # Create PIVOT_TO between hosts in the same segment
        # where at least one has an exploitable vulnerability
        result = session.run(
            """
            MATCH (h1:Host)-[:IN_SEGMENT]->(seg:NetworkSegment)<-[:IN_SEGMENT]-(h2:Host)
            WHERE h1.ip < h2.ip
            AND h1.role <> 'unknown' AND h2.role <> 'unknown'
            OPTIONAL MATCH (h1)-[:HAS_SERVICE]->(s1:Service)-[:HAS_VULN]->(v1:Vulnerability)
            OPTIONAL MATCH (h2)-[:HAS_SERVICE]->(s2:Service)-[:HAS_VULN]->(v2:Vulnerability)
            WITH h1, h2,
                 max(v1.cvss) AS h1_cvss, max(v2.cvss) AS h2_cvss,
                 max(CASE WHEN v1.has_exploit = true THEN 1 ELSE 0 END) AS h1_exploit,
                 max(CASE WHEN v2.has_exploit = true THEN 1 ELSE 0 END) AS h2_exploit
            RETURN h1.ip AS ip1, h2.ip AS ip2,
                   COALESCE(h1_cvss, 0) AS h1_cvss, COALESCE(h2_cvss, 0) AS h2_cvss,
                   h1_exploit AS h1_exploit, h2_exploit AS h2_exploit
            """
        )

        pairs = list(result)
        stats["pairs_analyzed"] = len(pairs)

        for record in pairs:
            ip1, ip2 = record["ip1"], record["ip2"]
            h1_cvss = record["h1_cvss"]
            h2_cvss = record["h2_cvss"]
            h1_exploit = record["h1_exploit"]
            h2_exploit = record["h2_exploit"]

            # Determine pivot method: exploit > vuln_service > shared_segment
            # h1 -> h2 direction
            if h1_exploit:
                method_fwd, diff_fwd = "exploit", "easy"
            elif h1_cvss > 0:
                method_fwd, diff_fwd = "vuln_service", "medium"
            else:
                method_fwd, diff_fwd = "shared_segment", "hard"

            session.run(
                """
                MATCH (h1:Host {ip: $ip1}), (h2:Host {ip: $ip2})
                MERGE (h1)-[p:PIVOT_TO]->(h2)
                SET p.method = $method, p.difficulty = $difficulty,
                    p.cvss = $cvss
                """,
                ip1=ip1, ip2=ip2, method=method_fwd,
                difficulty=diff_fwd, cvss=h1_cvss,
            )
            stats["pivots_created"] += 1

            # h2 -> h1 direction
            if h2_exploit:
                method_rev, diff_rev = "exploit", "easy"
            elif h2_cvss > 0:
                method_rev, diff_rev = "vuln_service", "medium"
            else:
                method_rev, diff_rev = "shared_segment", "hard"

            session.run(
                """
                MATCH (h1:Host {ip: $ip1}), (h2:Host {ip: $ip2})
                MERGE (h2)-[p:PIVOT_TO]->(h1)
                SET p.method = $method, p.difficulty = $difficulty,
                    p.cvss = $cvss
                """,
                ip1=ip1, ip2=ip2, method=method_rev,
                difficulty=diff_rev, cvss=h2_cvss,
            )
            stats["pivots_created"] += 1

    return stats


def get_path_summary() -> dict:
    """Get attack path statistics for display."""
    with get_session() as session:
        # Count PIVOT_TO relationships
        pivot_result = session.run(
            """
            MATCH ()-[p:PIVOT_TO]->()
            RETURN count(p) AS total,
                   count(CASE WHEN p.difficulty = 'easy' THEN 1 END) AS easy,
                   count(CASE WHEN p.difficulty = 'medium' THEN 1 END) AS medium,
                   count(CASE WHEN p.difficulty = 'hard' THEN 1 END) AS hard
            """
        )
        pivot_record = pivot_result.single()

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

        return {
            "total_pivots": pivot_record["total"] if pivot_record else 0,
            "easy_pivots": pivot_record["easy"] if pivot_record else 0,
            "medium_pivots": pivot_record["medium"] if pivot_record else 0,
            "hard_pivots": pivot_record["hard"] if pivot_record else 0,
            "high_value_targets": targets,
        }
