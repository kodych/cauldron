"""AI-powered network analysis using Claude API.

Four integrated AI phases that directly affect the graph:
1. CVE discovery — find vulnerabilities NVD missed based on product+version
2. Host classification — re-classify ambiguous hosts (anonymized)
3. Attack chain discovery — find non-obvious attack insights (anonymized)
4. False positive detection — AI reviews CVE assignments and marks misclassifications

Phases 2-4 anonymize all client data (IPs, hostnames) before sending to AI API.
Only product names, versions, ports, CVEs, and OS info are sent — these are public knowledge.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field

from cauldron.config import settings
from cauldron.graph.connection import get_session

logger = logging.getLogger(__name__)


@dataclass
class AIInsight:
    """A single insight discovered by AI analysis."""

    insight_type: str  # "attack_chain", "correlation", "chokepoint"
    confidence: float  # 0.0 - 1.0
    title: str
    details: str
    hosts: list[str] = field(default_factory=list)  # IPs involved
    cves: list[str] = field(default_factory=list)  # CVEs involved
    priority: int = 0  # 1 = highest, 5 = lowest


@dataclass
class AnalysisResult:
    """Result of AI analysis run."""

    cves_found: int = 0
    services_enriched: int = 0
    ambiguous_classified: int = 0
    insights: list[AIInsight] = field(default_factory=list)
    pivots_created: int = 0
    false_positives_found: int = 0
    vulns_kept: int = 0
    vulns_dismissed: int = 0


def is_ai_available() -> bool:
    """Check if AI features are available (API key configured)."""
    return bool(settings.anthropic_api_key)


def analyze_graph() -> AnalysisResult:
    """Run all AI analysis phases on the current graph.

    Phase 1: Find CVEs that NVD missed (based on product+version).
    Phase 2: Re-classify ambiguous hosts.
    Phase 3: Discover attack chains → create PIVOT_TO relationships.

    Returns:
        AnalysisResult with all findings.
    """
    if not is_ai_available():
        logger.warning("AI analysis skipped: CAULDRON_ANTHROPIC_API_KEY not set")
        return AnalysisResult()

    result = AnalysisResult()

    # Phase 1: AI CVE enrichment (most impactful — fills the CVSS/exploit columns)
    cves, services = _ai_enrich_cves()
    result.cves_found = cves
    result.services_enriched = services

    # Phase 2: Re-classify ambiguous hosts
    result.ambiguous_classified = _classify_ambiguous_hosts()

    # Phase 3: Contextual engagement triage
    # AI reviews ALL vulns with engagement context (owned/target/scan sources)
    # and dismisses noise — keeping only gold findings
    kept, dismissed = _contextual_vuln_triage()
    result.vulns_kept = kept
    result.vulns_dismissed = dismissed
    result.false_positives_found = dismissed

    return result


# ---------------------------------------------------------------------------
# Phase 1: AI CVE Enrichment
# ---------------------------------------------------------------------------


def _ai_enrich_cves() -> tuple[int, int]:
    """Ask AI to identify CVEs for services that NVD couldn't match.

    Uses index-based referencing to avoid product name mismatch between
    AI response and Neo4j data.

    Returns:
        (total_cves_created, services_enriched)
    """
    # Get services with product+version but no CVEs
    with get_session() as session:
        result = session.run(
            """
            MATCH (h:Host)-[:HAS_SERVICE]->(s:Service)
            WHERE s.product IS NOT NULL AND s.version IS NOT NULL
            AND NOT (s)-[:HAS_VULN]->(:Vulnerability)
            RETURN DISTINCT s.product AS product, s.version AS version
            """
        )
        pairs = [(r["product"], r["version"]) for r in result]

    if not pairs:
        return 0, 0

    # Build indexed prompt — AI returns index, we match by original product+version
    lines = [f"{i}. {p} {v}" for i, (p, v) in enumerate(pairs)]
    prompt = f"""You are a vulnerability researcher. For each software product+version below, list known CVEs with CVSS scores.

Products:
{chr(10).join(lines)}

Respond with ONLY a JSON array:
[{{"index": 0, "cves": [{{"cve_id": "CVE-YYYY-NNNNN", "cvss": 7.5, "severity": "HIGH", "has_exploit": true, "description": "brief"}}]}}]

Rules:
- "index" must match the product number from the list above
- Only include REAL, published CVEs (no guessing)
- Include CVSS v3.1 score
- has_exploit = true only if public exploit exists (ExploitDB, Metasploit, GitHub PoC)
- If no known CVEs for a product, omit it from the array
- Focus on pentester-relevant CVEs: RCE, auth bypass, privesc, not DoS or info disclosure
- Respond with ONLY the JSON, no other text"""

    response = _call_claude(prompt, max_tokens=2048)
    if not response:
        return 0, 0

    return _apply_ai_cves(response, pairs)


def _apply_ai_cves(response: str, pairs: list[tuple[str, str]] | None = None) -> tuple[int, int]:
    """Parse AI CVE response and create Vulnerability nodes.

    Uses index-based matching: AI returns {"index": N} which maps to
    the original product+version pair, avoiding name mismatch issues.
    """
    data = _parse_json_response(response)
    if not isinstance(data, list):
        return 0, 0

    total_cves = 0
    services_enriched = 0

    with get_session() as session:
        for item in data:
            if not isinstance(item, dict):
                continue

            # Resolve product+version from index or fallback to direct fields
            idx = item.get("index")
            if idx is not None and pairs and isinstance(idx, int) and 0 <= idx < len(pairs):
                product, version = pairs[idx]
            else:
                product = item.get("product")
                version = item.get("version")

            cves = item.get("cves", [])
            if not product or not version or not cves:
                continue

            svc_cve_count = 0
            for cve in cves:
                if not isinstance(cve, dict):
                    continue
                cve_id = cve.get("cve_id", "")
                if not cve_id.startswith("CVE-"):
                    continue

                # Verify CVE via NVD API — never trust AI-generated CVSS/description
                from cauldron.ai.cve_enricher import verify_cve_via_nvd

                verified = verify_cve_via_nvd(cve_id)
                if verified:
                    # Use real NVD data instead of AI hallucinations
                    cvss = verified.cvss or 0.0
                    severity = verified.severity or "MEDIUM"
                    has_exploit = verified.has_exploit
                    description = verified.description or ""
                    exploit_url = verified.exploit_url
                else:
                    # CVE not in NVD or rejected — skip it entirely
                    logger.info("AI CVE %s not verified by NVD — skipping", cve_id)
                    continue

                # Create Vulnerability node with verified NVD data
                session.run(
                    """
                    MERGE (v:Vulnerability {cve_id: $cve_id})
                    ON CREATE SET
                        v.cvss = $cvss, v.severity = $severity,
                        v.has_exploit = $has_exploit, v.description = $description,
                        v.exploit_url = $exploit_url,
                        v.source = 'ai', v.confidence = 'check'
                    """,
                    cve_id=cve_id, cvss=cvss, severity=severity,
                    has_exploit=has_exploit, description=description,
                    exploit_url=exploit_url,
                )

                # Link to matching services using exact product+version from our data
                # Count only NEW links (not already existing)
                link_result = session.run(
                    """
                    MATCH (s:Service)
                    WHERE s.product = $product AND s.version = $version
                    AND NOT (s)-[:HAS_VULN]->(:Vulnerability {cve_id: $cve_id})
                    MATCH (v:Vulnerability {cve_id: $cve_id})
                    MERGE (s)-[:HAS_VULN]->(v)
                    RETURN count(s) AS linked
                    """,
                    product=product, version=version, cve_id=cve_id,
                )
                linked = link_result.single()
                new_links = linked["linked"] if linked else 0
                if new_links > 0:
                    svc_cve_count += 1
                    total_cves += 1
                    logger.info("AI linked %s to %s %s (%d services)", cve_id, product, version, new_links)

            if svc_cve_count > 0:
                services_enriched += 1

    return total_cves, services_enriched


# ---------------------------------------------------------------------------
# Phase 2: Host Classification
# ---------------------------------------------------------------------------


def _classify_ambiguous_hosts() -> int:
    """Use AI to classify hosts where rule-based classifier has low confidence.

    Anonymized: real IPs replaced with host-N aliases before sending to AI.
    """
    with get_session() as session:
        result = session.run(
            """
            MATCH (h:Host)
            WHERE h.role_confidence < 0.6 AND h.role_confidence > 0
            OPTIONAL MATCH (h)-[:HAS_SERVICE]->(s:Service)
            WITH h, collect({port: s.port, protocol: s.protocol,
                            name: s.name, product: s.product, version: s.version}) AS services
            RETURN h.ip AS ip, h.hostname AS hostname, h.role AS current_role,
                   h.role_confidence AS confidence, services
            LIMIT 15
            """
        )
        hosts = list(result)

    if not hosts:
        return 0

    ip_map, reverse_map = _build_anonymization_map([h["ip"] for h in hosts])

    # Compact prompt with anonymized IPs, no hostnames
    lines = []
    for h in hosts:
        alias = ip_map[h["ip"]]
        svcs = [f"{s['port']}/{s.get('protocol', 'tcp')} {s.get('product', s.get('name', ''))}"
                for s in h["services"] if s.get("port")]
        lines.append(f"{alias}: {', '.join(svcs[:10]) if svcs else 'no services'}")

    prompt = f"""Classify these network hosts by role based on their services.

Roles: domain_controller, web_server, database, mail_server, file_server, network_equipment, printer, voip, remote_access, hypervisor, dns_server, proxy, monitoring, siem, ci_cd, vpn_gateway, backup, unknown

Hosts:
{chr(10).join(lines)}

Respond with ONLY JSON: [{{"id": "host-N", "role": "role_name", "confidence": 0.0-1.0}}]
Only include hosts where confidence > 0.6."""

    response = _call_claude(prompt, max_tokens=1024)
    if not response:
        return 0

    classifications = _parse_classification_response(response, reverse_map)
    return _apply_classifications(classifications)


# ---------------------------------------------------------------------------
# Phase 3: Contextual Engagement Triage
# ---------------------------------------------------------------------------


def _contextual_vuln_triage() -> tuple[int, int]:
    """AI reviews all vulns with engagement context and triages them.

    AI sees: scan sources (our positions), owned hosts, target hosts,
    all hosts with their vulns. Returns keep/dismiss verdicts.

    Rules:
    - Remote RCE/auth_bypass on non-owned hosts: KEEP
    - Local privesc on owned hosts: KEEP
    - Local privesc on non-owned hosts: DISMISS
    - OS mismatch (Linux CVE on Windows, vice versa): DISMISS
    - Wrong product (dependency CVE, name collision): DISMISS
    - Remote vulns on owned hosts: KEEP but lower priority
    - Never override user decisions (checked_status IS NOT NULL)

    Returns:
        (vulns_kept, vulns_dismissed)
    """
    # Gather engagement context
    with get_session() as session:
        scan_sources = [r["name"] for r in session.run(
            "MATCH (ss:ScanSource) RETURN ss.name AS name"
        )]
        owned_hosts = [r["ip"] for r in session.run(
            "MATCH (h:Host) WHERE h.owned = true RETURN h.ip AS ip"
        )]
        target_hosts = [r["ip"] for r in session.run(
            "MATCH (h:Host) WHERE h.target = true RETURN h.ip AS ip, h.role AS role"
        )]

        # Get all hosts with untriaged vulns
        rows = list(session.run("""
            MATCH (h:Host)-[:HAS_SERVICE]->(s:Service)-[r:HAS_VULN]->(v:Vulnerability)
            WHERE r.checked_status IS NULL
            RETURN h.ip AS ip, h.os_name AS os_name, h.role AS role,
                   h.owned AS owned, h.target AS target,
                   s.port AS port, s.product AS product, s.version AS version,
                   v.cve_id AS cve_id, v.cvss AS cvss, v.has_exploit AS has_exploit,
                   v.description AS description, v.source AS source,
                   v.cvss_vector AS cvss_vector
            ORDER BY h.ip, s.port
        """))

    if not rows:
        return 0, 0

    # Group by host
    host_data: dict[str, dict] = {}
    for row in rows:
        ip = row["ip"]
        if ip not in host_data:
            host_data[ip] = {
                "ip": ip,
                "os": row["os_name"],
                "role": row["role"],
                "owned": bool(row.get("owned")),
                "target": bool(row.get("target")),
                "vulns": [],
            }
        # Detect local-only from CVSS vector
        is_local = False
        vec = row.get("cvss_vector") or ""
        if "AV:L" in vec or "AV:P" in vec:
            is_local = True

        host_data[ip]["vulns"].append({
            "port": row["port"],
            "product": row["product"],
            "version": row["version"],
            "cve_id": row["cve_id"],
            "cvss": row["cvss"],
            "has_exploit": row["has_exploit"],
            "description": (row["description"] or "")[:120],
            "source": row["source"],
            "is_local": is_local,
        })

    hosts = list(host_data.values())
    all_ips = [h["ip"] for h in hosts] + scan_sources + owned_hosts + target_hosts
    ip_map, reverse_map = _build_anonymization_map(list(set(all_ips)))

    # Build context header
    src_aliases = [ip_map.get(s, s) for s in scan_sources]
    owned_aliases = [ip_map.get(o, o) for o in owned_hosts]
    target_lines = []
    for r in target_hosts:
        ip = r if isinstance(r, str) else r
        alias = ip_map.get(ip, ip)
        # Find role from host_data
        role = host_data.get(ip, {}).get("role", "unknown")
        target_lines.append(f"{alias} [{role}]")

    context = f"""=== ENGAGEMENT CONTEXT ===
SCAN SOURCES (our network positions): {', '.join(src_aliases) if src_aliases else 'none'}
OWNED HOSTS (we have shell/access): {', '.join(owned_aliases) if owned_aliases else 'none'}
TARGET HOSTS (engagement goals): {', '.join(target_lines) if target_lines else 'none'}
"""

    # Batch hosts: 15 per API call
    total_kept = 0
    total_dismissed = 0

    for i in range(0, len(hosts), 15):
        batch = hosts[i:i + 15]
        batch_num = i // 15 + 1
        batch_total = (len(hosts) + 14) // 15
        logger.info("AI triage batch %d/%d (%d hosts)", batch_num, batch_total, len(batch))
        k, d = _triage_batch(batch, ip_map, reverse_map, context)
        logger.info("AI triage batch %d result: kept=%d, dismissed=%d", batch_num, k, d)
        total_kept += k
        total_dismissed += d

    return total_kept, total_dismissed


def _triage_batch(
    hosts: list[dict],
    ip_map: dict[str, str],
    reverse_map: dict[str, str],
    context: str,
) -> tuple[int, int]:
    """Send a batch of hosts to AI for contextual triage."""
    lines = []
    vuln_count = 0
    for h in hosts:
        alias = ip_map.get(h["ip"], h["ip"])
        role = h["role"] or "unknown"
        os_str = f" OS:{h['os']}" if h.get("os") else ""
        owned_tag = " [OWNED]" if h.get("owned") else ""
        target_tag = " [TARGET]" if h.get("target") else ""
        lines.append(f"\n{alias} [{role}]{os_str}{owned_tag}{target_tag}")
        for v in h["vulns"]:
            prod = f"{v['product']} {v['version']}" if v.get("product") else ""
            local_tag = " [LOCAL]" if v.get("is_local") else ""
            exploit_tag = " EXPLOIT" if v.get("has_exploit") else ""
            lines.append(
                f"  :{v['port']} {prod}  {v['cve_id']} "
                f"CVSS:{v['cvss'] or '?'}{exploit_tag}{local_tag} [{v['source']}]"
            )
            if v.get("description"):
                lines.append(f"    {v['description']}")
            vuln_count += 1

    prompt = f"""You are a penetration testing operator reviewing vulnerability findings.
Your job is to TRIAGE existing vulnerabilities into KEEP (gold — actionable for the engagement)
vs DISMISS (noise — not exploitable in this context).

=== VULNERABILITY SOURCES ===
Vulnerabilities come from three sources:
- [exploit_db] — Cauldron's built-in exploit database. IDs starting with "CAULDRON-" are
  pentester-focused rules (default creds, misconfigs, known exploits). These are HIGH VALUE
  and should almost always be KEPT. They represent real attack techniques.
- [nvd] — NVD CVE database. Standard CVE-YYYY-NNNNN format. Version-matched by NVD API.
- [ai] — AI-discovered CVEs, verified through NVD.

IMPORTANT: CAULDRON-* IDs are NOT errors or unknown formats. They are our exploit rules
and are typically MORE actionable than NVD CVEs because they focus on pentester techniques.

{context}

=== HOSTS WITH VULNERABILITIES ===
{''.join(lines)}

=== TRIAGE RULES ===
1. Remote RCE/auth bypass on NON-OWNED hosts: KEEP (attack surface)
2. Local privilege escalation on OWNED hosts: KEEP (we can use these for privesc)
3. Local exploits on NON-OWNED hosts: DISMISS (we can't use these — no access)
4. OS mismatch — Linux-only CVE on Windows host or vice versa: DISMISS
5. Wrong product — dependency CVE, name collision (e.g. Oracle library CVE on Exchange): DISMISS
6. Exploits requiring specific uncommon configurations: DISMISS with reason
7. Remote vulns on OWNED hosts: KEEP but note "already owned"
8. DoS-only without exploit on low-value targets: DISMISS
9. CAULDRON-* exploit rules: almost always KEEP — these are pentester-focused findings

CRITICAL: Do NOT dismiss based on version range comparison. NVD version matching is authoritative.
CRITICAL: Do NOT dismiss CAULDRON-* IDs just because they are not standard CVEs.
If unsure, KEEP. Missing a real vuln is worse than keeping noise.

Respond with ONLY JSON:
[{{"id": "host-N", "vulns": [
  {{"cve_id": "CVE-YYYY-NNNNN", "port": 443, "verdict": "keep"}},
  {{"cve_id": "CAULDRON-041", "port": 5432, "verdict": "keep"}},
  {{"cve_id": "CVE-YYYY-NNNNN", "port": 22, "verdict": "dismiss", "reason": "Local privesc, host not owned"}}
]}}]

Rules:
- "cve_id" field contains the vulnerability ID exactly as shown above (CVE-* or CAULDRON-*)
- verdict must be "keep" or "dismiss"
- reason required for dismiss, optional for keep
- Include ALL vulns for each host (don't omit any)
- Respond with ONLY the JSON, no other text"""

    response = _call_claude(prompt, max_tokens=4096)
    if not response:
        return vuln_count, 0  # If AI fails, keep everything

    return _apply_triage(response, reverse_map)


def _apply_triage(response: str, reverse_map: dict[str, str]) -> tuple[int, int]:
    """Parse triage response and apply dismiss verdicts to Neo4j."""
    data = _parse_json_response(response)
    if not isinstance(data, list):
        return 0, 0

    kept = 0
    dismissed = 0

    with get_session() as session:
        for item in data:
            if not isinstance(item, dict):
                continue
            alias = item.get("id", "")
            real_ip = reverse_map.get(alias, alias)

            for v in item.get("vulns", []):
                if not isinstance(v, dict):
                    continue
                verdict = v.get("verdict", "keep")
                cve_id = v.get("cve_id", "")
                port = v.get("port")

                if not cve_id or not isinstance(port, int):
                    continue

                if verdict == "dismiss":
                    reason = v.get("reason", "AI triage: not exploitable in engagement context")
                    result = session.run(
                        """
                        MATCH (h:Host {ip: $ip})-[:HAS_SERVICE]->(s:Service {port: $port})
                              -[r:HAS_VULN]->(v:Vulnerability {cve_id: $cve_id})
                        WHERE r.checked_status IS NULL
                        SET r.checked_status = 'false_positive',
                            r.ai_fp_reason = $reason
                        RETURN v.cve_id AS cve_id
                        """,
                        ip=real_ip, port=port, cve_id=cve_id, reason=reason,
                    )
                    if result.single():
                        dismissed += 1
                        logger.info("AI triage DISMISS: %s on %s:%d — %s", cve_id, real_ip, port, reason)
                elif verdict == "keep":
                    kept += 1

    return kept, dismissed


# ---------------------------------------------------------------------------
# Legacy Phase 3: Attack Chain Discovery (kept for reference)
# ---------------------------------------------------------------------------


def _discover_attack_insights() -> list[AIInsight]:
    """Discover non-obvious attack chains and insights.

    AI analyzes the full network map and identifies attack chains,
    chokepoints, and correlations. Results are returned as insights
    for display — no graph mutations.

    Anonymized: real IPs/hostnames replaced with aliases.
    """
    result = _get_network_summary()
    if result is None:
        return []
    summary, hostnames, all_ips = result

    ip_map, reverse_map = _build_anonymization_map(all_ips)
    anon_summary = _anonymize_text(summary, ip_map, hostnames)

    prompt = f"""You are a penetration tester. Analyze this network and find non-obvious attack insights.

The ATTACKER POSITIONS section shows hosts where the attacker already has access (scan was run from there).
Build attack chains FROM these positions — what can the attacker reach and compromise next?

{anon_summary}

Find:
1. Attack chains FROM attacker positions (what to target first and how to get there)
2. Lateral movement paths (which compromised host leads to which next target)
3. Chokepoint hosts (compromising one = access to many)
4. High-value targets reachable from current positions (domain controllers, databases, hypervisors)

IMPORTANT: Only report insights involving real exploitable vulnerabilities or confirmed misconfigurations.
Do NOT suggest checking for default credentials, null sessions, or anonymous access —
those are basic checks, not insights. Focus on known vulns and concrete attack techniques.

Use confidence levels:
- 0.9+ = confirmed (version-matched CVE with known exploit)
- 0.7-0.9 = likely (CVE exists, exploit probable but unverified)
- 0.5-0.7 = check (needs manual verification)

Respond with ONLY JSON array:
[{{
  "type": "attack_chain",
  "title": "short description",
  "hosts": ["host-1", "host-2"],
  "priority": 1-5,
  "confidence": 0.0-1.0,
  "details": "brief explanation of the attack technique"
}}]

Priority 1 = most critical. Only include findings with confidence > 0.5.
Respond with ONLY the JSON."""

    response = _call_claude(prompt, max_tokens=2048)
    if not response:
        return []

    return _parse_attack_insights(response, reverse_map)


def _get_network_summary() -> tuple[str, set[str], list[str]] | None:
    """Build a detailed network summary for AI analysis.

    Returns:
        Tuple of (summary_text, hostnames, all_ips) or None if graph is empty.
        Hostnames and IPs are provided for anonymization.
    """
    with get_session() as session:
        result = session.run(
            """
            MATCH (h:Host)
            WHERE h.state = 'up'
            OPTIONAL MATCH (h)-[:IN_SEGMENT]->(seg:NetworkSegment)
            OPTIONAL MATCH (h)-[:HAS_SERVICE]->(s:Service)
            OPTIONAL MATCH (s)-[:HAS_VULN]->(v:Vulnerability)
            WITH h, seg.cidr AS segment,
                 collect(DISTINCT {
                     port: s.port, protocol: s.protocol, name: s.name,
                     product: s.product, version: s.version, banner: s.banner
                 }) AS services,
                 collect(DISTINCT {
                     cve_id: v.cve_id, cvss: v.cvss, severity: v.severity,
                     has_exploit: v.has_exploit
                 }) AS vulns
            RETURN h.ip AS ip, h.hostname AS hostname, h.role AS role,
                   h.os_name AS os, segment, services, vulns
            ORDER BY segment, h.ip
            """
        )
        hosts = list(result)

        if not hosts:
            return None

        all_ips = [h["ip"] for h in hosts]
        hostnames = {h["hostname"] for h in hosts if h.get("hostname")}

        conn = session.run(
            "MATCH (s1:NetworkSegment)-[:CAN_REACH]->(s2:NetworkSegment) "
            "RETURN s1.cidr AS src, s2.cidr AS dst"
        )
        connectivity = list(conn)

        # Get scan sources (our positions in the network)
        scan_sources = session.run(
            "MATCH (ss:ScanSource) RETURN ss.name AS ip, ss.ip AS alt_ip"
        )
        source_ips = [r["ip"] or r["alt_ip"] for r in scan_sources if r["ip"] or r["alt_ip"]]

    lines = ["=== ATTACKER POSITIONS ==="]
    if source_ips:
        lines.append("These are the hosts where scans were run FROM (already compromised/controlled):")
        for sip in source_ips:
            lines.append(f"  {sip} [ATTACKER]")
    else:
        lines.append("  (unknown — external scan)")
    lines.extend(["", "=== NETWORK MAP ===", ""])

    current_segment = None
    for h in hosts:
        seg = h["segment"] or "unknown"
        if seg != current_segment:
            current_segment = seg
            lines.append(f"--- Segment: {seg} ---")

        role = h["role"] or "unknown"
        header = f"  {h['ip']} [{role}]"
        if h.get("hostname"):
            header += f" ({h['hostname']})"
        if h.get("os"):
            header += f" OS:{h['os']}"
        lines.append(header)

        services = [s for s in (h["services"] or []) if s.get("port")]
        for s in services:
            svc_line = f"    {s['port']}/{s.get('protocol', 'tcp')}"
            if s.get("product"):
                svc_line += f" {s['product']}"
                if s.get("version"):
                    svc_line += f" {s['version']}"
            elif s.get("name"):
                svc_line += f" {s['name']}"
            if s.get("banner"):
                svc_line += f" | {s['banner'][:80]}"
            lines.append(svc_line)

        vulns = [v for v in (h["vulns"] or []) if v.get("cve_id")]
        for v in vulns:
            vuln_line = f"    VULN: {v['cve_id']} CVSS:{v.get('cvss', '?')}"
            if v.get("has_exploit"):
                vuln_line += " EXPLOIT"
            lines.append(vuln_line)

        lines.append("")

    if connectivity:
        lines.append("=== SEGMENT CONNECTIVITY ===")
        for c in connectivity:
            lines.append(f"  {c['src']} -> {c['dst']}")
        lines.append("")

    return "\n".join(lines), hostnames, all_ips


def _parse_attack_insights(response: str, reverse_map: dict[str, str] | None = None) -> list[AIInsight]:
    """Parse AI attack chain response into insights. De-anonymizes host aliases."""
    data = _parse_json_response(response)
    if not isinstance(data, list):
        return []

    insights = []
    for item in data:
        if not isinstance(item, dict):
            continue
        title = item.get("title", "")
        hosts = item.get("hosts", item.get("path", []))
        priority_raw = item.get("priority")
        priority = int(priority_raw) if priority_raw is not None else 3
        confidence_raw = item.get("confidence")
        confidence = float(confidence_raw) if confidence_raw is not None else 0.5

        if not title or confidence <= 0.5:
            continue

        # De-anonymize host references
        if reverse_map:
            hosts = _deanonymize_hosts(hosts, reverse_map)

        insight = AIInsight(
            insight_type=item.get("type", "attack_chain"),
            confidence=confidence,
            title=title,
            details=item.get("details", ""),
            hosts=hosts,
            priority=priority,
        )
        insights.append(insight)

    insights.sort(key=lambda i: (i.priority, -i.confidence))
    return insights


# ---------------------------------------------------------------------------
# Phase 4: AI False Positive Detection
# ---------------------------------------------------------------------------


def _ai_review_false_positives() -> int:
    """Ask AI to identify false positive CVE assignments.

    Reviews all CVEs per host and marks NVD misclassifications:
    - Wrong product (name collision in NVD CPE)
    - Wrong version range (CVE for older version assigned to newer)
    - Dependency CVE (library vuln, not exploitable through main service)
    - Ancient CVE on modern OS

    Only marks CVEs where checked_status is NULL (never overrides user decisions).
    """
    with get_session() as session:
        result = session.run(
            """
            MATCH (h:Host)-[:HAS_SERVICE]->(s:Service)-[r:HAS_VULN]->(v:Vulnerability)
            WHERE r.checked_status IS NULL
            RETURN h.ip AS ip, h.os_name AS os_name, h.role AS role,
                   s.port AS port, s.product AS product, s.version AS version,
                   v.cve_id AS cve_id, v.cvss AS cvss,
                   v.description AS description, v.source AS source
            ORDER BY h.ip, s.port
            """
        )
        rows = list(result)

    if not rows:
        return 0

    # Group by host
    host_data: dict[str, dict] = {}
    for row in rows:
        ip = row["ip"]
        if ip not in host_data:
            host_data[ip] = {
                "ip": ip,
                "os": row["os_name"],
                "role": row["role"],
                "cves": [],
            }
        host_data[ip]["cves"].append({
            "port": row["port"],
            "product": row["product"],
            "version": row["version"],
            "cve_id": row["cve_id"],
            "cvss": row["cvss"],
            "description": (row["description"] or "")[:150],
            "source": row["source"],
        })

    hosts = list(host_data.values())
    ip_map, reverse_map = _build_anonymization_map([h["ip"] for h in hosts])

    # Batch: 15 hosts per API call
    total_fps = 0
    for i in range(0, len(hosts), 15):
        batch = hosts[i:i + 15]
        fps = _review_batch(batch, ip_map, reverse_map)
        total_fps += _apply_false_positives(fps)

    return total_fps


def _review_batch(
    hosts: list[dict],
    ip_map: dict[str, str],
    reverse_map: dict[str, str],
) -> list[dict]:
    """Send a batch of hosts to AI for false positive review."""
    lines = []
    for h in hosts:
        alias = ip_map.get(h["ip"], h["ip"])
        role = h["role"] or "unknown"
        os_str = f" OS:{h['os']}" if h.get("os") else ""
        lines.append(f"{alias} [{role}]{os_str}")
        for c in h["cves"]:
            prod = f"{c['product']} {c['version']}" if c.get("product") else ""
            desc = c["description"][:100] if c.get("description") else ""
            lines.append(f"  :{c['port']} {prod}  {c['cve_id']} CVSS:{c['cvss'] or '?'} [{c['source']}]")
            if desc:
                lines.append(f"    {desc}")

    prompt = f"""You are a vulnerability researcher reviewing CVE assignments for accuracy.
For each host below, identify FALSE POSITIVES — CVEs incorrectly assigned to this host.

A CVE is a false positive ONLY if:
- It affects a COMPLETELY DIFFERENT product (name collision in NVD, e.g. Oracle library CVE on Exchange server)
- It's a dependency/library CVE not exploitable through the network service (e.g. libpng CVE on MySQL)
- It targets a different OS family (Linux-only CVE on a Windows host, or vice versa)

DO NOT flag a CVE as false positive based on version ranges.
Version matching was already done by NVD's CPE matching engine — trust it.
If NVD says the CVE applies to this product, it most likely does.

{chr(10).join(lines)}

Respond with ONLY JSON:
[{{"id": "host-N", "false_positives": [
  {{"cve_id": "CVE-YYYY-NNNNN", "port": 22, "reason": "brief explanation"}}
]}}]

Rules:
- NEVER flag based on version comparison — only product or OS mismatch
- Only flag CVEs you are ABSOLUTELY CONFIDENT are false positives
- Missing a false positive is acceptable; flagging a real vulnerability is NOT
- If in doubt, do NOT flag
- Respond with ONLY the JSON, no other text"""

    response = _call_claude(prompt, max_tokens=2048)
    if not response:
        return []

    return _parse_fp_response(response, reverse_map)


def _parse_fp_response(response: str, reverse_map: dict[str, str]) -> list[dict]:
    """Parse AI false positive response and de-anonymize."""
    data = _parse_json_response(response)
    if not isinstance(data, list):
        return []

    results = []
    for item in data:
        if not isinstance(item, dict):
            continue
        alias = item.get("id", "")
        real_ip = reverse_map.get(alias, alias)
        for fp in item.get("false_positives", []):
            if not isinstance(fp, dict):
                continue
            cve_id = fp.get("cve_id", "")
            if not cve_id.startswith("CVE-") and not cve_id.startswith("CAULDRON-"):
                continue
            port = fp.get("port")
            if not isinstance(port, int):
                continue
            results.append({
                "ip": real_ip,
                "cve_id": cve_id,
                "port": port,
                "reason": fp.get("reason", "AI-detected false positive"),
            })

    return results


def _apply_false_positives(fps: list[dict]) -> int:
    """Mark false positives in Neo4j. Never overrides user decisions."""
    if not fps:
        return 0

    count = 0
    with get_session() as session:
        for fp in fps:
            result = session.run(
                """
                MATCH (h:Host {ip: $ip})-[:HAS_SERVICE]->(s:Service {port: $port})
                      -[r:HAS_VULN]->(v:Vulnerability {cve_id: $cve_id})
                WHERE r.checked_status IS NULL
                SET r.checked_status = 'false_positive',
                    r.ai_fp_reason = $reason
                RETURN v.cve_id AS cve_id
                """,
                ip=fp["ip"],
                port=fp["port"],
                cve_id=fp["cve_id"],
                reason=fp["reason"],
            )
            if result.single():
                count += 1
                logger.info(
                    "AI marked %s on %s:%d as false positive: %s",
                    fp["cve_id"], fp["ip"], fp["port"], fp["reason"],
                )

    return count


# ---------------------------------------------------------------------------
# Anonymization
# ---------------------------------------------------------------------------


def _build_anonymization_map(ips: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    """Build IP → alias mapping. Sorted by IP for deterministic aliases.

    Returns:
        (ip_to_alias, alias_to_ip) dictionaries.
    """
    # Sort IPs numerically for deterministic ordering
    try:
        sorted_ips = sorted(set(ips), key=lambda x: ipaddress.ip_address(x))
    except ValueError:
        sorted_ips = sorted(set(ips))

    ip_to_alias = {}
    alias_to_ip = {}
    for i, ip in enumerate(sorted_ips, 1):
        alias = f"host-{i}"
        ip_to_alias[ip] = alias
        alias_to_ip[alias] = ip

    return ip_to_alias, alias_to_ip


def _anonymize_text(text: str, ip_map: dict[str, str], hostnames: set[str] | None = None) -> str:
    """Replace real IPs and hostnames in text with aliases.

    Also strips segment headers and connectivity blocks.
    """
    result = text
    # Replace IPs (longest first to avoid partial matches like 10.0.0.1 matching in 10.0.0.10)
    for ip in sorted(ip_map.keys(), key=len, reverse=True):
        result = result.replace(ip, ip_map[ip])

    # Strip hostnames if provided
    if hostnames:
        for hn in hostnames:
            if hn:
                result = result.replace(hn, "")
        # Clean up empty parentheses left behind: "()" or "( )"
        result = re.sub(r"\s*\(\s*\)", "", result)

    # Remove segment headers and connectivity (these are /24 assumptions)
    result = re.sub(r"--- Segment:.*?---\n?", "", result)
    result = re.sub(r"=== SEGMENT CONNECTIVITY ===.*", "", result, flags=re.DOTALL)

    return result


def _deanonymize_hosts(hosts: list[str], reverse_map: dict[str, str]) -> list[str]:
    """Replace host-N aliases back to real IPs."""
    return [reverse_map.get(h, h) for h in hosts]


# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------


def _call_claude(prompt: str, max_tokens: int = 2048) -> str | None:
    """Call Claude API and return the text response."""
    try:
        import anthropic
    except ImportError:
        logger.error("anthropic package not installed. Run: pip install 'cauldron[ai]'")
        return None

    try:
        client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        message = client.messages.create(
            model=settings.ai_model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text
    except anthropic.AuthenticationError:
        logger.error("Invalid Anthropic API key. Check CAULDRON_ANTHROPIC_API_KEY.")
        return None
    except anthropic.RateLimitError:
        logger.warning("Anthropic API rate limit hit, skipping AI analysis")
        return None
    except anthropic.BadRequestError as e:
        logger.error("Anthropic API error: %s", e.message)
        return None
    except Exception:
        logger.error("Claude API call failed unexpectedly")
        return None


def _parse_json_response(response: str) -> list | dict | None:
    """Parse JSON from AI response, handling markdown fences and preamble text."""
    if not response:
        return None

    text = response.strip()

    # Strip markdown code fences: ```json ... ``` or ``` ... ```
    if "```" in text:
        # Find content between first ``` and last ```
        parts = text.split("```")
        for part in parts[1:]:
            # Skip the language tag line (e.g., "json\n")
            candidate = part.strip()
            if candidate.lower().startswith("json"):
                candidate = candidate[4:].strip()
            if candidate.startswith("[") or candidate.startswith("{"):
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    continue

    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try to find JSON array or object in the text
    for start_char, end_char in [("[", "]"), ("{", "}")]:
        start = text.find(start_char)
        if start == -1:
            continue
        # Find matching closing bracket
        depth = 0
        for i in range(start, len(text)):
            if text[i] == start_char:
                depth += 1
            elif text[i] == end_char:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break

    logger.warning("Failed to parse AI JSON response: %s...", text[:200])
    return None


def _parse_classification_response(
    response: str,
    reverse_map: dict[str, str] | None = None,
) -> list[dict]:
    """Parse AI classification response. De-anonymizes host-N → real IP."""
    data = _parse_json_response(response)
    if not isinstance(data, list):
        return []

    valid_roles = {
        "domain_controller", "web_server", "database", "mail_server",
        "file_server", "network_equipment", "printer", "voip",
        "remote_access", "hypervisor", "dns_server", "proxy",
        "monitoring", "siem", "ci_cd", "vpn_gateway", "backup",
        "unknown",
    }

    results = []
    for item in data:
        if not isinstance(item, dict):
            continue
        # Accept both "ip" (legacy) and "id" (anonymized) keys
        host_ref = item.get("id") or item.get("ip")
        if not host_ref:
            continue
        # De-anonymize if needed
        real_ip = reverse_map.get(host_ref, host_ref) if reverse_map else host_ref
        role = item.get("role")
        confidence = item.get("confidence")
        if (
            role in valid_roles
            and isinstance(confidence, (int, float))
            and confidence > 0.6
        ):
            results.append({"ip": real_ip, "role": role, "confidence": confidence})
    return results


def _apply_classifications(classifications: list[dict]) -> int:
    """Apply AI classifications to graph hosts."""
    if not classifications:
        return 0

    updated = 0
    with get_session() as session:
        for c in classifications:
            result = session.run(
                """
                MATCH (h:Host {ip: $ip})
                WHERE h.role_confidence < $confidence
                SET h.role = $role, h.role_confidence = $confidence,
                    h.ai_classified = true
                RETURN h.ip AS ip
                """,
                ip=c["ip"],
                role=c["role"],
                confidence=c["confidence"],
            )
            if result.single():
                updated += 1

    return updated
