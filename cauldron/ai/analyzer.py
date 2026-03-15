"""AI-powered network analysis using Claude API.

Three integrated AI phases that directly affect the graph:
1. CVE discovery — find vulnerabilities NVD missed based on product+version
2. Host classification — re-classify ambiguous hosts
3. Attack chain discovery — find non-obvious paths, create PIVOT_TO relationships

Each phase writes results back to Neo4j so that `cauldron paths` reflects AI findings.
"""

from __future__ import annotations

import json
import logging
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

    # Phase 3: Attack chain discovery → PIVOT_TO
    insights, pivots = _discover_and_create_pivots()
    result.insights = insights
    result.pivots_created = pivots

    return result


# ---------------------------------------------------------------------------
# Phase 1: AI CVE Enrichment
# ---------------------------------------------------------------------------


def _ai_enrich_cves() -> tuple[int, int]:
    """Ask AI to identify CVEs for services that NVD couldn't match.

    Only sends services WITHOUT existing vulnerabilities — efficient,
    no redundant work.

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

    # Build compact prompt — just product+version list
    lines = [f"- {p} {v}" for p, v in pairs]
    prompt = f"""You are a vulnerability researcher. For each software product+version below, list known CVEs with CVSS scores.

Products:
{chr(10).join(lines)}

Respond with ONLY a JSON array:
[{{"product": "exact product name", "version": "exact version", "cves": [{{"cve_id": "CVE-YYYY-NNNNN", "cvss": 7.5, "severity": "HIGH", "has_exploit": true, "description": "brief"}}]}}]

Rules:
- Only include REAL, published CVEs (no guessing)
- Include CVSS v3.1 score
- has_exploit = true only if public exploit exists (ExploitDB, Metasploit, GitHub PoC)
- If no known CVEs for a product+version, omit it from the array
- Respond with ONLY the JSON, no other text"""

    response = _call_claude(prompt, max_tokens=2048)
    if not response:
        return 0, 0

    return _apply_ai_cves(response)


def _apply_ai_cves(response: str) -> tuple[int, int]:
    """Parse AI CVE response and create Vulnerability nodes."""
    data = _parse_json_response(response)
    if not isinstance(data, list):
        return 0, 0

    total_cves = 0
    services_enriched = 0

    with get_session() as session:
        for item in data:
            if not isinstance(item, dict):
                continue
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

                cvss_raw = cve.get("cvss")
                cvss = float(cvss_raw) if cvss_raw is not None else 0.0
                severity = cve.get("severity", "MEDIUM")
                has_exploit = bool(cve.get("has_exploit", False))
                description = cve.get("description", "")

                # Create Vulnerability node
                # AI-found CVEs are "likely" — real CVE but unverified on target
                session.run(
                    """
                    MERGE (v:Vulnerability {cve_id: $cve_id})
                    ON CREATE SET
                        v.cvss = $cvss, v.severity = $severity,
                        v.has_exploit = $has_exploit, v.description = $description,
                        v.source = 'ai', v.confidence = 'likely'
                    """,
                    cve_id=cve_id, cvss=cvss, severity=severity,
                    has_exploit=has_exploit, description=description,
                )

                # Link to matching services
                session.run(
                    """
                    MATCH (s:Service)
                    WHERE s.product = $product AND s.version = $version
                    MATCH (v:Vulnerability {cve_id: $cve_id})
                    MERGE (s)-[:HAS_VULN]->(v)
                    """,
                    product=product, version=version, cve_id=cve_id,
                )
                svc_cve_count += 1
                total_cves += 1

            if svc_cve_count > 0:
                services_enriched += 1

    return total_cves, services_enriched


# ---------------------------------------------------------------------------
# Phase 2: Host Classification
# ---------------------------------------------------------------------------


def _classify_ambiguous_hosts() -> int:
    """Use AI to classify hosts where rule-based classifier has low confidence."""
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

    # Compact prompt — only what's needed
    lines = []
    for h in hosts:
        svcs = [f"{s['port']}/{s.get('protocol', 'tcp')} {s.get('product', s.get('name', ''))}"
                for s in h["services"] if s.get("port")]
        lines.append(f"{h['ip']}: {', '.join(svcs[:10]) if svcs else 'no services'}")

    prompt = f"""Classify these network hosts by role based on their services.

Roles: domain_controller, web_server, database, mail_server, file_server, network_equipment, printer, voip, remote_access, hypervisor, dns_server, proxy, monitoring, siem, ci_cd, vpn_gateway, backup, unknown

Hosts:
{chr(10).join(lines)}

Respond with ONLY JSON: [{{"ip": "x.x.x.x", "role": "role_name", "confidence": 0.0-1.0}}]
Only include hosts where confidence > 0.6."""

    response = _call_claude(prompt, max_tokens=1024)
    if not response:
        return 0

    classifications = _parse_classification_response(response)
    return _apply_classifications(classifications)


# ---------------------------------------------------------------------------
# Phase 3: Attack Chain Discovery → PIVOT_TO
# ---------------------------------------------------------------------------


def _discover_and_create_pivots() -> tuple[list[AIInsight], int]:
    """Discover attack chains and create PIVOT_TO relationships for them.

    Returns:
        (insights, pivots_created)
    """
    # Get full network summary — AI needs complete picture to find hidden paths
    summary = _get_network_summary()
    if not summary:
        return [], 0

    prompt = f"""You are a penetration tester. Analyze this network and find non-obvious attack chains.

{summary}

Find:
1. Multi-step attack chains through unexpected pivots (printers, VoIP, monitoring → DC)
2. Service correlations that enable lateral movement
3. Chokepoint hosts (compromising one = access to many)

IMPORTANT: Only report chains that involve real exploitable vulnerabilities or confirmed misconfigurations.
Do NOT suggest checking for default credentials, null sessions, or anonymous access as attack chains —
those are basic checks, not attack paths. Focus on paths where the exploit or vulnerability is known.

Use confidence levels:
- 0.9+ = confirmed (version-matched CVE with known exploit)
- 0.7-0.9 = likely (CVE exists, exploit probable but unverified)
- 0.5-0.7 = check (needs manual verification)

Respond with ONLY JSON array:
[{{
  "type": "attack_chain",
  "title": "short description",
  "path": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
  "priority": 1-5,
  "confidence": 0.0-1.0
}}]

"path" = ordered list of IPs in the attack chain. Priority 1 = most interesting.
Only include findings with confidence > 0.5. Respond with ONLY the JSON."""

    response = _call_claude(prompt, max_tokens=2048)
    if not response:
        return [], 0

    insights, pivots = _parse_and_create_chain_pivots(response)
    return insights, pivots


def _get_network_summary() -> str | None:
    """Build a detailed network summary for AI attack chain discovery.

    Includes full service details, all CVEs, banners, and existing pivots
    so AI has complete picture to find non-obvious attack paths.
    """
    with get_session() as session:
        # Get all up hosts with their services and vulns — no limits
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

        # Get segment connectivity
        conn = session.run(
            "MATCH (s1:NetworkSegment)-[:CAN_REACH]->(s2:NetworkSegment) "
            "RETURN s1.cidr AS src, s2.cidr AS dst"
        )
        connectivity = list(conn)

        # Get existing pivots so AI knows what's already discovered
        pivots = session.run(
            "MATCH (h1:Host)-[p:PIVOT_TO]->(h2:Host) "
            "RETURN h1.ip AS src, h2.ip AS dst, p.method AS method, "
            "p.difficulty AS difficulty"
        )
        existing_pivots = list(pivots)

    lines = ["=== NETWORK MAP ===", ""]

    # Group by segment for readability
    current_segment = None
    for h in hosts:
        seg = h["segment"] or "unknown"
        if seg != current_segment:
            current_segment = seg
            lines.append(f"--- Segment: {seg} ---")

        # Host header
        role = h["role"] or "unknown"
        header = f"  {h['ip']} [{role}]"
        if h.get("hostname"):
            header += f" ({h['hostname']})"
        if h.get("os"):
            header += f" OS:{h['os']}"
        lines.append(header)

        # Services — full detail
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

        # Vulnerabilities — all of them
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

    if existing_pivots:
        lines.append("=== EXISTING PIVOTS (already discovered) ===")
        for p in existing_pivots:
            lines.append(f"  {p['src']} -> {p['dst']} [{p['method']}] {p['difficulty']}")
        lines.append("")

    return "\n".join(lines)


def _parse_and_create_chain_pivots(response: str) -> tuple[list[AIInsight], int]:
    """Parse chain response and create PIVOT_TO for discovered paths."""
    data = _parse_json_response(response)
    if not isinstance(data, list):
        return [], 0

    insights = []
    pivots_created = 0

    with get_session() as session:
        for item in data:
            if not isinstance(item, dict):
                continue
            path = item.get("path", [])
            title = item.get("title", "")
            priority_raw = item.get("priority")
            priority = int(priority_raw) if priority_raw is not None else 3
            confidence_raw = item.get("confidence")
            confidence = float(confidence_raw) if confidence_raw is not None else 0.5

            if not title or confidence <= 0.5 or len(path) < 2:
                continue

            insight = AIInsight(
                insight_type=item.get("type", "attack_chain"),
                confidence=confidence,
                title=title,
                details=item.get("details", ""),
                hosts=path,
                priority=priority,
            )
            insights.append(insight)

            # Create PIVOT_TO for each consecutive pair in the chain
            for i in range(len(path) - 1):
                result = session.run(
                    """
                    MATCH (h1:Host {ip: $ip1}), (h2:Host {ip: $ip2})
                    MERGE (h1)-[p:PIVOT_TO]->(h2)
                    ON CREATE SET p.method = 'ai_chain', p.difficulty = $diff,
                                  p.ai_title = $title
                    RETURN h1.ip AS ip
                    """,
                    ip1=path[i], ip2=path[i + 1],
                    diff="easy" if priority <= 2 else "medium" if priority <= 3 else "hard",
                    title=title,
                )
                if result.single():
                    pivots_created += 1

    insights.sort(key=lambda i: (i.priority, -i.confidence))
    return insights, pivots_created


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
    """Parse JSON from AI response, stripping markdown fences."""
    try:
        text = response.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        text = text.strip()
        return json.loads(text)
    except (json.JSONDecodeError, KeyError, TypeError):
        logger.warning("Failed to parse AI JSON response")
        return None


def _parse_classification_response(response: str) -> list[dict]:
    """Parse AI classification response into list of {ip, role, confidence}."""
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
        if (
            isinstance(item, dict)
            and item.get("ip")
            and item.get("role") in valid_roles
            and isinstance(item.get("confidence"), (int, float))
            and item["confidence"] > 0.6
        ):
            results.append(item)
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
