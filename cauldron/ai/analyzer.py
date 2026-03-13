"""AI-powered network analysis using Claude API.

Uses Claude to find non-obvious attack chains, correlate vulnerabilities
across hosts, and prioritize paths that a pentester should check first.
This is the "second pair of eyes" — AI processes the large graph and
highlights what's interesting, the pentester validates.
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

    insight_type: str  # "attack_chain", "correlation", "classification"
    confidence: float  # 0.0 - 1.0
    title: str
    details: str
    hosts: list[str] = field(default_factory=list)  # IPs involved
    cves: list[str] = field(default_factory=list)  # CVEs involved
    priority: int = 0  # 1 = highest, 5 = lowest


@dataclass
class AnalysisResult:
    """Result of AI analysis run."""

    insights: list[AIInsight] = field(default_factory=list)
    hosts_analyzed: int = 0
    paths_analyzed: int = 0
    ambiguous_classified: int = 0
    errors: int = 0


def is_ai_available() -> bool:
    """Check if AI features are available (API key configured)."""
    return bool(settings.anthropic_api_key)


def analyze_graph(
    classify_ambiguous: bool = True,
    find_chains: bool = True,
    max_hosts_per_batch: int = 20,
) -> AnalysisResult:
    """Run AI analysis on the current graph.

    Args:
        classify_ambiguous: Re-classify hosts with low confidence using AI.
        find_chains: Find non-obvious attack chains.
        max_hosts_per_batch: Max hosts to send per API call.

    Returns:
        AnalysisResult with discovered insights.
    """
    if not is_ai_available():
        logger.warning("AI analysis skipped: CAULDRON_ANTHROPIC_API_KEY not set")
        return AnalysisResult()

    result = AnalysisResult()

    if classify_ambiguous:
        classified = _classify_ambiguous_hosts(max_hosts_per_batch)
        result.ambiguous_classified = classified
        result.hosts_analyzed += classified

    if find_chains:
        insights = _find_attack_chains(max_hosts_per_batch)
        result.insights.extend(insights)
        result.paths_analyzed = len(insights)

    return result


def _classify_ambiguous_hosts(max_hosts: int) -> int:
    """Use AI to classify hosts where rule-based classifier has low confidence."""
    with get_session() as session:
        result = session.run(
            """
            MATCH (h:Host)
            WHERE h.role_confidence < 0.6 AND h.role_confidence > 0
            OPTIONAL MATCH (h)-[:HAS_SERVICE]->(s:Service)
            WITH h, collect({
                port: s.port, protocol: s.protocol, name: s.name,
                product: s.product, version: s.version
            }) AS services
            RETURN h.ip AS ip, h.hostname AS hostname, h.role AS current_role,
                   h.role_confidence AS confidence, services
            LIMIT $limit
            """,
            limit=max_hosts,
        )
        hosts = list(result)

    if not hosts:
        return 0

    prompt = _build_classification_prompt(hosts)
    response = _call_claude(prompt, max_tokens=2048)
    if not response:
        return 0

    classifications = _parse_classification_response(response)
    updated = _apply_classifications(classifications)
    return updated


def _find_attack_chains(max_hosts: int) -> list[AIInsight]:
    """Use AI to find non-obvious attack chains in the graph."""
    subgraph = _extract_subgraph(max_hosts)
    if not subgraph:
        return []

    prompt = _build_chain_discovery_prompt(subgraph)
    response = _call_claude(prompt, max_tokens=4096)
    if not response:
        return []

    return _parse_chain_response(response)


def _extract_subgraph(max_hosts: int) -> dict | None:
    """Extract relevant subgraph data for AI analysis."""
    with get_session() as session:
        # Get hosts with services and vulns
        host_result = session.run(
            """
            MATCH (h:Host)
            WHERE h.state = 'up'
            OPTIONAL MATCH (h)-[:HAS_SERVICE]->(s:Service)
            OPTIONAL MATCH (s)-[:HAS_VULN]->(v:Vulnerability)
            OPTIONAL MATCH (h)-[:IN_SEGMENT]->(seg:NetworkSegment)
            WITH h, seg,
                 collect(DISTINCT {
                     port: s.port, protocol: s.protocol, name: s.name,
                     product: s.product, version: s.version,
                     cve: v.cve_id, cvss: v.cvss, has_exploit: v.has_exploit
                 }) AS services
            RETURN h.ip AS ip, h.hostname AS hostname, h.role AS role,
                   h.role_confidence AS confidence, seg.cidr AS segment,
                   services
            LIMIT $limit
            """,
            limit=max_hosts,
        )
        hosts = [dict(r) for r in host_result]

        if not hosts:
            return None

        # Get segment connectivity
        seg_result = session.run(
            """
            MATCH (s1:NetworkSegment)-[:CAN_REACH]->(s2:NetworkSegment)
            RETURN s1.cidr AS from_segment, s2.cidr AS to_segment
            """
        )
        connectivity = [dict(r) for r in seg_result]

        # Get existing pivots
        pivot_result = session.run(
            """
            MATCH (h1:Host)-[p:PIVOT_TO]->(h2:Host)
            RETURN h1.ip AS from_ip, h2.ip AS to_ip,
                   p.method AS method, p.difficulty AS difficulty
            """
        )
        pivots = [dict(r) for r in pivot_result]

        return {
            "hosts": hosts,
            "connectivity": connectivity,
            "pivots": pivots,
        }


def _build_classification_prompt(hosts: list[dict]) -> str:
    """Build prompt for AI host classification."""
    hosts_text = ""
    for h in hosts:
        services = h["services"]
        svc_list = []
        for s in services:
            if s.get("port"):
                parts = [f"{s['port']}/{s.get('protocol', 'tcp')}"]
                if s.get("product"):
                    parts.append(s["product"])
                if s.get("version"):
                    parts.append(s["version"])
                elif s.get("name"):
                    parts.append(s["name"])
                svc_list.append(" ".join(parts))

        hosts_text += f"\nHost: {h['ip']}"
        if h.get("hostname"):
            hosts_text += f" ({h['hostname']})"
        hosts_text += f"\n  Current role: {h['current_role']} (confidence: {h['confidence']:.2f})"
        hosts_text += f"\n  Services: {', '.join(svc_list) if svc_list else 'none'}\n"

    return f"""You are a network security analyst. Classify each host by its most likely role based on the open services.

Possible roles: domain_controller, web_server, database, mail_server, file_server, network_equipment, printer, voip, remote_access, hypervisor, dns_server, proxy, monitoring, unknown

For each host, respond with JSON array:
[{{"ip": "x.x.x.x", "role": "role_name", "confidence": 0.0-1.0}}]

Only include hosts where you are reasonably confident (>0.6). Omit uncertain ones.

Hosts to classify:
{hosts_text}

Respond with ONLY the JSON array, no other text."""


def _build_chain_discovery_prompt(subgraph: dict) -> str:
    """Build prompt for attack chain discovery."""
    hosts_text = ""
    for h in subgraph["hosts"]:
        hosts_text += f"\n  {h['ip']}"
        if h.get("hostname"):
            hosts_text += f" ({h['hostname']})"
        hosts_text += f" [{h.get('role', 'unknown')}]"
        if h.get("segment"):
            hosts_text += f" in {h['segment']}"

        for s in h.get("services", []):
            if s.get("port"):
                svc_str = f"    - {s['port']}/{s.get('protocol', 'tcp')}"
                if s.get("product"):
                    svc_str += f" {s['product']}"
                if s.get("version"):
                    svc_str += f" {s['version']}"
                if s.get("cve"):
                    svc_str += f" [CVE: {s['cve']}, CVSS: {s.get('cvss', '?')}]"
                    if s.get("has_exploit"):
                        svc_str += " EXPLOIT AVAILABLE"
                hosts_text += f"\n{svc_str}"
        hosts_text += "\n"

    connectivity_text = ""
    for c in subgraph.get("connectivity", []):
        connectivity_text += f"\n  {c['from_segment']} -> {c['to_segment']}"

    pivots_text = ""
    for p in subgraph.get("pivots", []):
        pivots_text += f"\n  {p['from_ip']} -> {p['to_ip']} ({p.get('method', '?')}, {p.get('difficulty', '?')})"

    return f"""You are a senior penetration tester analyzing a network graph. Your task is to find non-obvious, creative attack chains that a human might miss when looking at this data.

Focus on:
1. Multi-step chains through unexpected pivot points (printers, VoIP phones, monitoring systems)
2. Vulnerability correlations: CVE on host A + CVE on host B = chain exploitation opportunity
3. Paths to high-value targets (Domain Controllers, databases) through low-priority hosts
4. Hosts that serve as "chokepoints" — compromising one gives access to many segments

Do NOT explain why things are dangerous (the pentester knows). Just identify the chains and their components.

Network data:
{hosts_text}

Segment connectivity:
{connectivity_text if connectivity_text else "  (none found)"}

Existing pivot relationships:
{pivots_text if pivots_text else "  (none found)"}

Respond with ONLY a JSON array. Each item:
[{{
  "type": "attack_chain" | "correlation" | "chokepoint",
  "title": "short description of the finding",
  "details": "specific steps or details",
  "hosts": ["ip1", "ip2", ...],
  "cves": ["CVE-xxxx-yyyy", ...],
  "priority": 1-5,
  "confidence": 0.0-1.0
}}]

Order by priority (1=highest). Include only findings with confidence > 0.5.
Respond with ONLY the JSON array, no other text."""


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
        # Covers: insufficient credits, invalid model, etc.
        logger.error("Anthropic API error: %s", e.message)
        return None
    except Exception:
        logger.error("Claude API call failed unexpectedly")
        return None


def _parse_classification_response(response: str) -> list[dict]:
    """Parse AI classification response into list of {ip, role, confidence}."""
    try:
        # Strip markdown code fences if present
        text = response.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        text = text.strip()

        data = json.loads(text)
        if not isinstance(data, list):
            return []

        valid_roles = {
            "domain_controller", "web_server", "database", "mail_server",
            "file_server", "network_equipment", "printer", "voip",
            "remote_access", "hypervisor", "dns_server", "proxy",
            "monitoring", "unknown",
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
    except (json.JSONDecodeError, KeyError, TypeError):
        logger.warning("Failed to parse AI classification response")
        return []


def _parse_chain_response(response: str) -> list[AIInsight]:
    """Parse AI chain discovery response into AIInsight objects."""
    try:
        text = response.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        text = text.strip()

        data = json.loads(text)
        if not isinstance(data, list):
            return []

        insights = []
        for item in data:
            if not isinstance(item, dict):
                continue
            try:
                insight = AIInsight(
                    insight_type=item.get("type", "attack_chain"),
                    confidence=float(item.get("confidence", 0.5)),
                    title=item.get("title", ""),
                    details=item.get("details", ""),
                    hosts=item.get("hosts", []),
                    cves=item.get("cves", []),
                    priority=int(item.get("priority", 3)),
                )
                if insight.title and insight.confidence > 0.5:
                    insights.append(insight)
            except (ValueError, TypeError):
                continue

        insights.sort(key=lambda i: (i.priority, -i.confidence))
        return insights
    except (json.JSONDecodeError, KeyError, TypeError):
        logger.warning("Failed to parse AI chain response")
        return []


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
                logger.info("AI classified %s as %s (%.2f)", c["ip"], c["role"], c["confidence"])

    return updated


def store_insights(insights: list[AIInsight]) -> int:
    """Store AI insights as properties on relevant graph nodes."""
    if not insights:
        return 0

    stored = 0
    with get_session() as session:
        for insight in insights:
            # Store insight on the first host in the chain
            if insight.hosts:
                session.run(
                    """
                    MATCH (h:Host {ip: $ip})
                    SET h.ai_insight_type = $type,
                        h.ai_insight_title = $title,
                        h.ai_insight_priority = $priority
                    """,
                    ip=insight.hosts[0],
                    type=insight.insight_type,
                    title=insight.title,
                    priority=insight.priority,
                )
                stored += 1

    return stored
