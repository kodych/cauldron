"""AI-powered network analysis using Claude API.

Three integrated AI phases that directly affect the graph:

1. CPE extraction — for services where nmap had partial signal (raw
   servicefp, banner, vendor string not in PRODUCT_CPE_MAP), ask the
   LLM to distill a CPE 2.3 identifier, then run the standard NVD CPE
   query. AI augments product→CPE mapping; NVD remains the authority
   on CVE → product applicability. Self-correcting: hallucinated CPEs
   return NVD 404 and drop out.
2. Host classification — re-classify ambiguous hosts (anonymized).
3. Contextual vuln triage — AI reviews every NVD/exploit_db finding with
   engagement context (scan positions, owned, target) and dismisses
   noise, keeps gold.

Phase 2 & 3 anonymize client data (IPs, hostnames) before leaving the
process. Phase 1 sends product strings, banners, and servicefp probe
responses — public knowledge about the software running, not about the
engagement.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from cauldron.config import settings
from cauldron.graph.connection import get_session

logger = logging.getLogger(__name__)

# Concurrency cap for parallel Claude API calls within a single analysis
# phase. Five concurrent requests stay well inside Anthropic's Tier-1 RPM
# (50/min for Sonnet) while turning the Phase-3 wall clock from O(N×latency)
# into ~O(N×latency/5). Each worker opens its own short-lived Neo4j session
# on write; the driver's connection pool handles that fan-out natively.
_AI_MAX_WORKERS = 5


def _gather_batches(fns_and_args: list, max_workers: int = _AI_MAX_WORKERS) -> list:
    """Run batch callables concurrently, preserving ``ClaudeAuthError``
    short-circuit semantics. On the first auth failure, pending futures
    are cancelled and running ones drain; the exception propagates to
    the caller so ``analyze_graph`` can stamp ``auth_error`` on the result.

    ``fns_and_args`` is a list of ``(callable, args_tuple)`` pairs.
    """
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(fn, *args) for fn, args in fns_and_args]
        try:
            for fut in as_completed(futures):
                results.append(fut.result())
        except ClaudeAuthError:
            # Stop accepting more work. Running Claude calls will raise
            # the same AuthError and their results are simply discarded.
            for f in futures:
                f.cancel()
            raise
    return results


class ClaudeAuthError(Exception):
    """Anthropic API rejected the key. Raised from ``_call_claude`` so the
    entire analysis pipeline short-circuits on the first phase, instead
    of burning three rounds of log noise and returning silent zeros."""


@dataclass
class AnalysisResult:
    """Result of AI analysis run."""

    cves_found: int = 0
    services_enriched: int = 0
    ambiguous_classified: int = 0
    false_positives_found: int = 0
    vulns_kept: int = 0
    vulns_dismissed: int = 0
    targets_set: int = 0
    # Populated when the Anthropic key is rejected. Callers (CLI, API)
    # read this to show a prominent failure message instead of silently
    # reporting "0 insights" across every counter.
    auth_error: str | None = None
    # Count of AI calls whose response we couldn't parse — typically a
    # response truncated at ``max_tokens`` because the batch was bigger
    # than the output budget. Surfaced separately so a "0 dismissals"
    # result that's actually "0 dismissals AND 5 broken batches" doesn't
    # look like a green run. CLI / UI render a prominent warning.
    parse_failures: int = 0


def is_ai_available() -> bool:
    """Check if AI features are available (API key configured)."""
    return bool(settings.anthropic_api_key)


def analyze_graph() -> AnalysisResult:
    """Run all AI analysis phases on the current graph.

    Phase 1: Extract CPEs from services nmap couldn't fully identify,
             then let the standard NVD pipeline find CVEs for those CPEs.
    Phase 2: Re-classify ambiguous hosts.
    Phase 3: Contextual engagement triage — AI reviews every vuln with the
             scan-position / owned / target context and dismisses the noise
             that doesn't apply in this engagement.

    Returns:
        AnalysisResult with all findings.
    """
    if not is_ai_available():
        logger.warning("AI analysis skipped: CAULDRON_ANTHROPIC_API_KEY not set")
        return AnalysisResult()

    result = AnalysisResult()

    # One try/except wraps all three phases. ClaudeAuthError is raised
    # by the very first ``_call_claude`` invocation that 401s, so we
    # don't waste two more phases retrying with the same bad key.
    try:
        # Phase 1: AI CPE extraction for services with banners / servicefp
        # that nmap and PRODUCT_CPE_MAP couldn't resolve on their own.
        cves, services = _ai_extract_cpes()
        result.cves_found = cves
        result.services_enriched = services

        # Phase 2: Re-classify ambiguous hosts
        result.ambiguous_classified = _classify_ambiguous_hosts()

        # Phase 3: Contextual engagement triage
        # AI reviews ALL vulns with engagement context (owned/target/scan sources)
        # and dismisses noise — keeping only gold findings
        kept, dismissed, targets, parse_failures = _contextual_vuln_triage()
        result.vulns_kept = kept
        result.vulns_dismissed = dismissed
        result.false_positives_found = dismissed
        result.targets_set = targets
        result.parse_failures = parse_failures
    except ClaudeAuthError as e:
        result.auth_error = str(e)
        logger.error(
            "AI analysis aborted: %s. Remaining phases skipped — "
            "fix CAULDRON_ANTHROPIC_API_KEY and re-run boil.", e,
        )
        return result

    # Recount AI CVEs that survived triage (not dismissed)
    with get_session() as session:
        surviving = session.run(
            """
            MATCH ()-[r:HAS_VULN]->(v:Vulnerability {source: 'ai'})
            WHERE r.checked_status IS NULL OR r.checked_status <> 'false_positive'
            RETURN count(DISTINCT v.cve_id) AS c
            """
        ).single()
        result.cves_found = surviving["c"] if surviving else 0

    return result


# ---------------------------------------------------------------------------
# Phase 1: AI CPE Extraction
# ---------------------------------------------------------------------------

# CPE 2.3 layout: ``cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:
# <edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>``.
# Thirteen colon-separated fields total. Validate format before trusting
# AI output — malformed strings break NVD queries downstream.
_CPE23_RE = re.compile(
    r"^cpe:2\.3:[aoh]:[^:\s]+:[^:\s]+:[^:\s]+:[^:\s]*:[^:\s]*:[^:\s]*:"
    r"[^:\s]*:[^:\s]*:[^:\s]*:[^:\s]*$",
)

# How many hosts packed into one AI request. Host-level batching keeps the
# adjacent services of a host visible together (SMTP + IMAP + webmail → mail
# stack) so the LLM can cross-reference. Five hosts stay well under token
# limits with servicefp probe responses of a few hundred bytes each.
_HOSTS_PER_AI_BATCH = 5


def _ai_extract_cpes() -> tuple[int, int]:
    """Ask AI to extract CPE identifiers from services nmap couldn't fully identify.

    Targets services where nmap has SOME signal (``servicefp`` probe
    response, banner, product string) but Cauldron's own
    ``_get_cpe_for_service`` could not derive a CPE from nmap's CPE tag
    or ``PRODUCT_CPE_MAP``. The LLM distills the raw signal into a CPE
    2.3 tuple, then the standard NVD CPE enrichment runs over each
    extracted CPE.

    Self-correcting against hallucinations: NVD is the authoritative
    CPE dictionary. An AI-invented ``cpe:2.3:a:madeup:vendor:1.0`` will
    come back with zero CVEs and simply not link anything. Real CPEs
    for the wrong product remain a residual risk, bounded by the
    targeting rule — only services where nmap couldn't identify the
    product itself are sent for AI extraction, so there's nothing for
    the AI result to contradict.

    Returns:
        (total_cves_linked, services_enriched)
    """
    from cauldron.ai.cve_enricher import _get_cpe_for_service, _query_nvd_cpe

    with get_session() as session:
        result = session.run(
            """
            MATCH (h:Host)-[:HAS_SERVICE]->(s:Service)
            WHERE NOT (s)-[:HAS_VULN]->(:Vulnerability {source: 'nvd'})
              AND (
                    s.servicefp IS NOT NULL
                    OR s.banner   IS NOT NULL
                    OR s.product  IS NOT NULL
                  )
            RETURN h.ip AS ip, h.os_name AS os_name,
                   s.port AS port, s.protocol AS protocol,
                   s.name AS name, s.product AS product, s.version AS version,
                   s.extra_info AS extra_info, s.banner AS banner,
                   s.servicefp AS servicefp, s.cpe AS cpe
            ORDER BY h.ip, s.port
            """,
        )
        rows = [dict(r) for r in result]

    # Only services Cauldron couldn't map itself. If the standard pipeline
    # already has a CPE for this service, NVD enrichment will handle it —
    # no AI needed, no false-positive risk.
    candidates: list[dict] = []
    for row in rows:
        cpe_list = row["cpe"].split(";") if row["cpe"] else []
        if _get_cpe_for_service(cpe_list, row["product"], row["version"]):
            continue
        candidates.append(row)

    if not candidates:
        return 0, 0

    logger.info(
        "AI CPE extraction: %d candidate services across %d hosts",
        len(candidates),
        len({c["ip"] for c in candidates}),
    )

    from collections import defaultdict
    by_host: dict[str, list[dict]] = defaultdict(list)
    for c in candidates:
        by_host[c["ip"]].append(c)
    hosts_list = list(by_host.items())

    def _process_batch(batch: list[tuple[str, list[dict]]]) -> tuple[int, int]:
        """Run one AI extraction + per-CPE NVD lookup + link. Returns
        ``(vulns_linked, services_enriched)`` for this batch only, so the
        outer pool can sum across all futures without shared state."""
        extracted = _ai_cpes_for_batch(batch)
        if not extracted:
            return 0, 0
        batch_vulns = 0
        batch_services = 0
        for entry in extracted:
            linked_here = 0
            cpes_for_service = [
                c for c in entry.get("cpes", []) if _is_valid_cpe23(c)
            ]
            # Persist the AI-extracted CPE list on the Service node BEFORE
            # NVD enrichment so the operator sees ``product/version`` in
            # the UI even when zero CVEs come back from NVD — otherwise
            # an empty NVD response (rare but legitimate, e.g. an obscure
            # appliance) silently swallows the AI's identification work.
            # The persist call fills product/version only when nmap left
            # them null and flags the service ``ai_inferred=true`` so the
            # UI can render an "AI-inferred" chip distinguishing
            # heuristic identification from real probe matches.
            if cpes_for_service:
                _persist_ai_extracted_cpes(entry, cpes_for_service)
            for cpe23 in cpes_for_service:
                try:
                    cves = _query_nvd_cpe(cpe23)
                except Exception:  # noqa: BLE001
                    logger.exception("NVD query failed for AI CPE %s", cpe23)
                    continue
                if not cves:  # empty list or None (404) — AI CPE unknown to NVD
                    continue
                for cve in cves:
                    if _link_ai_cve_to_service(entry, cve):
                        linked_here += 1
                        batch_vulns += 1
            for invalid in (c for c in entry.get("cpes", []) if not _is_valid_cpe23(c)):
                logger.info("AI returned invalid CPE, dropping: %s", invalid)
            if linked_here:
                batch_services += 1
        return batch_vulns, batch_services

    batches = [
        hosts_list[i : i + _HOSTS_PER_AI_BATCH]
        for i in range(0, len(hosts_list), _HOSTS_PER_AI_BATCH)
    ]
    results = _gather_batches([(_process_batch, (b,)) for b in batches])
    total_vulns = sum(r[0] for r in results)
    services_enriched = sum(r[1] for r in results)
    return total_vulns, services_enriched


def _is_valid_cpe23(cpe: str) -> bool:
    """Reject obviously malformed CPE strings before sending to NVD."""
    return isinstance(cpe, str) and bool(_CPE23_RE.match(cpe))


def _truncate(text: str | None, limit: int) -> str:
    """Clip a banner / fingerprint to ``limit`` chars and collapse newlines
    so the prompt stays readable and token-bounded.
    """
    if not text:
        return ""
    clipped = text[:limit].replace("\n", " ").replace("\r", " ").strip()
    return clipped + ("…" if len(text) > limit else "")


def _ai_cpes_for_batch(batch: list[tuple[str, list[dict]]]) -> list[dict]:
    """Send a batch of hosts' unidentified services to Claude, return CPE tuples.

    Output shape per entry:
        {"ip": str, "port": int, "protocol": str, "cpes": list[str]}
    """
    host_blocks: list[str] = []
    index_map: list[dict] = []  # position → {ip, port, protocol}

    for ip, services in batch:
        os_label = services[0].get("os_name") or "unknown"
        svc_lines: list[str] = []
        for svc in services:
            idx = len(index_map)
            index_map.append(
                {"ip": ip, "port": svc["port"], "protocol": svc["protocol"]},
            )
            parts = [f"#{idx} {svc['port']}/{svc['protocol']}"]
            if svc.get("name"):
                parts.append(f"name={svc['name']}")
            if svc.get("product"):
                parts.append(f"product={svc['product']!r}")
            if svc.get("version"):
                parts.append(f"version={svc['version']!r}")
            if svc.get("extra_info"):
                parts.append(f"extra={_truncate(svc['extra_info'], 120)!r}")
            if svc.get("banner"):
                parts.append(f"banner={_truncate(svc['banner'], 200)!r}")
            if svc.get("servicefp"):
                parts.append(f"fp={_truncate(svc['servicefp'], 400)!r}")
            svc_lines.append(" ".join(parts))
        host_blocks.append(f"Host (OS: {os_label}):\n  " + "\n  ".join(svc_lines))

    if not index_map:
        return []

    prompt = f"""You are a vulnerability analyst. Extract CPE 2.3 identifiers from the service data below.

Each line is labelled "#N" where N is the service index. Respond with CPE 2.3 format:
  cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*

Use part type "a" for applications and "o" for operating systems. Use the NVD-registered vendor/product names — e.g. apache:http_server, openbsd:openssh, postgresql:postgresql, microsoft:exchange_server, f5:nginx (NVD uses "f5" for nginx post-acquisition), vmware:esxi, mikrotik:routeros, samba:samba, isc:bind, distcc:distcc, gnu:bash, openssl:openssl, proftpd:proftpd, vsftpd_project:vsftpd, dovecot:dovecot.

Rules:
- One service may expose multiple products (e.g. nginx fronting tomcat). Return each as a separate CPE in the cpes list.
- If version cannot be determined, use "*".
- If you CANNOT confidently identify the product, return an empty cpes list. DO NOT GUESS. Empty is better than wrong — a wrong CPE pins CVEs for a different product onto this service.
- Skip entries where the service is clearly generic Microsoft RPC / netbios-ssn / similar protocol-level listeners with no specific vendor product.
- DAEMON vs DISPATCHED-TOOL: when a network daemon delegates work to a local utility (distccd → invokes local gcc, build farms → invoke compilers, CI runners → invoke language interpreters), the CPE identifies the DAEMON, not the dispatched tool. distccd on TCP/3632 is ``cpe:2.3:a:distcc:distcc:<version>`` — even though the banner mentions GCC, the listening attack surface is distcc itself, and the CVE history (CVE-2004-2687 distccd RCE) is on the distcc product page, not the GCC one.

=== SERVICES ===
{chr(10).join(host_blocks)}

Respond with ONLY JSON, no prose, no markdown fences:
[
  {{"index": 0, "cpes": ["cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*"]}},
  {{"index": 1, "cpes": []}}
]"""

    response = _call_claude(prompt, max_tokens=16384)
    if not response:
        return []

    data = _parse_json_response(response.text)
    if not isinstance(data, list):
        if response.truncated:
            logger.warning("Phase 1 CPE extraction: response truncated at max_tokens — batch too large")
        return []

    out: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        idx = item.get("index")
        if not isinstance(idx, int) or idx < 0 or idx >= len(index_map):
            continue
        cpes = item.get("cpes", [])
        if not isinstance(cpes, list):
            continue
        coords = index_map[idx]
        out.append({**coords, "cpes": [c for c in cpes if isinstance(c, str)]})
    return out


def _cpe23_to_22(cpe23: str) -> str:
    """Convert CPE 2.3 (``cpe:2.3:a:vendor:product:version:...``) to the
    CPE 2.2 URI form Cauldron stores on Service nodes
    (``cpe:/a:vendor:product:version``). Trailing wildcard slots are
    stripped — both forms are semantically identical when the upper
    slots are unset, and the shorter form keeps the semicolon-joined
    ``s.cpe`` field readable.
    """
    parts = cpe23.split(":")
    if len(parts) < 4 or parts[0] != "cpe" or parts[1] != "2.3":
        return cpe23
    type_part = parts[2]
    components = parts[3:]
    while components and components[-1] == "*":
        components.pop()
    return f"cpe:/{type_part}:" + ":".join(components)


def _persist_ai_extracted_cpes(coords: dict, cpes_23: list[str]) -> None:
    """Write AI Phase 1's CPE extraction back to the Service node.

    Surfaces the AI's identification work in the UI even when zero CVEs
    come back from the subsequent NVD lookup. Without this the operator
    sees a bare ``ssh`` row with no product/version on a host that AI
    successfully fingerprinted via ``servicefp`` — they have no way to
    distinguish "AI couldn't tell" from "AI knew, but didn't write it".

    Three updates per service:

    - ``s.product`` / ``s.version`` filled **only when nmap left them
      null**. A real nmap probe-match is more reliable than AI's banner
      interpretation, so we never overwrite. The first AI-returned CPE
      drives both values (services that expose multiple products — e.g.
      nginx fronting tomcat — get one primary identity, the rest land
      as extras in the cpe list below).
    - ``s.cpe`` extended with the CPE 2.2 form of every AI-returned
      ``cpe:2.3:`` URI. Existing nmap-emitted CPEs stay; this only
      appends.
    - ``s.ai_inferred = true`` so the frontend can render an
      "AI-inferred" chip alongside the version, distinguishing
      heuristic identification from a cure-grade nmap fingerprint.
    """
    if not cpes_23:
        return
    first_parts = cpes_23[0].split(":")
    if len(first_parts) < 6:
        return
    product_from_cpe = first_parts[4] if first_parts[4] not in ("*", "-") else None
    version_from_cpe = first_parts[5] if first_parts[5] not in ("*", "-") else None

    cpes_22 = [_cpe23_to_22(c) for c in cpes_23]
    cpes_22_join = ";".join(cpes_22)

    with get_session() as session:
        session.run(
            """
            MATCH (s:Service {host_ip: $ip, port: $port, protocol: $proto})
            SET
              s.product = coalesce(s.product, $product),
              s.version = coalesce(s.version, $version),
              s.cpe = CASE
                WHEN s.cpe IS NULL THEN $cpes_join
                WHEN s.cpe CONTAINS $first_cpe THEN s.cpe
                ELSE s.cpe + ';' + $cpes_join
              END,
              s.ai_inferred = true
            """,
            ip=coords["ip"],
            port=coords["port"],
            proto=coords["protocol"],
            product=product_from_cpe,
            version=version_from_cpe,
            cpes_join=cpes_22_join,
            first_cpe=cpes_22[0],
        )


def _link_ai_cve_to_service(coords: dict, cve) -> bool:
    """Create / refresh a Vulnerability node and link it to the exact service
    that produced the CPE match. Returns True if a new HAS_VULN was created.
    """
    with get_session() as session:
        session.run(
            """
            MERGE (v:Vulnerability {cve_id: $cve_id})
            ON CREATE SET
                v.cvss = $cvss,
                v.cvss_vector = $vector,
                v.severity = $severity,
                v.description = $description,
                v.has_exploit = $has_exploit,
                v.exploit_url = $exploit_url,
                v.exploit_sources = $exploit_sources,
                v.in_cisa_kev = $in_cisa_kev,
                v.cisa_kev_added = $cisa_kev_added,
                v.source = 'ai'
            ON MATCH SET
                v.has_exploit = CASE WHEN $has_exploit THEN true ELSE v.has_exploit END,
                v.in_cisa_kev = CASE WHEN $in_cisa_kev THEN true ELSE v.in_cisa_kev END,
                v.cvss_vector = coalesce(v.cvss_vector, $vector),
                v.cisa_kev_added = coalesce(v.cisa_kev_added, $cisa_kev_added),
                v.exploit_url = coalesce(v.exploit_url, $exploit_url),
                v.exploit_sources = CASE
                    WHEN $exploit_sources IS NULL OR $exploit_sources = '' THEN v.exploit_sources
                    WHEN v.exploit_sources IS NULL OR v.exploit_sources = '' THEN $exploit_sources
                    WHEN v.exploit_sources = $exploit_sources THEN v.exploit_sources
                    ELSE v.exploit_sources + '+' + $exploit_sources
                END,
                v.source = CASE
                    WHEN v.source IS NULL THEN 'ai'
                    WHEN v.source = 'ai' THEN 'ai'
                    WHEN v.source CONTAINS 'ai' THEN v.source
                    ELSE v.source + '+ai'
                END
            """,
            cve_id=cve.cve_id,
            cvss=cve.cvss,
            vector=cve.cvss_vector,
            severity=cve.severity,
            description=cve.description,
            has_exploit=cve.has_exploit,
            exploit_url=cve.exploit_url,
            exploit_sources=getattr(cve, "exploit_sources", "") or "",
            in_cisa_kev=cve.in_cisa_kev,
            cisa_kev_added=cve.cisa_kev_added,
        )

        # Confidence lives on the HAS_VULN relationship so a later upgrade
        # (script confirm, operator verdict) scopes to this specific socket.
        result = session.run(
            """
            MATCH (s:Service {host_ip: $ip, port: $port, protocol: $proto})
            WHERE NOT (s)-[:HAS_VULN]->(:Vulnerability {cve_id: $cve_id})
            MATCH (v:Vulnerability {cve_id: $cve_id})
            MERGE (s)-[rel:HAS_VULN]->(v)
            ON CREATE SET rel.confidence = 'check'
            RETURN s.host_ip AS linked
            """,
            ip=coords["ip"],
            port=coords["port"],
            proto=coords["protocol"],
            cve_id=cve.cve_id,
        )
        return result.single() is not None


# ---------------------------------------------------------------------------
# Phase 2: Host Classification
# ---------------------------------------------------------------------------


# How many ambiguous hosts per Claude request. 50 is a sweet spot:
# small enough that the LLM doesn't lose track of indices and produce
# sloppy matches, large enough that the fixed prompt overhead (role
# list, instructions, JSON schema — ~200 tokens per call) amortises
# across many hosts. A 500-host scan needs 10 calls at this size, and
# progress logging makes the wait visible to the operator.
_CLASSIFY_BATCH_SIZE = 50


def _classify_ambiguous_hosts() -> int:
    """Use AI to classify hosts where rule-based classifier has low confidence.

    Anonymized: real IPs replaced with host-N aliases before sending to AI.
    Processes every ambiguous host (role_confidence in (0, 0.6)) in
    batches — the earlier LIMIT 15 hard-cap silently dropped everyone
    past the fifteenth on networks with many partially-identified hosts.
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
            ORDER BY h.ip
            """,
        )
        hosts = list(result)

    if not hosts:
        return 0

    total = len(hosts)
    batch_total = (total + _CLASSIFY_BATCH_SIZE - 1) // _CLASSIFY_BATCH_SIZE
    logger.info(
        "AI classification: %d ambiguous hosts across %d batch%s",
        total, batch_total, "" if batch_total == 1 else "es",
    )

    batches = [
        hosts[i : i + _CLASSIFY_BATCH_SIZE]
        for i in range(0, total, _CLASSIFY_BATCH_SIZE)
    ]

    def _run_one(batch_num: int, batch: list) -> int:
        logger.info(
            "AI classification batch %d/%d (%d hosts)",
            batch_num, batch_total, len(batch),
        )
        return _classify_ambiguous_batch(batch)

    results = _gather_batches(
        [(_run_one, (n + 1, b)) for n, b in enumerate(batches)],
    )
    return sum(results)


def _classify_ambiguous_batch(hosts: list) -> int:
    """Classify one batch of ambiguous hosts via Claude, write results.

    Returns the number of hosts whose role was actually updated in the
    graph (``_apply_classifications`` refuses to downgrade).
    """
    ip_map, reverse_map = _build_anonymization_map([h["ip"] for h in hosts])

    # Compact prompt with anonymized IPs, no hostnames
    lines = []
    for h in hosts:
        alias = ip_map[h["ip"]]
        svcs = [
            f"{s['port']}/{s.get('protocol', 'tcp')} {s.get('product', s.get('name', ''))}"
            for s in h["services"]
            if s.get("port")
        ]
        lines.append(
            f"{alias}: {', '.join(svcs[:10]) if svcs else 'no services'}",
        )

    prompt = f"""Classify these network hosts by role based on their services.

Roles: domain_controller, web_server, database, mail_server, file_server, network_equipment, printer, voip, remote_access, hypervisor, dns_server, proxy, monitoring, siem, ci_cd, vpn_gateway, backup, unknown

Hosts:
{chr(10).join(lines)}

Respond with ONLY JSON: [{{"id": "host-N", "role": "role_name", "confidence": 0.0-1.0}}]
Only include hosts where confidence > 0.6."""

    # Output budget: 8192 leaves comfortable headroom over the ~2500-token
    # baseline for a 50-host batch. We pay only for what's generated;
    # over-provisioning costs nothing if the actual response fits.
    response = _call_claude(prompt, max_tokens=8192)
    if not response:
        return 0
    if response.truncated:
        logger.warning("Phase 2 classification: response truncated; tail hosts will not be reclassified")

    classifications = _parse_classification_response(response.text, reverse_map)
    return _apply_classifications(classifications)


# ---------------------------------------------------------------------------
# Phase 3: Contextual Engagement Triage
# ---------------------------------------------------------------------------


def _contextual_vuln_triage() -> tuple[int, int, int, int]:
    """AI reviews all vulns with engagement context and triages them.

    AI sees: scan sources (our positions), owned hosts, target hosts,
    all hosts with their vulns. Returns keep/dismiss verdicts.

    Returns:
        (kept, dismissed, targets_set, parse_failures)
        ``parse_failures`` counts how many batches returned a response we
        couldn't parse (typically truncated at max_tokens). Surfaced so a
        zero-dismissal result that's actually a parse-fail doesn't look
        like a clean run.

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

        # Pull untriaged vulns AND the host's full service inventory in
        # one query. AI now reads CVE description + every service open
        # on the host, which lets it derive surface-applicability
        # natively ("CVE attacks HTTP, host has only SFTP open → not
        # reachable") without our regex pre-classifier feeding a
        # structural [SURFACE_MISMATCH] flag. The full service shape
        # also helps role-disambiguation and chained-exploit reasoning.
        rows = list(session.run("""
            MATCH (h:Host)-[:HAS_SERVICE]->(allSvc:Service)
            WITH h, collect(DISTINCT {
                port: allSvc.port,
                name: allSvc.name,
                product: allSvc.product,
                version: allSvc.version
            }) AS all_services
            MATCH (h)-[:HAS_SERVICE]->(s:Service)-[r:HAS_VULN]->(v:Vulnerability)
            WHERE r.checked_status IS NULL
            RETURN h.ip AS ip, h.os_name AS os_name, h.role AS role,
                   h.owned AS owned, h.target AS target,
                   all_services,
                   s.port AS port, s.product AS product, s.version AS version,
                   s.name AS service_name,
                   coalesce(s.ai_inferred, false) AS ai_inferred,
                   v.cve_id AS cve_id, v.cvss AS cvss, v.has_exploit AS has_exploit,
                   v.description AS description, v.source AS source,
                   v.cvss_vector AS cvss_vector,
                   coalesce(v.in_cisa_kev, false) AS in_cisa_kev
            ORDER BY h.ip, s.port
        """))

    if not rows:
        return 0, 0, 0, 0

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
                # Full service inventory (sorted by port) — formatted
                # into the prompt so AI sees the host's whole shape, not
                # just the vulnerable surface.
                "all_services": sorted(
                    [s for s in (row.get("all_services") or [])
                     if s.get("port") is not None],
                    key=lambda x: x["port"],
                ),
                "vulns": [],
            }
        # Detect local-only from CVSS vector
        is_local = False
        vec = row.get("cvss_vector") or ""
        if "AV:L" in vec or "AV:P" in vec:
            is_local = True

        host_data[ip]["vulns"].append({
            "port": row["port"],
            "service_name": row.get("service_name"),
            "product": row["product"],
            "version": row["version"],
            "ai_inferred": bool(row.get("ai_inferred")),
            "cve_id": row["cve_id"],
            "cvss": row["cvss"],
            "has_exploit": row["has_exploit"],
            "description": (row["description"] or "")[:250],
            "source": row["source"],
            "is_local": is_local,
            "in_cisa_kev": bool(row.get("in_cisa_kev")),
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

    # Batch hosts: 15 per API call. Batches are independent (disjoint host
    # sets, read-only ip_map / context, guarded Cypher writes), so we fan
    # them out across a thread pool. See _AI_MAX_WORKERS for rationale.
    batches = [hosts[i:i + 15] for i in range(0, len(hosts), 15)]
    batch_total = len(batches)

    def _run_one(batch_num: int, batch: list[dict]) -> tuple[int, int, int, int]:
        logger.info("AI triage batch %d/%d (%d hosts)", batch_num, batch_total, len(batch))
        k, d, t, pf = _triage_batch(batch, ip_map, reverse_map, context)
        logger.info(
            "AI triage batch %d result: kept=%d, dismissed=%d, targets=%d, parse_failures=%d",
            batch_num, k, d, t, pf,
        )
        return k, d, t, pf

    results = _gather_batches(
        [(_run_one, (n + 1, b)) for n, b in enumerate(batches)],
    )
    total_kept = sum(r[0] for r in results)
    total_dismissed = sum(r[1] for r in results)
    total_targets = sum(r[2] for r in results)
    total_parse_failures = sum(r[3] for r in results)
    return total_kept, total_dismissed, total_targets, total_parse_failures


def _triage_batch(
    hosts: list[dict],
    ip_map: dict[str, str],
    reverse_map: dict[str, str],
    context: str,
) -> tuple[int, int, int]:
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
        # Full service inventory of this host — gives AI the shape of
        # the box, not just the vulnerable surface. Lets it reason
        # "CVE attacks HTTP, host has no HTTP port → not reachable" or
        # "CVE attacks HTTP, host has CrushFTP on :22 AND :443 → could
        # be exploitable on the alt port."
        svcs = h.get("all_services") or []
        if svcs:
            svc_strs = []
            for s in svcs:
                pv = ""
                if s.get("product"):
                    pv = f" {s['product']}"
                    if s.get("version"):
                        pv += f" {s['version']}"
                    elif s.get("product"):
                        pv += " ?"  # version unknown — important AI signal
                svc_strs.append(f":{s['port']}/{s.get('name') or '?'}{pv}")
            lines.append(f"  Services: {', '.join(svc_strs)}")
            lines.append("  Findings:")
        for v in h["vulns"]:
            prod = f"{v['product']} {v['version']}" if v.get("version") else (v.get("product") or "")
            # ``[ai-cpe]`` annotation when the product / version came
            # from AI Phase 1's banner-distillation rather than a real
            # nmap probe-match. Tells Phase 3 the identity is heuristic
            # — when the CVE description names a version that contradicts
            # the inferred one, the dismissal can still fire, but the
            # reasoning should acknowledge the inference (previous wording
            # of "no version fingerprint" was misleading when the version
            # WAS extracted, just by AI not nmap).
            ai_inferred_tag = " [ai-cpe]" if v.get("ai_inferred") else ""
            local_tag = " [LOCAL]" if v.get("is_local") else ""
            exploit_tag = " EXPLOIT" if v.get("has_exploit") else ""
            # CISA KEV = confirmed in-the-wild exploitation. Surface it so
            # triage treats these as near-untouchable gold — even if some
            # other heuristic (local vector on non-owned, say) would dismiss
            # a normal CVE, KEV entries should almost always stay.
            kev_tag = " KEV" if v.get("in_cisa_kev") else ""
            svc_name = v.get("service_name") or "?"
            lines.append(
                f"    :{v['port']}/{svc_name} {prod}{ai_inferred_tag}  {v['cve_id']} "
                f"CVSS:{v['cvss'] or '?'}{exploit_tag}{kev_tag}{local_tag} [{v['source']}]"
            )
            if v.get("description"):
                lines.append(f"      {v['description']}")
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
0. KEV (CISA Known Exploited Vulnerabilities) is a strong signal — CISA
   observed in-the-wild exploitation. Treat KEV as equivalent to a public
   exploit being available: it RAISES the bar for dismissal, it does NOT
   exempt the CVE from the other rules. KEV CVEs CAN still be dismissed
   when there is clear evidence of CPE mismatch, wrong product, wrong OS,
   reverse-temporal impossibility (KEV exploit targets product version
   newer than the one running here), or surface mismatch — apply the rules
   below in full. When in doubt on a KEV, prefer KEEP and note the concern.
1. Remote RCE/auth bypass on NON-OWNED hosts: KEEP (attack surface)
2. Local privilege escalation on OWNED hosts: KEEP (we can use these for privesc)
3. Local exploits on NON-OWNED hosts: DISMISS (we can't use these — no access)
4. OS mismatch — Linux-only CVE on Windows host or vice versa: DISMISS
5. Wrong product — dependency CVE, name collision (e.g. Oracle library CVE on Exchange): DISMISS
6. Exploits requiring specific uncommon configurations: DISMISS with reason
7. Remote vulns on OWNED hosts: KEEP but note "already owned"
8. DoS-only without exploit on low-value targets: DISMISS
9. CAULDRON-* exploit rules: almost always KEEP — these are pentester-focused findings
10. Version-range sanity check: if the CVE description names a specific version
    that is CLEARLY not the one running here (e.g. description says "OpenSSH 9.1"
    but the listed product line shows OpenSSH 7.4), DISMISS with reason "wrong
    version". Prefer the description-stated affected range over an empty/wildcard
    product line — wildcard-CPE NVD matches pull in CVEs for any release.
    The product/version on the service line IS the live identification —
    nmap probe-match if shown plain, or AI Phase 1 banner extraction if
    suffixed with ``[ai-cpe]``. Both are usable for this rule (do NOT
    reason "no version fingerprint" when ``[ai-cpe]`` shows a version —
    the version is there, just sourced from servicefp distillation rather
    than nmap's signature library).
11. Surface compatibility: read the CVE description and compare the
    attack vector it describes against the service this CVE is attached
    to AND the host's full Services list.
    (a) Surface mismatch — CVE attacks HTTP/HTTPS/web but the attached
        service is non-HTTP (e.g. CVE-2024-4040 SSTI on a :22/sftp
        service): scan the host's Services list. Decision depends on
        whether an alt-port has a CONFIRMED product match — the
        Services line shows ``product=`` only when nmap fingerprinted
        it; entries like ``:443/https`` (bare service name, no product
        word) mean the running software is unknown.
          - alt-port runs the SAME product as the affected service
            (e.g. :443/https CrushFTP next to :22/sftp CrushFTP) →
            KEEP with reason "verify alt-port :443 for HTTP interface"
          - HTTP port exists but its product is UNKNOWN or different
            (e.g. :443/https with no product fingerprint) → DISMISS,
            reason "HTTP-only CVE, alt-port not confirmed as same
            product — re-run nmap --version-intensity 9 to verify"
          - no HTTP port at all → DISMISS, reason "HTTP-only CVE,
            no HTTP service on this host"
    (b) Surface match — CVE protocol matches service protocol: KEEP
        unless another rule applies.
    (c) Library-level CVE (krb5 in Samba, openssl in TLS services):
        the description names a library, the service embeds it → KEEP.
        Don't be fooled by the protocol mismatch in this case.
12. UNIVERSAL DISMISSAL — when a CVE's precondition is the same on every
    affected host (Terrapin needs MITM regardless of host context;
    SCP-injection needs scp-usage regardless of role; user-enumeration
    needs nothing host-specific), use verdict="dismiss-all" instead of
    plain "dismiss". This signals Cauldron to mark the CVE as FP across
    every active edge in the graph, not just this socket — fixing the
    consistency problem where the same noise gets dismissed on some
    hosts but kept on others across batches.
    Use dismiss-all sparingly and only when the precondition is truly
    host-independent. When in doubt, use plain "dismiss" for the
    individual host.

CRITICAL: Do NOT dismiss CAULDRON-* IDs just because they are not standard CVEs.
If unsure, KEEP. Missing a real vuln is worse than keeping noise — except for
clear OS / product / version mismatches where the CVE description itself names
the wrong target.

Respond with ONLY JSON:
[{{"id": "host-N", "suggest_target": true, "vulns": [
  {{"cve_id": "CVE-YYYY-NNNNN", "port": 443, "verdict": "keep"}},
  {{"cve_id": "CAULDRON-042", "port": 6379, "verdict": "keep"}},
  {{"cve_id": "CVE-YYYY-NNNNN", "port": 22, "verdict": "dismiss", "reason": "Local privesc, host not owned"}},
  {{"cve_id": "CVE-2023-48795", "port": 22, "verdict": "dismiss-all", "reason": "Terrapin requires MITM position — universal precondition"}}
]}}]

Rules:
- "cve_id" field contains the vulnerability ID exactly as shown above (CVE-* or CAULDRON-*)
- verdict must be "keep", "dismiss", or "dismiss-all"
- reason required for dismiss / dismiss-all, optional for keep
- "suggest_target": true — set on hosts that should be priority targets
  (domain controllers, critical databases, mail servers, management interfaces)
  Only suggest targets that are NOT already marked as TARGET
- Include ALL vulns for each host (don't omit any)
- Respond with ONLY the JSON, no other text"""

    # Output budget: triage output scales with the count of vulns in the
    # batch (every vuln gets a verdict line, optionally with a reason).
    # A single host with 60+ findings (Kioptrix-class legacy stack) already
    # overflows 4096 tokens — the JSON gets truncated mid-string and the
    # parser silently fails, producing "0 dismissed" even when AI made
    # correct calls. 32768 covers every realistic batch (a 15-host batch
    # with ~50 vulns/host × ~75 tokens/verdict ≈ 56k worst-case, this
    # cap leaves room for typical 5-15k responses while still bounding
    # runaway output). Sonnet 4.6 supports up to 64k output; we pay only
    # for what's generated, so over-provisioning is free.
    response = _call_claude(prompt, max_tokens=32768)
    if not response:
        return vuln_count, 0, 0, 0  # If AI fails, keep everything

    kept, dismissed, targets = _apply_triage(response.text, reverse_map)
    parse_failed = 0
    if kept == 0 and dismissed == 0 and targets == 0 and vuln_count > 0:
        # Distinguish "AI returned a valid empty triage" from "AI response
        # was unparseable or truncated." A valid response would normally
        # carry at least some keeps for a non-empty batch -- zero across
        # the board only happens when the parser bailed.
        logger.warning(
            "AI triage returned 0 verdicts on a batch of %d vulns -- response %s. "
            "First 200 chars: %r",
            vuln_count,
            "TRUNCATED at max_tokens" if response.truncated else "unparseable",
            response.text[:200] if response.text else "(empty)",
        )
        parse_failed = 1
    return kept, dismissed, targets, parse_failed


def _apply_triage(response: str, reverse_map: dict[str, str]) -> tuple[int, int, int]:
    """Parse triage response and apply dismiss verdicts + target suggestions.

    Returns: (kept, dismissed, targets_set)

    Verdict types:
    - "keep" — leave the edge as-is.
    - "dismiss" — mark THIS edge (host+port+cve) as FP.
    - "dismiss-all" — mark every active edge for THIS CVE across the
      whole graph as FP (operator's "FP to all" mirror). KEV no longer
      blocks this path — KEV-flagged CVEs that turn out to be CPE-
      mismatch noise (NVD attribution bugs, reverse-temporal mismatch)
      get the same universal-dismiss treatment as any other CVE.
    """
    data = _parse_json_response(response)
    if not isinstance(data, list):
        return 0, 0, 0

    kept = 0
    dismissed = 0
    targets_set = 0
    # Track CVEs that already received a graph-wide bulk dismiss within
    # this batch — re-applying is a no-op but logging once is cleaner.
    bulk_dismissed_cves: set[str] = set()

    with get_session() as session:
        for item in data:
            if not isinstance(item, dict):
                continue
            alias = item.get("id", "")
            real_ip = reverse_map.get(alias, alias)

            # AI target suggestion
            if item.get("suggest_target"):
                result = session.run(
                    """
                    MATCH (h:Host {ip: $ip})
                    WHERE h.target <> true AND h.owned <> true
                    SET h.target = true
                    RETURN h.ip AS ip
                    """,
                    ip=real_ip,
                )
                if result.single():
                    targets_set += 1
                    logger.info("AI suggested target: %s", real_ip)

            for v in item.get("vulns", []):
                if not isinstance(v, dict):
                    continue
                verdict = v.get("verdict", "keep")
                cve_id = v.get("cve_id", "")
                port = v.get("port")

                if not cve_id:
                    continue

                if verdict == "dismiss-all":
                    # Mirror of operator's bulk-FP. Idempotent within a
                    # batch — skip if we already applied bulk for this CVE.
                    if cve_id in bulk_dismissed_cves:
                        continue
                    reason = v.get("reason", "AI universal dismiss — host-independent precondition")
                    result = session.run(
                        """
                        MATCH ()-[r:HAS_VULN]->(v:Vulnerability {cve_id: $cve_id})
                        WHERE r.checked_status IS NULL
                        SET r.checked_status = 'false_positive',
                            r.ai_fp_reason = $reason,
                            r.ai_normalized = 'ai_dismiss_all',
                            r.fp_source = 'ai'
                        RETURN count(r) AS affected
                        """,
                        cve_id=cve_id, reason=reason,
                    )
                    rec = result.single()
                    affected = rec["affected"] if rec else 0
                    if affected > 0:
                        bulk_dismissed_cves.add(cve_id)
                        dismissed += affected
                        logger.info(
                            "AI dismiss-all: %s — %d edges flipped — %s",
                            cve_id, affected, reason,
                        )
                elif verdict == "dismiss":
                    reason = v.get("reason", "AI triage: not exploitable in engagement context")
                    if isinstance(port, int) and port > 0:
                        result = session.run(
                            """
                            MATCH (h:Host {ip: $ip})-[:HAS_SERVICE]->(s:Service {port: $port})
                                  -[r:HAS_VULN]->(v:Vulnerability {cve_id: $cve_id})
                            WHERE r.checked_status IS NULL
                            SET r.checked_status = 'false_positive',
                                r.ai_fp_reason = $reason,
                                r.fp_source = 'ai'
                            RETURN v.cve_id AS cve_id
                            """,
                            ip=real_ip, port=port, cve_id=cve_id, reason=reason,
                        )
                    else:
                        # No port — dismiss on all ports
                        result = session.run(
                            """
                            MATCH (h:Host {ip: $ip})-[:HAS_SERVICE]->(s:Service)
                                  -[r:HAS_VULN]->(v:Vulnerability {cve_id: $cve_id})
                            WHERE r.checked_status IS NULL
                            SET r.checked_status = 'false_positive',
                                r.ai_fp_reason = $reason,
                                r.fp_source = 'ai'
                            RETURN count(r) AS cnt
                            """,
                            ip=real_ip, cve_id=cve_id, reason=reason,
                        )
                    if result.single():
                        dismissed += 1
                        logger.info("AI triage DISMISS: %s on %s — %s", cve_id, real_ip, reason)
                elif verdict == "keep":
                    kept += 1

    return kept, dismissed, targets_set


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


@dataclass
class ClaudeResponse:
    """Structured result of a Claude API call.

    Carries the response text plus the stop_reason so callers can detect
    truncation ("max_tokens") and either bump the budget or split the
    batch instead of silently treating a truncated response as a complete
    one. Before this struct, the parser would fail on the cut-off JSON
    and the caller would report "AI dismissed 0 findings" — visually
    indistinguishable from "AI kept everything intentionally."
    """

    text: str
    stop_reason: str | None = None  # "end_turn" | "max_tokens" | "stop_sequence" | "tool_use" | None
    truncated: bool = False


def _call_claude(prompt: str, max_tokens: int = 2048) -> ClaudeResponse | None:
    """Call Claude API and return a structured ClaudeResponse.

    Returns None for non-recoverable errors (auth raised separately,
    rate-limit, bad request, unexpected). Truncation at ``max_tokens``
    is NOT an error — caller decides whether to retry or accept the
    partial output. The ``truncated`` flag and ``stop_reason`` let
    callers tell "AI finished cleanly" from "we ran out of budget."
    """
    try:
        import anthropic
    except ImportError:
        logger.error("anthropic package not installed. Run: pip install 'cauldron[ai]'")
        return None

    try:
        client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        # Explicit ``timeout=600`` (10 min) bypasses the SDK's auto-
        # calculated nonstreaming timeout, which otherwise refuses any
        # ``max_tokens`` above ~21k as "streaming-required". With this in
        # place we can use the full Sonnet output budget (up to 64k) for
        # triage on engagement-scale graphs without rearchitecting to
        # streaming. Triage rarely takes more than 60-90s in practice;
        # 600s is a generous ceiling for the worst-case batch.
        message = client.messages.create(
            model=settings.ai_model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
            timeout=600.0,
        )
        text = message.content[0].text if message.content else ""
        stop_reason = getattr(message, "stop_reason", None)
        truncated = stop_reason == "max_tokens"
        if truncated:
            logger.warning(
                "Claude response truncated at max_tokens=%d (stop_reason=%s). "
                "The JSON parser will likely fail on cut-off output. "
                "Bump max_tokens or split the batch.",
                max_tokens, stop_reason,
            )
        return ClaudeResponse(text=text, stop_reason=stop_reason, truncated=truncated)
    except anthropic.AuthenticationError as e:
        # Short-circuit the whole boil pipeline — every subsequent phase
        # would hit the same 401 and spam the same log line. Caller is
        # ``analyze_graph`` which turns this into a user-visible
        # ``AnalysisResult.auth_error`` message.
        logger.error("Invalid Anthropic API key. Check CAULDRON_ANTHROPIC_API_KEY.")
        raise ClaudeAuthError("Invalid Anthropic API key") from e
    except anthropic.RateLimitError:
        logger.warning("Anthropic API rate limit hit, skipping AI analysis")
        return None
    except anthropic.BadRequestError as e:
        logger.error("Anthropic API error: %s", e.message)
        return None
    except Exception:
        logger.exception("Claude API call failed unexpectedly")
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
