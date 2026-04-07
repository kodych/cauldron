"""Report generation for Cauldron.

Exports scan results as structured Markdown, JSON, or HTML.
Designed for AI-compatible format — pentester adds notes and feeds to LLM for report drafting.
"""

from __future__ import annotations

import json
from datetime import datetime

from cauldron.graph.connection import get_session
from cauldron.graph.ingestion import get_graph_stats, get_host_role_distribution
from cauldron.ai.attack_paths import discover_attack_paths, get_path_summary


def _query_scan_sources() -> list[dict]:
    """Get scan source info."""
    with get_session() as s:
        rows = list(s.run(
            "MATCH (src:ScanSource) RETURN src.name AS name ORDER BY src.name"
        ))
    return [{"name": r["name"]} for r in rows]


def _query_hosts_with_vulns() -> list[dict]:
    """Get all hosts with services and vulnerability counts (FP-aware)."""
    with get_session() as s:
        rows = list(s.run("""
            MATCH (h:Host)
            OPTIONAL MATCH (h)-[:HAS_SERVICE]->(svc:Service)
            OPTIONAL MATCH (svc)-[r:HAS_VULN]->(v:Vulnerability)
            WHERE r IS NULL OR r.checked_status IS NULL OR r.checked_status <> 'false_positive'
            WITH h,
                 count(DISTINCT svc) AS svc_count,
                 count(DISTINCT v) AS vuln_count,
                 max(v.cvss) AS max_cvss,
                 sum(CASE WHEN v.has_exploit = true THEN 1 ELSE 0 END) AS exploit_count
            RETURN h.ip AS ip, h.hostname AS hostname, h.role AS role,
                   h.os_name AS os, h.state AS state, h.owned AS owned, h.target AS target,
                   svc_count, vuln_count, max_cvss, exploit_count
            ORDER BY exploit_count DESC, max_cvss DESC, vuln_count DESC
        """))
    return [dict(r) for r in rows]


def _query_findings_grouped() -> list[dict]:
    """Get findings grouped by CVE — one CVE with list of affected hosts."""
    with get_session() as s:
        rows = list(s.run("""
            MATCH (h:Host)-[:HAS_SERVICE]->(svc:Service)-[r:HAS_VULN]->(v:Vulnerability)
            WHERE r.checked_status IS NULL OR r.checked_status <> 'false_positive'
            WITH v, collect(DISTINCT {ip: h.ip, port: svc.port, product: svc.product, version: svc.version}) AS hosts
            RETURN v.cve_id AS cve_id, v.cvss AS cvss, v.has_exploit AS has_exploit,
                   v.confidence AS confidence, v.source AS source,
                   v.description AS description, v.exploit_url AS exploit_url,
                   v.exploit_module AS exploit_module,
                   size(hosts) AS host_count, hosts
            ORDER BY
                CASE WHEN v.has_exploit = true THEN 0 ELSE 1 END,
                COALESCE(v.cvss, 0) DESC
        """))
    return [dict(r) for r in rows]


def _query_vuln_stats() -> dict:
    """Get vulnerability statistics by source (FP-aware)."""
    with get_session() as s:
        rows = list(s.run("""
            MATCH ()-[r:HAS_VULN]->(v:Vulnerability)
            WHERE r.checked_status IS NULL OR r.checked_status <> 'false_positive'
            WITH v, CASE WHEN v.cvss IS NULL THEN 'no_cvss' ELSE 'has_cvss' END AS cvss_type
            RETURN v.source AS source,
                   sum(CASE WHEN v.cvss >= 9.0 THEN 1 ELSE 0 END) AS critical,
                   sum(CASE WHEN v.cvss >= 7.0 AND v.cvss < 9.0 THEN 1 ELSE 0 END) AS high,
                   sum(CASE WHEN v.cvss >= 4.0 AND v.cvss < 7.0 THEN 1 ELSE 0 END) AS medium,
                   sum(CASE WHEN v.cvss < 4.0 AND v.cvss IS NOT NULL THEN 1 ELSE 0 END) AS low,
                   sum(CASE WHEN v.cvss IS NULL THEN 1 ELSE 0 END) AS no_cvss,
                   sum(CASE WHEN v.has_exploit = true THEN 1 ELSE 0 END) AS with_exploit,
                   count(DISTINCT v) AS total
        """))
    return {r["source"]: dict(r) for r in rows}


def _query_checked_vulns() -> list[dict]:
    """Get vulnerabilities with checked status (exploited/mitigated/FP)."""
    with get_session() as s:
        rows = list(s.run("""
            MATCH (h:Host)-[:HAS_SERVICE]->(svc:Service)-[r:HAS_VULN]->(v:Vulnerability)
            WHERE r.checked_status IS NOT NULL
            RETURN h.ip AS ip, svc.port AS port,
                   v.cve_id AS cve_id, v.cvss AS cvss,
                   r.checked_status AS status, r.ai_fp_reason AS ai_reason
            ORDER BY r.checked_status, v.cvss DESC
        """))
    return [dict(r) for r in rows]


def _query_bruteforceable() -> list[dict]:
    """Get bruteforceable services grouped by port."""
    with get_session() as s:
        rows = list(s.run("""
            MATCH (h:Host)-[:HAS_SERVICE]->(svc:Service)
            WHERE svc.bruteforceable = true
            RETURN svc.port AS port, svc.name AS name,
                   collect(DISTINCT h.ip) AS hosts,
                   count(DISTINCT h.ip) AS host_count
            ORDER BY svc.port
        """))
    return [dict(r) for r in rows]


def _query_owned_target() -> dict:
    """Get owned and target hosts."""
    with get_session() as s:
        owned = [dict(r) for r in s.run(
            "MATCH (h:Host) WHERE h.owned = true RETURN h.ip AS ip, h.role AS role"
        )]
        targets = [dict(r) for r in s.run(
            "MATCH (h:Host) WHERE h.target = true RETURN h.ip AS ip, h.role AS role"
        )]
    return {"owned": owned, "targets": targets}


def _query_notes() -> dict:
    """Get host-level and service-level pentester notes."""
    result: dict = {"host_notes": [], "service_notes": []}
    with get_session() as s:
        rows = list(s.run("""
            MATCH (h:Host)
            WHERE h.notes IS NOT NULL AND h.notes <> ''
            RETURN h.ip AS ip, h.hostname AS hostname, h.role AS role, h.notes AS notes
            ORDER BY h.ip
        """))
        result["host_notes"] = [dict(r) for r in rows]

        rows = list(s.run("""
            MATCH (h:Host)-[:HAS_SERVICE]->(svc:Service)
            WHERE svc.notes IS NOT NULL AND svc.notes <> ''
            RETURN h.ip AS ip, svc.port AS port, svc.name AS name, svc.notes AS notes
            ORDER BY h.ip, svc.port
        """))
        result["service_notes"] = [dict(r) for r in rows]
    return result


# ---------------------------------------------------------------------------
# Collect all data
# ---------------------------------------------------------------------------

def _collect_report_data(top: int = 20, include_notes: bool = False) -> dict:
    """Collect all data needed for report generation."""
    stats = get_graph_stats()
    roles = get_host_role_distribution()
    sources = _query_scan_sources()
    hosts = _query_hosts_with_vulns()
    findings = _query_findings_grouped()
    vuln_stats = _query_vuln_stats()
    checked = _query_checked_vulns()
    brute = _query_bruteforceable()
    owned_target = _query_owned_target()
    path_summary = get_path_summary()
    paths = discover_attack_paths()
    notes = _query_notes() if include_notes else {"host_notes": [], "service_notes": []}

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "stats": stats,
        "roles": roles,
        "scan_sources": sources,
        "hosts": hosts,
        "findings": findings[:top],
        "vuln_stats": vuln_stats,
        "checked_vulns": checked,
        "bruteforceable": brute,
        "owned_target": owned_target,
        "notes": notes,
        "include_notes": include_notes,
        "path_summary": path_summary,
        "attack_paths": [
            {
                "target": p.nodes[-1].ip if p.nodes else "?",
                "target_role": p.target_role or "?",
                "hops": p.hop_count,
                "max_cvss": p.max_cvss,
                "has_exploits": p.has_exploits,
                "score": round(p.score, 1),
                "methods": p.attack_methods,
                "nodes": [
                    {
                        "ip": n.ip,
                        "role": n.role,
                        "vulns": [
                            {"cve_id": v.cve_id, "cvss": v.cvss, "has_exploit": v.has_exploit,
                             "confidence": v.confidence, "title": v.title}
                            for v in n.vulns
                        ],
                    }
                    for n in p.nodes
                ],
            }
            for p in paths[:top]
        ],
    }


# ---------------------------------------------------------------------------
# JSON format
# ---------------------------------------------------------------------------

def generate_json(top: int = 20, include_notes: bool = False) -> str:
    """Generate JSON report."""
    data = _collect_report_data(top=top, include_notes=include_notes)
    return json.dumps(data, indent=2, default=str, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Markdown format
# ---------------------------------------------------------------------------

def _fmt_cvss(cvss) -> str:
    """Format CVSS score — show value or dash for exploit_db rules without CVSS."""
    if cvss and cvss > 0:
        return f"{cvss:.1f}"
    return "-"


def generate_markdown(top: int = 20, include_notes: bool = False) -> str:
    """Generate Markdown report — AI-compatible, structured, no recommendations."""
    data = _collect_report_data(top=top, include_notes=include_notes)
    lines: list[str] = []

    def w(line: str = "") -> None:
        lines.append(line)

    # Header
    w("# Cauldron Scan Report")
    w()
    w(f"**Generated:** {data['generated_at']}")
    w(f"**Tool:** Cauldron v0.1.0 — Network Attack Path Discovery")
    w()

    # --- 1. Executive Summary ---
    w("## 1. Executive Summary")
    w()
    s = data["stats"]
    ps = data["path_summary"]
    ot = data["owned_target"]

    w("| Metric | Value |")
    w("|--------|-------|")
    w(f"| Hosts | **{s['hosts']}** |")
    w(f"| Services | **{s['services']}** |")
    w(f"| Segments | **{s['segments']}** |")
    w(f"| Findings | **{s['findings']}** |")
    w(f"| Unique vulnerabilities | **{s['vulnerabilities']}** |")
    w(f"| Vulnerable hosts | **{ps['vulnerable_hosts']}** |")
    w(f"| With public exploits | **{ps['with_exploits']}** |")
    w(f"| Scan sources | **{s['scan_sources']}** |")
    w()

    if ot["owned"]:
        owned_str = ", ".join("`{ip}` [{role}]".format(**h) for h in ot["owned"])
        w(f"**Owned hosts:** {owned_str}")
        w()
    if ot["targets"]:
        target_str = ", ".join("`{ip}` [{role}]".format(**h) for h in ot["targets"])
        w(f"**Targets:** {target_str}")
        w()

    if data["scan_sources"]:
        src_str = ", ".join("`{name}`".format(**src) for src in data["scan_sources"])
        w(f"**Scan positions:** {src_str}")
        w()

    # Vuln stats compact
    vs = data["vuln_stats"]
    if vs:
        total_exploit = sum(r.get("with_exploit", 0) for r in vs.values())
        total_high = sum(r.get("critical", 0) + r.get("high", 0) for r in vs.values())
        w(f"**{total_exploit}** findings with public exploits, **{total_high}** critical/high severity.")
        w()

    # --- 2. Critical Findings ---
    w("## 2. Critical Findings")
    w()
    findings = data["findings"]
    if not findings:
        w("No vulnerabilities found.")
        w()
    else:
        w(f"{len(findings)} unique vulnerabilities, sorted by exploitability:")
        w()
        for i, f_ in enumerate(findings, 1):
            cve = f_["cve_id"]
            cvss = _fmt_cvss(f_["cvss"])
            exploit_tag = " **EXPLOIT**" if f_["has_exploit"] else ""
            host_count = f_["host_count"]
            hosts_list = f_["hosts"]

            w(f"### {i}. {cve} (CVSS: {cvss}){exploit_tag}")
            if f_["description"]:
                desc = f_["description"]
                dot = desc.find(". ")
                if dot > 0 and dot < 200:
                    desc = desc[:dot + 1]
                w(f"> {desc}")
            w()

            # Metadata line
            meta = []
            if f_["confidence"]:
                meta.append(f"Confidence: {f_['confidence']}")
            if f_["source"]:
                meta.append(f"Source: {f_['source']}")
            if f_["exploit_module"]:
                meta.append(f"Module: `{f_['exploit_module']}`")
            if meta:
                w(f"_{' | '.join(meta)}_")

            if f_["exploit_url"]:
                w(f"Exploit: {f_['exploit_url']}")
            w()

            # Affected hosts
            w(f"**Affected hosts ({host_count}):**")
            w()
            # Group by port
            port_groups: dict[int, list[str]] = {}
            for h in hosts_list:
                port = h.get("port", 0)
                ip = h.get("ip", "?")
                if port not in port_groups:
                    port_groups[port] = []
                if ip not in port_groups[port]:
                    port_groups[port].append(ip)

            for port in sorted(port_groups.keys()):
                ips = port_groups[port]
                w(f"- Port {port}: {', '.join(f'`{ip}`' for ip in ips)}")
            w()

    # --- 3. Attack Paths ---
    w("## 3. Attack Paths")
    w()
    ap = data["attack_paths"]
    if not ap:
        w("No attack paths discovered.")
        w()
    else:
        w(f"{len(ap)} attack paths, ranked by score:")
        w()
        w("| # | Source | Target | Role | Score | Methods | Key Vulns |")
        w("|---|--------|--------|------|-------|---------|-----------|")
        for i, path in enumerate(ap, 1):
            source = path["nodes"][0]["ip"] if path["nodes"] else "?"
            target = path["target"]
            role = path["target_role"]
            score = path["score"]
            methods = ", ".join(path["methods"])
            # Top vuln from target node
            target_vulns = path["nodes"][-1]["vulns"] if path["nodes"] else []
            key_vulns = ", ".join(v["cve_id"] for v in target_vulns[:2])
            if len(target_vulns) > 2:
                key_vulns += f" +{len(target_vulns) - 2}"
            exp = " 🔥" if path["has_exploits"] else ""
            w(f"| {i} | `{source}` | `{target}` | {role} | {score}{exp} | {methods} | {key_vulns} |")
        w()

    # --- 4. Host Inventory ---
    w("## 4. Host Inventory")
    w()

    # Split: hosts with findings vs clean hosts
    vuln_hosts = [h for h in data["hosts"] if h["vuln_count"] > 0]
    clean_hosts = [h for h in data["hosts"] if h["vuln_count"] == 0]

    if vuln_hosts:
        w(f"### Vulnerable Hosts ({len(vuln_hosts)})")
        w()
        header = "| IP | Hostname | Role | Services | Vulns | Max CVSS | Exploits |"
        sep = "|----|----------|------|----------|-------|----------|----------|"
        if data["include_notes"]:
            header = "| IP | Hostname | Role | Services | Vulns | Max CVSS | Exploits | Notes |"
            sep = "|----|----------|------|----------|-------|----------|----------|-------|"
        w(header)
        w(sep)
        for h in vuln_hosts:
            ip = h["ip"]
            hostname = h["hostname"] or "-"
            role = h["role"] or "-"
            cvss = _fmt_cvss(h["max_cvss"])
            exp = str(h["exploit_count"]) if h["exploit_count"] else "-"
            tags = ""
            if h.get("owned"):
                tags += " 🔓"
            if h.get("target"):
                tags += " 🎯"
            row = f"| {ip}{tags} | {hostname} | {role} | {h['svc_count']} | {h['vuln_count']} | {cvss} | {exp} |"
            if data["include_notes"]:
                # Find notes inline
                note = "-"
                for hn in data["notes"]["host_notes"]:
                    if hn["ip"] == ip:
                        note = hn["notes"].replace("\n", " ").replace("|", "/")[:60]
                        break
                row += f" {note} |"
            w(row)
        w()

    if clean_hosts:
        w(f"### Clean Hosts ({len(clean_hosts)})")
        w()
        # Compact: just role groups with IP lists
        role_groups: dict[str, list[str]] = {}
        for h in clean_hosts:
            role = h["role"] or "unknown"
            if role not in role_groups:
                role_groups[role] = []
            role_groups[role].append(h["ip"])

        for role in sorted(role_groups.keys()):
            ips = role_groups[role]
            w(f"- **{role}** ({len(ips)}): {', '.join(f'`{ip}`' for ip in ips[:10])}"
              + (f" +{len(ips) - 10} more" if len(ips) > 10 else ""))
        w()

    # Role distribution
    w("### Role Distribution")
    w()
    w("| Role | Count |")
    w("|------|-------|")
    for role, count in sorted(data["roles"].items(), key=lambda x: -x[1]):
        w(f"| {role} | {count} |")
    w()

    # --- 5. Bruteforceable Services ---
    brute = data["bruteforceable"]
    if brute:
        w("## 5. Bruteforceable Services")
        w()
        total_brute = sum(b["host_count"] for b in brute)
        w(f"{total_brute} services across {len(brute)} port types:")
        w()
        for b in brute:
            port = b["port"]
            name = b["name"] or f"port {port}"
            hosts = b["hosts"]
            count = b["host_count"]
            # Show max 10 IPs, then +N more
            ips_display = ", ".join(f"`{ip}`" for ip in hosts[:10])
            if count > 10:
                ips_display += f" +{count - 10} more"
            w(f"- **:{port} {name}** ({count} hosts): {ips_display}")
        w()

    # --- 6. Verification Status ---
    checked = data["checked_vulns"]
    if checked:
        w("## 6. Verification Status")
        w()
        exploited = [c for c in checked if c["status"] == "exploited"]
        mitigated = [c for c in checked if c["status"] == "mitigated"]
        fps = [c for c in checked if c["status"] == "false_positive"]

        if exploited:
            w(f"### Exploited ({len(exploited)})")
            w()
            w("| Host | Port | Vuln ID | CVSS |")
            w("|------|------|---------|------|")
            for c in exploited:
                w(f"| {c['ip']} | {c['port']} | {c['cve_id']} | {_fmt_cvss(c['cvss'])} |")
            w()

        if mitigated:
            w(f"### Mitigated ({len(mitigated)})")
            w()
            w("| Host | Port | Vuln ID | CVSS |")
            w("|------|------|---------|------|")
            for c in mitigated:
                w(f"| {c['ip']} | {c['port']} | {c['cve_id']} | {_fmt_cvss(c['cvss'])} |")
            w()

        if fps:
            w(f"### False Positives ({len(fps)})")
            w()
            w("| Host | Port | Vuln ID | Reason |")
            w("|------|------|---------|--------|")
            for c in fps:
                reason = (c.get("ai_reason") or "Manual").replace("|", "/")[:60]
                w(f"| {c['ip']} | {c['port']} | {c['cve_id']} | {reason} |")
            w()

    # --- 7. Pentester Notes ---
    if data["include_notes"]:
        host_notes = data["notes"]["host_notes"]
        svc_notes = data["notes"]["service_notes"]
        if host_notes or svc_notes:
            w("## 7. Pentester Notes")
            w()
            if host_notes:
                w("### Host Notes")
                w()
                for hn in host_notes:
                    label = hn["ip"]
                    if hn.get("hostname"):
                        label += f" ({hn['hostname']})"
                    w(f"**{label}** [{hn.get('role', 'unknown')}]")
                    w()
                    w(f"> {hn['notes'].replace(chr(10), chr(10) + '> ')}")
                    w()
            if svc_notes:
                w("### Service Notes")
                w()
                w("| Host | Port | Service | Notes |")
                w("|------|------|---------|-------|")
                for sn in svc_notes:
                    note = sn["notes"].replace("\n", " ").replace("|", "/")
                    name = sn.get("name") or "-"
                    w(f"| {sn['ip']} | {sn['port']} | {name} | {note} |")
                w()

    # --- Footer ---
    w("---")
    w("*Generated by Cauldron v0.1.0 — Network Attack Path Discovery*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML format
# ---------------------------------------------------------------------------

def generate_html(top: int = 20, include_notes: bool = False) -> str:
    """Generate self-contained interactive HTML report.

    Features: sortable tables, keyword search/highlight, collapsible sections,
    copy-to-clipboard buttons. No external dependencies — fully offline.
    """
    md_content = generate_markdown(top=top, include_notes=include_notes)

    css = """
body { font-family: -apple-system, 'Segoe UI', sans-serif; max-width: 1100px; margin: 0 auto; padding: 20px; background: #0f1117; color: #e2e8f0; line-height: 1.6; }
h1 { color: #818cf8; border-bottom: 2px solid #3730a3; padding-bottom: 8px; }
h2 { color: #a5b4fc; margin-top: 40px; border-bottom: 1px solid #1e1b4b; padding-bottom: 4px; cursor: pointer; }
h2:hover { color: #c7d2fe; }
h2::before { content: '▼ '; font-size: 10px; }
h2.collapsed::before { content: '▶ '; font-size: 10px; }
h3 { color: #c7d2fe; }
table { border-collapse: collapse; width: 100%; margin: 16px 0; font-size: 13px; }
th { background: #1e1b4b; color: #a5b4fc; text-align: left; padding: 8px 10px; border: 1px solid #312e81; cursor: pointer; user-select: none; }
th:hover { background: #312e81; }
th.sorted-asc::after { content: ' ▲'; font-size: 9px; }
th.sorted-desc::after { content: ' ▼'; font-size: 9px; }
td { padding: 6px 10px; border: 1px solid #1e1b4b; }
tr:nth-child(even) { background: #151822; }
tr:hover { background: #1e2433; }
code { background: #1e1b4b; padding: 2px 6px; border-radius: 3px; font-size: 12px; color: #22c55e; }
strong { color: #fbbf24; }
em { color: #94a3b8; }
hr { border: none; border-top: 1px solid #1e1b4b; margin: 32px 0; }
p { margin: 8px 0; }
ul { padding-left: 20px; }
blockquote { border-left: 3px solid #3730a3; margin: 8px 0; padding: 4px 12px; color: #94a3b8; }
.search-bar { position: sticky; top: 0; z-index: 100; background: #0f1117; padding: 10px 0; border-bottom: 1px solid #1e1b4b; margin-bottom: 20px; display: flex; gap: 10px; align-items: center; }
.search-bar input { flex: 1; background: #1e1b4b; border: 1px solid #312e81; color: #e2e8f0; padding: 8px 12px; border-radius: 6px; font-size: 13px; outline: none; }
.search-bar input:focus { border-color: #818cf8; }
.search-bar button { background: #312e81; color: #a5b4fc; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 12px; }
.search-bar button:hover { background: #3730a3; }
mark { background: #854d0e; color: #fbbf24; padding: 1px 2px; border-radius: 2px; }
.section-content { overflow: hidden; transition: max-height 0.3s ease; }
.section-content.collapsed { max-height: 0 !important; overflow: hidden; }
.nav-bar { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px; }
.nav-bar a { background: #1e1b4b; color: #a5b4fc; padding: 4px 12px; border-radius: 4px; text-decoration: none; font-size: 12px; }
.nav-bar a:hover { background: #312e81; }
"""

    js = """
// Sortable tables: click header to sort
document.addEventListener('click', function(e) {
  if (e.target.tagName !== 'TH') return;
  var th = e.target;
  var table = th.closest('table');
  if (!table) return;
  var idx = Array.from(th.parentNode.children).indexOf(th);
  var tbody = table.querySelector('tbody');
  if (!tbody) return;
  var rows = Array.from(tbody.rows);
  var asc = !th.classList.contains('sorted-asc');
  // Clear other headers
  th.parentNode.querySelectorAll('th').forEach(function(h) { h.classList.remove('sorted-asc','sorted-desc'); });
  th.classList.add(asc ? 'sorted-asc' : 'sorted-desc');
  rows.sort(function(a, b) {
    var av = a.cells[idx] ? a.cells[idx].textContent.trim() : '';
    var bv = b.cells[idx] ? b.cells[idx].textContent.trim() : '';
    var an = parseFloat(av), bn = parseFloat(bv);
    if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
    return asc ? av.localeCompare(bv) : bv.localeCompare(av);
  });
  rows.forEach(function(r) { tbody.appendChild(r); });
});

// Keyword search and highlight
function doSearch() {
  var q = document.getElementById('search-input').value.trim();
  // Remove old marks
  document.querySelectorAll('mark[data-search]').forEach(function(m) {
    m.replaceWith(m.textContent);
  });
  if (!q) return;
  var keywords = q.split(',').map(function(k) { return k.trim(); }).filter(Boolean);
  if (!keywords.length) return;
  var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
  var nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  keywords.forEach(function(kw) {
    var re = new RegExp('(' + kw.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&') + ')', 'gi');
    nodes.forEach(function(node) {
      if (node.parentNode.tagName === 'SCRIPT' || node.parentNode.tagName === 'STYLE') return;
      if (node.parentNode.tagName === 'MARK') return;
      if (!re.test(node.textContent)) return;
      var span = document.createElement('span');
      span.innerHTML = node.textContent.replace(re, '<mark data-search>$1</mark>');
      node.parentNode.replaceChild(span, node);
    });
  });
  // Scroll to first match
  var first = document.querySelector('mark[data-search]');
  if (first) first.scrollIntoView({behavior:'smooth', block:'center'});
}

// Collapsible sections
document.addEventListener('click', function(e) {
  if (e.target.tagName !== 'H2') return;
  var next = e.target.nextElementSibling;
  if (!next || !next.classList.contains('section-content')) return;
  next.classList.toggle('collapsed');
  e.target.classList.toggle('collapsed');
});
"""

    html_lines = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "<meta charset='UTF-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
        "<title>Cauldron Scan Report</title>",
        f"<style>{css}</style>",
        "</head>",
        "<body>",
        # Search bar
        '<div class="search-bar">',
        '<input id="search-input" type="text" placeholder="Search keywords (comma separated): ssh, admin, CVE-2024..." onkeydown="if(event.key===\'Enter\')doSearch()">',
        '<button onclick="doSearch()">Search</button>',
        '<button onclick="document.getElementById(\'search-input\').value=\'\';doSearch()">Clear</button>',
        '</div>',
    ]

    # Navigation bar
    html_lines.append('<div class="nav-bar">')
    section_num = 0
    for line in md_content.split("\n"):
        stripped = line.strip()
        if stripped.startswith("## "):
            section_num += 1
            title = stripped[3:]
            anchor = f"section-{section_num}"
            html_lines.append(f'<a href="#{anchor}">{_md_inline(title)}</a>')
    html_lines.append('</div>')

    # Convert Markdown to HTML with section wrapping
    in_table = False
    in_list = False
    in_section = False
    section_num = 0

    for line in md_content.split("\n"):
        stripped = line.strip()

        # H2 = new collapsible section
        if stripped.startswith("## "):
            if in_table:
                html_lines.append("</tbody></table>")
                in_table = False
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            if in_section:
                html_lines.append("</div>")  # close section-content
            section_num += 1
            anchor = f"section-{section_num}"
            html_lines.append(f'<h2 id="{anchor}">{_md_inline(stripped[3:])}</h2>')
            html_lines.append('<div class="section-content">')
            in_section = True
            continue

        # Table rows
        if stripped.startswith("|") and stripped.endswith("|"):
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            if all(set(c) <= set("-| ") for c in cells):
                continue
            if not in_table:
                html_lines.append("<table><thead><tr>")
                for cell in cells:
                    html_lines.append(f"<th>{_md_inline(cell)}</th>")
                html_lines.append("</tr></thead><tbody>")
                in_table = True
            else:
                html_lines.append("<tr>")
                for cell in cells:
                    html_lines.append(f"<td>{_md_inline(cell)}</td>")
                html_lines.append("</tr>")
            continue

        if in_table and not stripped.startswith("|"):
            html_lines.append("</tbody></table>")
            in_table = False

        # Blockquote
        if stripped.startswith("> "):
            html_lines.append(f"<blockquote>{_md_inline(stripped[2:])}</blockquote>")
            continue

        # List items
        if stripped.startswith("- "):
            if not in_list:
                html_lines.append("<ul>")
                in_list = True
            html_lines.append(f"<li>{_md_inline(stripped[2:])}</li>")
            continue

        if in_list and not stripped.startswith("- "):
            html_lines.append("</ul>")
            in_list = False

        # Headers
        if stripped.startswith("# "):
            html_lines.append(f"<h1>{_md_inline(stripped[2:])}</h1>")
        elif stripped.startswith("### "):
            html_lines.append(f"<h3>{_md_inline(stripped[4:])}</h3>")
        elif stripped.startswith("---"):
            html_lines.append("<hr>")
        elif stripped == "":
            html_lines.append("")
        else:
            html_lines.append(f"<p>{_md_inline(stripped)}</p>")

    if in_table:
        html_lines.append("</tbody></table>")
    if in_list:
        html_lines.append("</ul>")
    if in_section:
        html_lines.append("</div>")

    html_lines.append(f"<script>{js}</script>")
    html_lines.extend(["</body>", "</html>"])
    return "\n".join(html_lines)


def _md_inline(text: str) -> str:
    """Convert inline Markdown formatting to HTML."""
    import re
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'_(.+?)_', r'<em>\1</em>', text)
    text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
    return text
