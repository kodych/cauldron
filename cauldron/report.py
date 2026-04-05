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
    """Get all hosts with their services and vulnerability counts."""
    with get_session() as s:
        rows = list(s.run("""
            MATCH (h:Host)
            OPTIONAL MATCH (h)-[:HAS_SERVICE]->(svc:Service)
            OPTIONAL MATCH (svc)-[:HAS_VULN]->(v:Vulnerability)
            WITH h,
                 count(DISTINCT svc) AS svc_count,
                 count(DISTINCT v) AS vuln_count,
                 max(v.cvss) AS max_cvss,
                 sum(CASE WHEN v.has_exploit = true THEN 1 ELSE 0 END) AS exploit_count
            RETURN h.ip AS ip, h.hostname AS hostname, h.role AS role,
                   h.os_name AS os, h.state AS state,
                   svc_count, vuln_count, max_cvss, exploit_count
            ORDER BY exploit_count DESC, max_cvss DESC, vuln_count DESC
        """))
    return [dict(r) for r in rows]


def _query_critical_findings(top: int = 20) -> list[dict]:
    """Get top findings sorted by pentester priority: exploit > CVSS > confidence."""
    with get_session() as s:
        rows = list(s.run("""
            MATCH (h:Host)-[:HAS_SERVICE]->(svc:Service)-[r:HAS_VULN]->(v:Vulnerability)
            WHERE r.checked_status IS NULL OR r.checked_status <> 'false_positive'
            WITH h, svc, v, r,
                 CASE WHEN v.has_exploit = true THEN 1 ELSE 0 END AS has_exp,
                 COALESCE(v.cvss, 0) AS cvss,
                 CASE v.confidence
                    WHEN 'confirmed' THEN 3
                    WHEN 'likely' THEN 2
                    ELSE 1
                 END AS conf_score
            ORDER BY has_exp DESC, cvss DESC, conf_score DESC
            LIMIT $top
            RETURN h.ip AS ip, h.role AS role,
                   svc.port AS port, svc.protocol AS protocol,
                   svc.product AS product, svc.version AS version,
                   v.cve_id AS cve_id, v.cvss AS cvss,
                   v.has_exploit AS has_exploit,
                   v.confidence AS confidence, v.source AS source,
                   v.description AS description,
                   v.exploit_url AS exploit_url,
                   r.checked_status AS status
        """, top=top))
    return [dict(r) for r in rows]


def _query_vuln_stats() -> dict:
    """Get vulnerability statistics by severity and source."""
    with get_session() as s:
        rows = list(s.run("""
            MATCH ()-[r:HAS_VULN]->(v:Vulnerability)
            WHERE r.checked_status IS NULL OR r.checked_status <> 'false_positive'
            RETURN v.source AS source,
                   sum(CASE WHEN v.cvss >= 9.0 THEN 1 ELSE 0 END) AS critical,
                   sum(CASE WHEN v.cvss >= 7.0 AND v.cvss < 9.0 THEN 1 ELSE 0 END) AS high,
                   sum(CASE WHEN v.cvss >= 4.0 AND v.cvss < 7.0 THEN 1 ELSE 0 END) AS medium,
                   sum(CASE WHEN v.cvss < 4.0 OR v.cvss IS NULL THEN 1 ELSE 0 END) AS low,
                   sum(CASE WHEN v.has_exploit = true THEN 1 ELSE 0 END) AS with_exploit,
                   count(DISTINCT v) AS total
        """))
    return {r["source"]: dict(r) for r in rows}


def _query_checked_vulns() -> list[dict]:
    """Get vulnerabilities with checked status (exploited/mitigated)."""
    with get_session() as s:
        rows = list(s.run("""
            MATCH (h:Host)-[:HAS_SERVICE]->(svc:Service)-[r:HAS_VULN]->(v:Vulnerability)
            WHERE r.checked_status IS NOT NULL
            RETURN h.ip AS ip, svc.port AS port,
                   v.cve_id AS cve_id, v.cvss AS cvss,
                   r.checked_status AS status
            ORDER BY r.checked_status, v.cvss DESC
        """))
    return [dict(r) for r in rows]


def _query_bruteforceable() -> list[dict]:
    """Get bruteforceable services."""
    with get_session() as s:
        rows = list(s.run("""
            MATCH (h:Host)-[:HAS_SERVICE]->(svc:Service)
            WHERE svc.bruteforceable = true
            RETURN h.ip AS ip, h.role AS role,
                   svc.port AS port, svc.product AS product, svc.name AS name
            ORDER BY svc.port, h.ip
        """))
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Collect all data
# ---------------------------------------------------------------------------

def _collect_report_data(top: int = 20) -> dict:
    """Collect all data needed for report generation."""
    stats = get_graph_stats()
    roles = get_host_role_distribution()
    sources = _query_scan_sources()
    hosts = _query_hosts_with_vulns()
    findings = _query_critical_findings(top=top)
    vuln_stats = _query_vuln_stats()
    checked = _query_checked_vulns()
    brute = _query_bruteforceable()
    path_summary = get_path_summary()
    paths = discover_attack_paths()

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "stats": stats,
        "roles": roles,
        "scan_sources": sources,
        "hosts": hosts,
        "critical_findings": findings,
        "vuln_stats": vuln_stats,
        "checked_vulns": checked,
        "bruteforceable": brute,
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

def generate_json(top: int = 20) -> str:
    """Generate JSON report."""
    data = _collect_report_data(top=top)
    return json.dumps(data, indent=2, default=str, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Markdown format
# ---------------------------------------------------------------------------

def generate_markdown(top: int = 20) -> str:
    """Generate Markdown report — AI-compatible, structured, no recommendations."""
    data = _collect_report_data(top=top)
    lines: list[str] = []

    def w(line: str = "") -> None:
        lines.append(line)

    # Header
    w("# Cauldron Scan Report")
    w()
    w(f"**Generated:** {data['generated_at']}")
    w(f"**Tool:** Cauldron v0.1.0 — Network Attack Path Discovery")
    w()

    # --- 1. Summary ---
    w("## 1. Summary")
    w()
    s = data["stats"]
    w("| Metric | Value |")
    w("|--------|-------|")
    w(f"| Hosts discovered | {s['hosts']} |")
    w(f"| Services detected | {s['services']} |")
    w(f"| Network segments | {s['segments']} |")
    w(f"| Vulnerabilities | {s['vulnerabilities']} |")
    w(f"| Scan sources | {s['scan_sources']} |")
    w()

    # Scan sources
    if data["scan_sources"]:
        w("**Scan positions:**")
        w()
        for src in data["scan_sources"]:
            w(f"- `{src['name']}`")
        w()

    # Vuln stats by source
    vs = data["vuln_stats"]
    if vs:
        w("**Vulnerability breakdown:**")
        w()
        w("| Source | Critical | High | Medium | Low | With Exploit | Total |")
        w("|--------|----------|------|--------|-----|-------------|-------|")
        total_row = {"critical": 0, "high": 0, "medium": 0, "low": 0, "with_exploit": 0, "total": 0}
        for source, row in sorted(vs.items()):
            w(f"| {source} | {row['critical']} | {row['high']} | {row['medium']} | {row['low']} | {row['with_exploit']} | {row['total']} |")
            for k in total_row:
                total_row[k] += row[k]
        if len(vs) > 1:
            w(f"| **TOTAL** | **{total_row['critical']}** | **{total_row['high']}** | **{total_row['medium']}** | **{total_row['low']}** | **{total_row['with_exploit']}** | **{total_row['total']}** |")
        w()

    # Path summary
    ps = data["path_summary"]
    w(f"**Attack surface:** {ps['vulnerable_hosts']} vulnerable hosts, "
      f"{ps['with_exploits']} with known exploits, "
      f"{ps['pivot_hosts']} pivot points")
    w()

    # --- 2. Host Inventory ---
    w("## 2. Host Inventory")
    w()
    w("### 2.1 Role Distribution")
    w()
    w("| Role | Count |")
    w("|------|-------|")
    for role, count in sorted(data["roles"].items(), key=lambda x: -x[1]):
        w(f"| {role} | {count} |")
    w()

    w("### 2.2 All Hosts")
    w()
    w("| IP | Role | OS | Services | Vulns | Max CVSS | Exploits |")
    w("|----|------|-----|----------|-------|----------|----------|")
    for h in data["hosts"]:
        ip = h["ip"]
        role = h["role"] or "-"
        os_name = h["os"] or "-"
        cvss = f"{h['max_cvss']:.1f}" if h["max_cvss"] else "-"
        exp = str(h["exploit_count"]) if h["exploit_count"] else "-"
        w(f"| {ip} | {role} | {os_name} | {h['svc_count']} | {h['vuln_count']} | {cvss} | {exp} |")
    w()

    # --- 3. Critical Findings ---
    w("## 3. Critical Findings")
    w()
    if not data["critical_findings"]:
        w("No vulnerabilities found.")
        w()
    else:
        w(f"Top {len(data['critical_findings'])} findings by severity and exploitability:")
        w()
        w("| # | Host | Port | Vuln ID | CVSS | Exploit | Confidence | Source | Product |")
        w("|---|------|------|---------|------|---------|------------|--------|---------|")
        for i, f_ in enumerate(data["critical_findings"], 1):
            ip = f_["ip"]
            port = f"{f_['port']}/{f_['protocol']}"
            cve = f_["cve_id"] or "-"
            cvss = f"{f_['cvss']:.1f}" if f_["cvss"] else "N/A"
            exploit = "YES" if f_["has_exploit"] else "-"
            conf = f_["confidence"] or "-"
            source = f_["source"] or "-"
            prod = f"{f_['product'] or ''} {f_['version'] or ''}".strip() or "-"
            w(f"| {i} | {ip} | {port} | {cve} | {cvss} | {exploit} | {conf} | {source} | {prod} |")
        w()

        # Detail blocks for top findings
        w("### Finding Details")
        w()
        for i, f_ in enumerate(data["critical_findings"], 1):
            cve = f_["cve_id"] or "Unknown"
            cvss = f"{f_['cvss']:.1f}" if f_["cvss"] else "N/A"
            exploit_tag = " | EXPLOIT" if f_["has_exploit"] else ""
            w(f"**{i}. {cve}** (CVSS {cvss}{exploit_tag})")
            w(f"- Host: `{f_['ip']}:{f_['port']}/{f_['protocol']}`")
            prod = f"{f_['product'] or ''} {f_['version'] or ''}".strip()
            if prod:
                w(f"- Service: {prod}")
            if f_["description"]:
                desc = f_["description"]
                # First sentence only
                dot = desc.find(". ")
                if dot > 0:
                    desc = desc[: dot + 1]
                w(f"- Description: {desc}")
            if f_["exploit_url"]:
                w(f"- Exploit: {f_['exploit_url']}")
            w()

    # --- 4. Attack Paths ---
    w("## 4. Attack Paths")
    w()
    ap = data["attack_paths"]
    if not ap:
        w("No attack paths discovered.")
        w()
    else:
        w(f"{len(ap)} attack paths discovered:")
        w()
        for i, path in enumerate(ap, 1):
            exp_tag = " | EXPLOIT" if path["has_exploits"] else ""
            w(f"### Path {i}: → {path['target']} ({path['target_role']})")
            w(f"- Score: {path['score']} | Hops: {path['hops']} | Max CVSS: {path['max_cvss']}{exp_tag}")
            if path["methods"]:
                w(f"- Methods: {', '.join(path['methods'])}")
            w()
            w("| Hop | IP | Role | Vulns |")
            w("|-----|-----|------|-------|")
            for j, node in enumerate(path["nodes"]):
                vulns_str = ", ".join(
                    f"{v['cve_id']} ({v['cvss']})" for v in node["vulns"][:3]
                )
                if len(node["vulns"]) > 3:
                    vulns_str += f" +{len(node['vulns']) - 3} more"
                if not vulns_str:
                    vulns_str = "(pivot)"
                w(f"| {j} | {node['ip']} | {node['role']} | {vulns_str} |")
            w()

    # --- 5. Bruteforceable Services ---
    w("## 5. Bruteforceable Services")
    w()
    brute = data["bruteforceable"]
    if not brute:
        w("No bruteforceable services detected.")
        w()
    else:
        w(f"{len(brute)} services with brute-force potential:")
        w()
        w("| Host | Port | Service | Product |")
        w("|------|------|---------|---------|")
        for b in brute:
            name = b["name"] or "-"
            prod = b["product"] or "-"
            w(f"| {b['ip']} | {b['port']} | {name} | {prod} |")
        w()

    # --- 6. Checked Vulnerabilities ---
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
                cvss = f"{c['cvss']:.1f}" if c["cvss"] else "N/A"
                w(f"| {c['ip']} | {c['port']} | {c['cve_id']} | {cvss} |")
            w()

        if mitigated:
            w(f"### Mitigated ({len(mitigated)})")
            w()
            w("| Host | Port | Vuln ID | CVSS |")
            w("|------|------|---------|------|")
            for c in mitigated:
                cvss = f"{c['cvss']:.1f}" if c["cvss"] else "N/A"
                w(f"| {c['ip']} | {c['port']} | {c['cve_id']} | {cvss} |")
            w()

        if fps:
            w(f"### False Positives ({len(fps)})")
            w()
            w("| Host | Port | Vuln ID | CVSS |")
            w("|------|------|---------|------|")
            for c in fps:
                cvss = f"{c['cvss']:.1f}" if c["cvss"] else "N/A"
                w(f"| {c['ip']} | {c['port']} | {c['cve_id']} | {cvss} |")
            w()

    # --- Footer ---
    w("---")
    w("*Generated by Cauldron v0.1.0 — Network Attack Path Discovery*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML format
# ---------------------------------------------------------------------------

def generate_html(top: int = 20) -> str:
    """Generate self-contained HTML report from Markdown."""
    md_content = generate_markdown(top=top)

    # Simple Markdown-to-HTML via basic conversion
    # Use a minimal CSS-only approach — no JS dependencies
    html_lines = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "<meta charset='UTF-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
        "<title>Cauldron Scan Report</title>",
        "<style>",
        "body { font-family: -apple-system, 'Segoe UI', sans-serif; max-width: 1000px; margin: 0 auto; padding: 20px; background: #0f1117; color: #e2e8f0; line-height: 1.6; }",
        "h1 { color: #818cf8; border-bottom: 2px solid #3730a3; padding-bottom: 8px; }",
        "h2 { color: #a5b4fc; margin-top: 40px; border-bottom: 1px solid #1e1b4b; padding-bottom: 4px; }",
        "h3 { color: #c7d2fe; }",
        "table { border-collapse: collapse; width: 100%; margin: 16px 0; font-size: 13px; }",
        "th { background: #1e1b4b; color: #a5b4fc; text-align: left; padding: 8px 10px; border: 1px solid #312e81; }",
        "td { padding: 6px 10px; border: 1px solid #1e1b4b; }",
        "tr:nth-child(even) { background: #151822; }",
        "tr:hover { background: #1e2433; }",
        "code { background: #1e1b4b; padding: 2px 6px; border-radius: 3px; font-size: 12px; }",
        "strong { color: #fbbf24; }",
        "hr { border: none; border-top: 1px solid #1e1b4b; margin: 32px 0; }",
        "p { margin: 8px 0; }",
        "ul { padding-left: 20px; }",
        "</style>",
        "</head>",
        "<body>",
    ]

    # Simple line-by-line Markdown to HTML conversion
    in_table = False
    in_list = False

    for line in md_content.split("\n"):
        stripped = line.strip()

        # Table rows
        if stripped.startswith("|") and stripped.endswith("|"):
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            if all(set(c) <= set("-| ") for c in cells):
                continue  # Skip separator row
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
        elif stripped.startswith("## "):
            html_lines.append(f"<h2>{_md_inline(stripped[3:])}</h2>")
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

    html_lines.extend(["</body>", "</html>"])
    return "\n".join(html_lines)


def _md_inline(text: str) -> str:
    """Convert inline Markdown formatting to HTML."""
    import re
    # Bold
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    # Code
    text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
    return text
