# Architecture

Cauldron is a pipeline that takes a stream of network scans and turns
them into a queryable, AI-enriched attack graph. The whole thing
factors into four conceptual layers:

```
┌─────────────────────────────────────────────────────────────┐
│  Scanners       Nmap (-sV / -O / NSE)   |   Masscan        │
└──────────────────────────┬──────────────────────────────────┘
                           │ XML / JSON
┌──────────────────────────▼──────────────────────────────────┐
│  Parsers        cauldron.parsers.{nmap,masscan}_parser      │
└──────────────────────────┬──────────────────────────────────┘
                           │ ScanResult
┌──────────────────────────▼──────────────────────────────────┐
│  Ingestion      cauldron.graph.ingestion (MERGE-only)       │
└──────────────────────────┬──────────────────────────────────┘
                           │ Cypher
┌──────────────────────────▼──────────────────────────────────┐
│  Neo4j          Host / Service / Vulnerability / Path /     │
│                 Segment / ScanSource / Credential           │
└─────┬──────────────────┬───────────────────┬────────────────┘
      │                  │                   │
┌─────▼─────┐   ┌────────▼─────────┐   ┌─────▼─────────┐
│ NVD/KEV/  │   │  Local exploit   │   │ Claude API    │
│ EPSS      │   │  rules + creds   │   │ triage,       │
│ enricher  │   │  matcher         │   │ classification │
└───────────┘   └──────────────────┘   └────────────────┘
                           │
                           │ enriched graph
                           ▼
                   ┌───────────────┐         ┌──────────────┐
                   │  FastAPI      │◀────────│  React UI    │
                   │  cauldron     │         │  Sigma.js    │
                   │  serve        │────────▶│              │
                   └───────────────┘         └──────────────┘
```

## Modules

| Path | Role |
|---|---|
| `cauldron/parsers/` | Nmap XML, Masscan XML/JSON → `ScanResult` |
| `cauldron/graph/ingestion.py` | `ScanResult` → Neo4j MERGE writes |
| `cauldron/graph/topology.py` | IP → segment, traceroute → reachability |
| `cauldron/ai/classifier.py` | Rule-based host role classification |
| `cauldron/ai/cve_enricher.py` | NVD CPE matching, KEV/EPSS enrichment, AI fallback |
| `cauldron/ai/attack_paths.py` | Path discovery + scoring |
| `cauldron/ai/analyzer.py` | Three-phase AI orchestration (CPE distill / classify / triage) |
| `cauldron/exploits/` | Local exploit rule DB + default-credentials matcher |
| `cauldron/api/server.py` | FastAPI HTTP surface |
| `cauldron/cli/commands.py` | `cauldron <verb>` command handlers |
| `cauldron/report.py` | Markdown / JSON / HTML report exports |
| `cauldron/collect.py` | BloodHound-style target list extraction |

## Neo4j schema

```cypher
// Nodes
(:ScanSource {name, ip, timestamp, scan_args})
(:NetworkSegment {cidr})
(:Host {
    ip, hostname, state, mac, mac_vendor,
    os_name, os_accuracy, os_family, os_vendor, os_gen, ttl,
    role, role_confidence,
    first_seen, last_seen,
    is_new, is_stale, has_changes,
    owned, target, target_blocked, notes
})
(:Service {
    port, protocol, state,
    name, product, version, extra_info, banner, servicefp,
    cpe, bruteforceable, is_new, is_stale, notes
})
(:Vulnerability {
    cve_id, cvss, cvss_version, epss, in_cisa_kev, has_exploit,
    description, exploit_url, ai_normalized
})
(:Credential {username, password_hash, source})

// Relationships
(:ScanSource)-[:SCANNED_FROM]->(:Host)
(:Host)-[:IN_SEGMENT]->(:NetworkSegment)
(:Host)-[:HAS_SERVICE]->(:Service)
(:Service)-[:HAS_VULN {
    confidence,           // confirmed | likely | possible
    checked_status,       // pending | mitigated | exploited | false_positive
    ai_fp_reason,         // free-text from AI when checked_status=false_positive
    source                // nvd | exploit_db | ai
}]->(:Vulnerability)
(:NetworkSegment)-[:CAN_REACH]->(:NetworkSegment)
(:Host)-[:ROUTE_THROUGH]->(:Host)
(:Credential)-[:VALID_FOR]->(:Service)
```

Constraints: `Host.ip`, `NetworkSegment.cidr`, `Vulnerability.cve_id`,
`ScanSource.name` are unique. Indexes on `Host.role`, `Service.port`,
`Service.name`. See [cauldron/graph/connection.py](../cauldron/graph/connection.py).

## Design principles

**MERGE, don't CREATE.** Re-importing the same scan never duplicates
nodes; new scans add data to existing ones. This is how the same graph
can survive a multi-week engagement.

**Multi-perspective scans.** Every import records the scan source —
where (network position) the scan was run from. Pivoting through the
target's network is supposed to enrich the same graph, not start a new
one.

**Rule-based first, AI second.** Host classification, exploit matching,
and CVE/CPE filtering are deterministic rules. AI is a fallback for
edge cases and for context-aware false-positive triage. This keeps
costs predictable and behavior reproducible.

**Asymmetric error tolerance.** Missing a real vuln is far worse than
showing one extra. So defaults lean toward false positives the
operator can dismiss, not silent drops. The AI triage pass is
explicitly conservative: it never auto-dismisses anything in the CISA
KEV catalog.

**Anonymize before sending.** Phase 2 (host classification) and Phase
3 (contextual triage) replace IPs and hostnames with stable aliases
before the prompt leaves the box. The model sees `host-1` /
`segment-A` / role hints, never engagement IPs.

**Loopback by default.** `cauldron serve` binds to `127.0.0.1` and the
API ships without auth — exposing it on `0.0.0.0` is an explicit opt-in
because anyone on the local network would otherwise be able to
`DELETE /api/v1/reset`.
