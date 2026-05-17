# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] — 2026-05-17

Host-OS kernel privilege escalation enrichment, an exploit-availability
index covering Metasploit + Exploit-DB, ownership-gated AV:L surfacing,
strict NVD configuration-tree evaluation, and a UI refactor that splits
vuln triage to per-port granularity. No schema migrations; safe to
upgrade in place.

### Added

#### Host-OS / kernel privesc enrichment
- Cauldron now enriches a host-level CVE backlog from the OS CPE, not
  just service-level CVEs. Kernel privilege escalation is back in play
  for any host with a fingerprinted OS.
- Specific-version OS CPE anchors derived from the nmap osclass tree,
  plus bare-version sub-product candidates so NVD matches single-version
  configs (e.g. `linux_kernel:2.6.9`) rather than only the generation
  prefix.
- Windows family OS CPEs are now queried as a group so a single
  fingerprint surfaces CVEs across the full family in scope.
- Per-host ownership gate on AV:L findings: kernel privesc only attaches
  to the graph when the host is marked owned, keeping pre-foothold views
  free of locally-exploitable noise.
- `Mark-as-Owned` re-enriches from the host-OS CVE cache synchronously
  inside the PATCH; AV:L entries surface immediately, no second boil
  needed. Primary CPE + parser-emitted alt CPEs are merged so versioned
  anchors are not missed.

#### ExploitIndex (CVE → public-exploit-references library)
- New `ExploitIndex` library cross-references CVEs against the
  Metasploit Framework module catalogue and Exploit-DB CSV mirror.
- `cauldron refresh-exploits` CLI command pulls/refreshes the index;
  `cauldron boil --nvd` triggers an auto-refresh when the index is
  cold or stale.
- `Vulnerability` nodes now carry an `exploit_sources` field listing
  every source that detected a public exploit (Metasploit, Exploit-DB,
  internal exploit_rules), instead of recording only the first hit.
- The UI surfaces per-source provenance chips on `EXPLOIT` findings so
  the operator can see at a glance which source(s) flagged the CVE.

#### AI Phase 1
- AI Phase 1 now distinguishes daemons from dispatched tools (e.g. an
  `xinetd`-wrapped service vs the underlying daemon), so CPE inference
  targets the right product.
- The inferred product / version surface back onto the `Service` node,
  so downstream queries can use AI-derived data when nmap was silent.

#### UI
- LPE badge on AV:L findings — kernel privesc is visually distinct from
  remote-access vulns in the per-host triage view.
- Per-port vuln triage: grouped CVE rows collapse by default and expand
  into per-port sub-rows, with FP visibility tracked per port. The
  refactor removes the duplicate `FALSE POSITIVE` label and wraps long
  reasons.
- `fp_source` is tracked on each FP edge so manual operator FPs are not
  mislabelled as AI verdicts on subsequent refreshes.
- Single MSF/EDB chip on the canonical-exploit-source side of each
  finding instead of duplicated tags.

#### Parser
- `smb-os-discovery` NSE output now overrides the osmatch fingerprint
  guess when present, since SMB-protocol-confirmed OS identity is
  stronger evidence than TCP/IP stack heuristics.

#### REST API
- `/api/v1/hosts` list endpoint now includes host-OS vulnerabilities,
  not just service-level findings.
- `cauldron serve` access logs filter 2xx / 3xx responses so the
  console stays readable during long engagements.

### Changed

- Strict NVD configuration-tree evaluation: applicability is walked over
  the full AND/OR config tree per CVE rather than flat CPE matching.
  Gated on `os_accuracy=100` to keep low-confidence OS fingerprints from
  poisoning host-OS enrichment.
- CVSS ≥ 7.0 severity floor for host-OS CVEs (drops the prior arbitrary
  cap on the upper end); EPSS probability gate added on the lower end
  so noisy low-likelihood entries are filtered before they reach the
  graph.
- KEV is now treated as exploit-equivalent in scoring instead of as a
  short-circuit bypass — a KEV-listed CVE that lacks a public exploit
  module is no longer auto-promoted past availability checks.
- Versionless applicability carve-out for OS-typed CPEs: the version-slot
  check is skipped for `cpe:o:` CPEs, and the recency cutoff that drops
  old versionless service CVEs does not apply to OS CPEs. Together this
  keeps long-tail kernel CVEs reachable for ancient host OSes.
- `exploit_db.yaml` OS-level rules are gated by `port_match` so they
  fire only when the matching port set is actually open on the host.
- Banner extrainfo is paired with `service.version` when emitting CPE
  candidates, so applications carried in extrainfo (Webmin behind
  MiniServ, Drupal behind Apache) get a versioned CPE for NVD to
  validate. Detection of these CVEs no longer requires AI.
- Mark-as-Owned re-enrichment now runs synchronously inside the PATCH
  handler instead of as a fire-and-forget background task, so the UI
  refetch sees the new AV:L edges on the first hop.
- `Vulnerability` nodes record every detection source. `has_exploit` is
  augmented by `ExploitIndex` lookups, not only by the original
  exploit_rules match.

### Fixed

- `cve_enricher`: stale `cached` reference in the no-AV:L info log
  (ruff F821 from the alt-CPE merge refactor).
- `cve_enricher`: alt-CPE cache results are now merged in
  Mark-as-Owned re-enrichment, so single-version-anchored AV:L LPEs
  (e.g. `sock_sendpage` CVE-2009-2692 against `linux_kernel:2.6.9`)
  actually surface on ownership change.
- `cve_enricher`: tolerate `IncompleteRead` on multi-megabyte NVD
  responses; the boil pipeline retries instead of dying on transient
  network errors.
- `cauldron boil`: exploit_db tag lookup now works for multi-source
  vulns; previously only the first source's tags were resolved.
- UI: `HostDetail` refetches on external mutations (FP toggle,
  ownership change), so per-port FP state reflects the latest server
  truth without a manual reload.
- UI: Mark-as-Owned hook awaits the refetch + caches
  `verify_connection`, eliminating the brief stale-state window after
  ownership change.
- Tests: CI regressions from the strict-eval + accuracy-gate changes
  are pinned.

### Sanity-tested

- Evaluated against the E0 sanity cohort of seven training VMs (Blue,
  DC-1, Kenobi, Kioptrix L1 + L2, Metasploitable 2, Wreath). Twin-row
  schema (free-mode and key-mode per VM) with manual TP / FP / FN /
  n_additional_valid classification.
- Free-mode aggregates: recall 0.93, precision 0.28, f1 0.40.
- Key-mode aggregates: recall 0.93, precision 0.60, f1 0.66.
- Zero recall regressions across 180 AI-Phase-3 dismisses in the
  cohort — AI never removed a real TP.

## [0.1.1] — 2026-05-12

Quality patches across the CVE pipeline, report output, graph topology, and
the UI. No schema or CLI-flag changes; safe to upgrade in place.

### Added

- Multi-CPE candidates via the NVD CPE Dictionary, so a single service can
  surface CVEs from every product alias the dictionary lists for it.
- Path-scoped exploit URL detection, narrowing exploit-availability flags to
  references that actually point at proof-of-concept code.
- Traceroute-based topology with pivot auto-own and a per-source edge
  palette in the graph view.
- Per-host services inventory in the engagement report.
- Community standards: `SECURITY.md` (GitHub Private Vulnerability Reporting
  flow), `CODE_OF_CONDUCT.md`, issue templates (bug / feature / question),
  and a pull-request template.

### Changed

- CVE enrichment now extracts `Name-Version` tokens from banners and retries
  matches with a major-only version when the full version returns nothing.
- Versionless nmap-emitted CPEs are merged with `service.version` before
  hitting NVD, so banner-derived versions are not silently dropped.
- Versionless applicability is tighter: range-bounded CVEs (those with
  explicit `versionStartIncluding` / `versionEndExcluding` bounds) are
  dropped when the service version is unknown, instead of pinning to a
  random in-range version.
- Per-edge `version_unconfirmed` flag on sub-product CVE matches, so the UI
  can mark inferred matches without poisoning the overall vuln verdict.

### Fixed

- AI triage no longer fails silently on large batches; parse failures are
  surfaced as pipeline errors instead of being swallowed.
- Orphan `Vulnerability` nodes are prevented at the source (MERGE moved
  inside the service-match Cypher) and a defensive sweep removes any that
  pre-existed in the graph.
- `cauldron paths` dedupes multi-port CVEs in CLI output: one row per CVE,
  with the affected port set collected on the host locator.
- UI: `version_unconfirmed` is OR-merged across multi-port CVE instances so
  the flag does not flicker between refreshes.
- Browser tab title is trimmed; node-drag stays stable on tiny graphs (no
  more "two-node orbit" artefact).

## [0.1.0] — 2026-04-28

Initial public release.

### Added

#### Ingestion
- Nmap XML parser with full host metadata (OS, ports, scripts, traceroute).
- Masscan parser (both XML and JSON formats).
- Neo4j-backed graph ingestion with deterministic MERGE — re-importing the
  same scan updates existing nodes instead of duplicating them.
- Multi-perspective scan tracking: every import records the scan source so
  the graph can grow as you pivot through the engagement.
- Scan diff: hosts and services are tagged `NEW`, `GONE`, or `CHANGED`
  between scans; stale auto-vulns are dropped when product or version
  changes on re-import.

#### Analysis
- Rule-based host role classifier (Domain Controller, web server, database,
  printer, hypervisor, SIEM, CI/CD, VPN gateway, backup, network equipment,
  workstation, …).
- CVE enrichment via NVD API with local cache, CPE-based matching, version
  range checks, and pagination.
- Score preference chain: CVSS v4.0 → v3.1 → v3.0 → v2.
- EPSS exploit-likelihood score from FIRST.org.
- CISA KEV (Known Exploited Vulnerabilities) flag end-to-end.
- Local exploit-rules database (~70 curated rules) with confidence levels
  and one-click ready-to-copy commands per finding.
- Default-credentials database keyed by service.
- Attack path discovery and scoring engine — direct paths from any source
  to any target, ranked by exploitability.
- Pivot path detection for hosts only reachable through other compromised
  hosts.
- Network topology from traceroute and segment data.

#### AI (Anthropic Claude)
- Contextual vulnerability triage: full host service inventory passed to
  the model so it can dismiss false positives that a versionless CPE match
  would otherwise flag.
- AI-driven CVE verification: hallucinated CVSS / descriptions are caught
  by cross-checking against the NVD API.
- Attack-chain reasoning over the graph.
- Bulk false-positive workflow: the operator (or the AI) can mark a vuln
  FP across every host that exposes the same product + port.
- KEV exception: CVEs in the CISA catalog are never auto-dismissed.
- Pipeline parallelized via `ThreadPoolExecutor` — phases that don't
  depend on each other run concurrently within Anthropic Tier-1 rate
  limits.
- Authentication errors short-circuit the whole pipeline instead of
  burning a retry on every phase.
- Anonymization layer: IPs and hostnames are replaced with stable aliases
  before being sent to the model so client data stays on-prem.

#### Engagement workflow
- Owned / target / target-blocked host markers, with persistence.
- Per-host and per-service free-text notes.
- `cauldron collect` — BloodHound-style target lists filterable by KEV,
  exploit availability, owned, target, target-blocked.
- `cauldron pour` — full-detail report export in Markdown, JSON, and HTML.

#### REST API + Web UI
- FastAPI backend with CORS pinned to local dev origins.
- React 19 + TypeScript frontend with Sigma.js / WebGL graph rendering,
  Tailwind, drag-resizable sidebar, search, expandable host detail,
  unified false-positive modal with scope choice, segmented status picker.
- Brand pack: pixel-art cauldron logo, favicons (16/32/48/64/192/SVG/ICO),
  Apple touch icon, social preview, Open Graph, Twitter card, animated
  splash for graph loading.

#### Tooling
- `cauldron` CLI: `brew`, `boil`, `taste`, `paths`, `condiments`, `collect`,
  `serve`, `pour`, `reset`.
- `docker-compose.yml` provisions Neo4j 5 community with APOC.
- GitHub Actions CI matrix on Python 3.11 + 3.12 (backend) and Node 20
  (frontend) — `ruff check`, full pytest, `tsc --noEmit`, `npm run build`.

### Security

- API binds to loopback by default. Operator must opt in to `0.0.0.0` and
  is warned that the API ships without authentication.
- `.env` is gitignored; only `.env.example` is tracked.
- AI prompts are anonymized so client IPs / hostnames never reach the
  Anthropic API.

[Unreleased]: https://github.com/kodych/cauldron/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/kodych/cauldron/releases/tag/v0.1.2
[0.1.1]: https://github.com/kodych/cauldron/releases/tag/v0.1.1
[0.1.0]: https://github.com/kodych/cauldron/releases/tag/v0.1.0
