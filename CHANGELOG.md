# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/kodych/cauldron/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kodych/cauldron/releases/tag/v0.1.0
