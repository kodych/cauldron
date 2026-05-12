---
name: Feature request
about: Suggest a capability or improvement you'd like to see in Cauldron
title: "[feature] "
labels: enhancement
---

## The problem you're trying to solve

What's the situation today? What forces you to use a workaround or
do something manually? Concrete example beats abstract phrasing.

## The change you'd like

What should Cauldron do differently? If you can name a specific
command, UI element, API endpoint, or config flag, please do.

## Where it fits

Tick whichever applies (helps me triage):

- [ ] Parser (Nmap / Masscan XML or JSON intake)
- [ ] Graph ingestion (Neo4j MERGE writes, schema)
- [ ] CVE enrichment (NVD pipeline, CPE matching, KEV/EPSS)
- [ ] AI analysis (CPE distill, host classification, triage)
- [ ] Attack-path discovery / scoring
- [ ] Web UI (graph canvas, host detail, reports view)
- [ ] CLI commands (`cauldron <verb>`)
- [ ] API (`cauldron serve` endpoints)
- [ ] Reports (Markdown / JSON / HTML export)
- [ ] Other / not sure

## Why this matters in a real engagement

A short note on the engagement context where you'd reach for this.
Cauldron is a pentester tool — practical value during an actual
assessment is what justifies new surface area. "I'd save 30 minutes
per scan because X" is a strong signal.

## Alternatives considered

What's the current workaround? Other tools that already do this?
What's wrong with each that brings you to Cauldron's repo?

## Anything else

Mockups, links to related research, prior issues, etc.
