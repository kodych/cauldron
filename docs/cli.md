# CLI reference

The `cauldron` CLI is themed after brewing potions. The pipeline:

1. `brew` — toss a scan in
2. `boil` — apply heat (classify, enrich, find paths)
3. `taste` — peek at what's in there
4. `paths` — see the routes to compromise
5. `pour` — bottle it up as a report

Run `cauldron --help` or `cauldron <verb> --help` for the canonical
list and option set; this page documents the moving pieces.

## brew — import scans

```bash
cauldron brew <file>
cauldron brew --source <name> <file>
cauldron brew --format {auto|nmap|masscan} <file>
```

Imports an Nmap XML or Masscan (XML/JSON) scan. Format is auto-detected
from file content. The `--source` tag records the network position
the scan was run from — supply it whenever you change pivots so the
multi-perspective graph holds together.

After parsing, hosts are auto-classified by the rule-based classifier,
the graph is initialized if needed, and the scan is MERGEd in. Re-running
`brew` on the same file is idempotent: existing nodes are updated, never
duplicated; stale services / vulns get a `GONE` flag for diff display.

## boil — analysis pipeline

```bash
cauldron boil               # local-only: classify, exploit DB, paths
cauldron boil --nvd         # add NVD CVE + EPSS enrichment
cauldron boil --ai          # add Claude AI triage
cauldron boil --all         # everything
```

Phases (each runs in order):

1. **Host classification** — re-classify any hosts whose role changed.
2. **Local exploit DB** — match services against ~70 curated rules, mark
   guaranteed wins.
3. **Script confidence upgrade** — read NSE script output (e.g. `vulners`,
   `smb-vuln-*`) to upgrade `possible` findings to `confirmed`.
4. **Bruteforceable detection** — flag services Hydra/`ncrack` can chew on.
5. **CVE enrichment (NVD)** — for products with CPE matches, fetch CVEs,
   filter by version range, attach with `confirmed`/`likely` confidence.
   EPSS exploit-prediction scores are fetched in a second pass.
6. **Attack path discovery** — direct paths, pivot paths, scoring.
7. **AI** — three sub-phases (CPE distill, host classify, contextual
   triage). Aborts on Anthropic auth error.

NVD enrichment can take minutes on a large network — that's the network
round-trip, not Cauldron. The local cache makes re-runs fast.

## taste — graph statistics

```bash
cauldron taste
```

Counts of hosts / services / segments / vulnerabilities / scan sources,
host-role distribution, and a /24 subnet breakdown. Quick orientation
between scans.

## paths — attack paths

```bash
cauldron paths
cauldron paths --target 10.0.1.10
cauldron paths --role domain_controller
cauldron paths --top 20
cauldron paths --all          # include check-level (possible) paths
```

By default shows confirmed and likely paths only. `--all` includes
`possible` findings — useful if `boil` hasn't run NVD/AI yet but you
want a quick first look.

## condiments — guaranteed wins per host

```bash
cauldron condiments
```

Quick reference: each host with at least one easy / guaranteed exploit
gets one row with the most decisive finding. Designed for the moment
you sit down to start exploiting and want a punch list.

## collect — target lists

```bash
cauldron collect --filter <name>
cauldron collect --role domain_controller --output dcs.txt
cauldron collect --vuln CVE-2024-1234 --format ip-port
```

BloodHound-style extraction: pull the host list (or IP:port list) for a
specific target class, ready to pipe into Hydra, ffuf, smbclient, etc.

Built-in filters include `kev` (CISA KEV present), `exploit` (any known
exploit), `owned`, `target`, `target_blocked`. List them all with
`cauldron collect --filter list`.

False-positive-marked vulns are auto-excluded from every match.

## serve — REST API

```bash
cauldron serve                      # 127.0.0.1:8000 (loopback)
cauldron serve --host 0.0.0.0 -p 9000
cauldron serve --reload             # dev mode
```

Starts FastAPI. Default bind is loopback — exposing on the local network
lets anyone there `DELETE /api/v1/reset` because the API ships without
auth. Swagger UI at `/docs`.

The web UI (in `frontend/`) reads from this API. See the
[REST API doc](api.md) for the endpoint surface.

## pour — reports

```bash
cauldron pour --format md --output report.md
cauldron pour --format json --output report.json
cauldron pour --format html --output report.html
```

Full-detail engagement report with: graph stats, role distribution,
every vulnerability with KEV/EPSS/source badges, attack paths, and host
notes. HTML is self-contained (CSS inlined) and renders cleanly when
mailed as an attachment.

## reset — wipe the cauldron

```bash
cauldron reset                      # interactive confirmation
cauldron reset --yes                # skip confirmation
```

Deletes every node and relationship. Keep your scan files — re-running
`brew` rebuilds the graph. Engagement-state markers (owned, target,
notes) are cleared along with the rest.
