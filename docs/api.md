# REST API

`cauldron serve` starts a FastAPI server on `http://127.0.0.1:8000` by
default. Interactive Swagger UI is at `/docs`, OpenAPI JSON at
`/openapi.json`. CORS is pinned to local dev origins; override with
`CAULDRON_CORS_ORIGINS=host1,host2`.

The API has **no authentication**. Default bind is loopback for that
reason. If you need to expose it across hosts, put it behind a reverse
proxy with auth and a TLS terminator.

## Endpoint surface

### Read-only

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Root health-check + links to `/docs` |
| GET | `/api/v1/stats` | Counts: hosts, services, segments, vulns, scan sources, role distribution |
| GET | `/api/v1/hosts` | Host list with filters: `role`, `is_owned`, `is_target`, `q` (search), `limit`, `offset` |
| GET | `/api/v1/hosts/{ip}` | Full host detail incl. services, vulns (with KEV/EPSS), notes, OS family |
| GET | `/api/v1/attack-paths` | Top-N attack paths, optionally filtered by `target`, `role`, `confidence` |
| GET | `/api/v1/collect` | Target list extraction (mirrors `cauldron collect`) |
| GET | `/api/v1/collect/filters` | List of built-in collect filters |
| GET | `/api/v1/graph` | Sigma-ready graph payload (nodes + edges); `limit` caps host count |
| GET | `/api/v1/topology` | Per-segment host counts |
| GET | `/api/v1/vulns` | Distinct vulnerabilities with affected-host counts |
| GET | `/api/v1/hosts/{ip}/services/{port}/default-creds` | Default credentials known for that service |
| GET | `/api/v1/hosts/{ip}/services/{port}/vulns/{vuln_id}/commands` | Ready-to-copy exploit commands |
| GET | `/api/v1/report?fmt={md,json,html}` | Render report inline |

### Mutations

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/import` | Upload an Nmap XML or Masscan file (multipart). Triggers parse + ingest. |
| POST | `/api/v1/analyze` | Synchronous boil. Query: `nvd=true`, `ai=true`. Returns once finished. |
| POST | `/api/v1/analyze/start` | Asynchronous boil — returns a `job_id`. |
| GET | `/api/v1/analyze/status/{job_id}` | Poll progress of an async boil. |
| PATCH | `/api/v1/hosts/{ip}/owned` | Toggle owned marker. |
| PATCH | `/api/v1/hosts/{ip}/target` | Toggle target marker. |
| PATCH | `/api/v1/hosts/{ip}/target-blocked` | Toggle target-blocked marker. |
| PATCH | `/api/v1/hosts/{ip}/notes` | Update pentester notes on a host. |
| PATCH | `/api/v1/hosts/{ip}/vulns/{vuln_id}/status` | Mark a vuln on **this host** as `pending` / `mitigated` / `exploited` / `false_positive` (with optional `reason`). |
| PATCH | `/api/v1/vulns/{vuln_id}/bulk-status` | Apply a verdict to **every** active edge of this CVE across the graph. |
| PATCH | `/api/v1/hosts/{ip}/services/{port}/bruteforceable` | Toggle bruteforceable flag on a service. |
| PATCH | `/api/v1/hosts/{ip}/services/{port}/notes` | Update notes on a service. |
| DELETE | `/api/v1/reset` | Wipe the entire graph. |

### Schemas

Request/response bodies are Pydantic models in
[`cauldron/api/server.py`](../cauldron/api/server.py). Notable ones:

- `HostOut` — full host with `os_family`, badges (`is_new`, `is_stale`,
  `has_changes`), services, and per-host vulns.
- `VulnListItem` — global vuln list row with `affected_hosts`,
  `version_unconfirmed`, KEV / EPSS / has_exploit flags.
- `VulnStatusUpdate` — `{ status, reason? }`. `reason` is recorded only
  when status is `false_positive`; clearing the status clears the reason.
- `VulnBulkStatusUpdate` — same as `VulnStatusUpdate` but applied
  graph-wide.
- `PathOut` — attack path with `nodes`, `edges`, `confidence`, `score`,
  and the deciding vuln per hop.

## Examples

```bash
# Total counts
curl -s localhost:8000/api/v1/stats | jq .

# Domain controllers
curl -s 'localhost:8000/api/v1/hosts?role=domain_controller' | jq '.hosts[].ip'

# Mark host owned
curl -s -X PATCH localhost:8000/api/v1/hosts/10.0.1.10/owned \
     -H 'Content-Type: application/json' \
     -d '{"value": true}'

# Bulk-FP a CVE across the graph
curl -s -X PATCH localhost:8000/api/v1/vulns/CVE-2024-1234/bulk-status \
     -H 'Content-Type: application/json' \
     -d '{"status": "false_positive", "reason": "service is firewalled, not actually exposed"}'

# Trigger NVD + AI analysis async, then poll
JOB=$(curl -s -X POST 'localhost:8000/api/v1/analyze/start?nvd=true&ai=true' | jq -r .job_id)
watch -n 2 "curl -s localhost:8000/api/v1/analyze/status/$JOB | jq ."
```

## Why no auth?

Cauldron is meant to live on the operator's pentest workstation,
typically airgapped from the engagement network on a separate VLAN.
Adding an auth layer for that single-user model would be friction
without value. If your situation differs, run it behind a reverse
proxy with the auth scheme that fits your environment.

The `0.0.0.0` warning in `cauldron serve` exists for exactly this
reason: the moment you bind beyond loopback, anyone on that network
segment can `DELETE /api/v1/reset`.
