# AI triage

Cauldron uses Anthropic's Claude API for three things:

1. **CPE extraction** — distilling a CPE 2.3 identifier from services
   that nmap could not fully fingerprint.
2. **Ambiguous host classification** — re-running role classification
   on hosts the rule-based classifier marked unknown.
3. **Contextual vulnerability triage** — reviewing every vuln with the
   full host context and engagement state, dismissing noise.

All three live in [cauldron/ai/analyzer.py](../cauldron/ai/analyzer.py).
The whole pipeline is opt-in — `cauldron boil --ai`. No AI calls
happen during the default `boil` or any read path.

## What goes to Anthropic

| Phase | Sent | Not sent |
|---|---|---|
| 1. CPE extraction | Service banners, `servicefp` probe responses, product/version strings | IPs, hostnames |
| 2. Host classification | Anonymized aliases (`host-1`, `segment-A`), open ports, products, role hints | Real IPs, real hostnames |
| 3. Contextual triage | Anonymized host inventory (every service on the host), vuln descriptions, owned/target flags | Real IPs, real hostnames, scan source IPs |

Phase 1 sends public information about what software is running on the
network — not where, not whose. Phases 2 and 3 anonymize via a
deterministic mapping built per-run; the model never sees engagement
identifiers.

## Phase 1 — CPE extraction

For services where nmap returned a banner or `servicefp` but
`PRODUCT_CPE_MAP` didn't yield a CPE, the model is asked to produce a
CPE 2.3 tuple. Output is regex-validated (the 13-field colon-separated
shape) before we trust it; malformed strings are dropped. Validated
CPEs go through the same NVD pipeline as nmap-emitted CPEs:

- Real CPE → real CVE list, attached at `confirmed` confidence if the
  version range applies.
- Hallucinated CPE → NVD returns zero results, nothing is linked.

This is self-correcting against hallucination: only the real-CPE
results survive.

## Phase 2 — host classification

Hosts whose role is `unknown` after the rule-based classifier are
re-classified by AI. The model sees:

- Anonymized aliases (`host-1` rather than `10.0.1.10`).
- Per-host: open TCP/UDP ports, product strings, version strings, OS
  family hint, classification candidates the rule engine considered.

The result must come back as a `HostRole` enum value or it's discarded.
Confidence is recorded so the UI can show that this role came from AI.

## Phase 3 — contextual vulnerability triage

This is the highest-value phase. NVD CPE-matching is conservative — it
flags any CVE whose CPE config could plausibly apply, including
versionless wildcard configurations. That produces a lot of "this
might be vulnerable" noise.

Phase 3 sends Claude:

- The full anonymized service inventory of every affected host (so a
  CVE described as affecting "the WebInterface" can be cross-referenced
  against whether the host actually exposes a web port at all).
- The vuln descriptions and CVSS / KEV / EPSS context.
- Engagement flags (`owned`, `target`, `target_blocked`).

The model is asked to verdict each finding as **keep** or **dismiss**.
Dismissals get a reason string that ends up on the `HAS_VULN` edge as
`ai_fp_reason` and is shown in the UI.

### Hard rules baked into the prompt

- **KEV is sacred.** Anything in the CISA Known Exploited Vulnerabilities
  catalog is never auto-dismissed, regardless of context. Real
  in-the-wild exploitation outweighs context-based skepticism.
- **Confirmed product on the alt-port test.** When triaging a CVE on
  port `X` of a host that exposes only port `Y`, the model may dismiss
  only if it is confident port `Y` cannot be running the affected
  product. A confirmed product fingerprint on the same host's other
  port can override that — a CrushFTP server with both `:443` and
  `:22` exposes the WebInterface on `:443` even when `:22` was the
  port we found the vuln on.
- **Asymmetric cost.** Default to keep on uncertainty. Missing a real
  vuln during a pentest is far worse than carrying one extra finding
  the operator dismisses by hand.

## Failure modes

| Failure | Behavior |
|---|---|
| `CAULDRON_ANTHROPIC_API_KEY` missing | All three phases skip, `boil` reports "AI analysis skipped" |
| 401 (bad key) on first call | Pipeline aborts, `auth_error` recorded on the result, UI shows red banner with the env-var name |
| 429 rate limit | Logged and skipped for that batch; downstream phases still run |
| Network / 5xx | Retried with exponential backoff inside the Anthropic SDK; persistent failure cancels that batch |

The triage pass uses a `ThreadPoolExecutor` with five concurrent
requests. That stays inside the Tier-1 RPM ceiling (50/min for Sonnet)
and turns the wall-clock cost from O(N × latency) to roughly
O(N × latency / 5). On the first auth error, pending futures are
cancelled and running ones drain — no second phase ever sees the bad
key.
