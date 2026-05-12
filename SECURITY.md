# Security Policy

## Reporting a vulnerability

If you find a security issue in Cauldron itself — code execution,
auth bypass on `cauldron serve`, injection into Cypher queries,
sensitive-data leak from imports — please report it privately via
**[GitHub's Private Vulnerability Reporting][pvr]**:

```
Repo → Security → Report a vulnerability
```

Direct link: <https://github.com/kodych/cauldron/security/advisories/new>

[pvr]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

Please include:

- a brief description of the issue and its impact,
- the Cauldron version (`cauldron --version` or commit hash),
- minimal steps to reproduce (a redacted scan file is fine — see
  *"What to redact"* below),
- whether you'd like credit in the advisory once it's published.

I read security reports within a few days. You'll get an
acknowledgement on the advisory thread; subsequent updates and the
fix timeline live there too.

### What's in scope

- Anything in this repo: `cauldron/`, `frontend/`, the Docker image
  published to `ghcr.io/kodych/cauldron`, the GitHub Action workflows.
- Default-configuration weaknesses (e.g. a setting whose stated
  default is "secure" but actually isn't).
- Sample-data shipped under `data/samples/` — synthetic by design,
  but if anything there is in fact identifying or sensitive, that's
  a bug.

### What's out of scope

- Vulnerabilities in software Cauldron *scans*, not in Cauldron
  itself — those are the CVEs Cauldron is built to surface, please
  report them to the upstream product or via the relevant national
  CERT.
- Findings inside an engagement graph the operator imported — that's
  the tool doing its job.
- Best-practice deviations with no exploitation path (e.g. "no
  rate-limiting on the API"). If you can show a way to use it
  against the operator, that becomes in-scope.

## What to redact before sharing reproducers

Cauldron is used on real pentest engagements; reproducer files can
accidentally carry client-identifying data. Please remove or
synthesize before attaching:

- Client/company names, internal domains, hostnames (FQDNs).
- Real IP addresses (replace with RFC 5737 docs ranges:
  `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- Certificate Subject CNs, banner strings with company names,
  AD domain names.
- Any extracted credentials, even hashed ones.

A trimmed scan file with one anonymous host that triggers the issue
is plenty.

## Why PVR-only

GitHub's Private Vulnerability Reporting gives every report a
durable thread, a CVE-ID workflow, draft-advisory tooling, and
notifications without exposing an inbox to spam or being missed in
a busy mail folder. Email channels are intentionally not offered.

## Past advisories

None yet. When advisories are published they appear under
<https://github.com/kodych/cauldron/security/advisories>.
