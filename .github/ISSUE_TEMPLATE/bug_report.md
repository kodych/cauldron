---
name: Bug report
about: Something Cauldron does (or fails to do) that doesn't match what you expected
title: "[bug] "
labels: bug
---

<!--
Thanks for taking the time to file this. Please don't report security
vulnerabilities here — use GitHub's Private Vulnerability Reporting
instead (Repo → Security → Report a vulnerability). See SECURITY.md.
-->

## What happened

Describe in one or two sentences what you saw.

## What you expected

What Cauldron should have done in the same situation.

## Steps to reproduce

1.
2.
3.

<!--
A minimal reproducer beats a long story. If the issue is about
ingesting / enriching a specific scan, attach a trimmed XML that
still triggers the problem. Strip client-identifying data first —
real IPs, hostnames, certificate CNs, banner strings carrying
company names. RFC 5737 ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) are good replacements for the IPs.
-->

## Environment

- Cauldron version: <!-- ``cauldron --version`` or commit hash -->
- Install method: <!-- pip, Docker image, source checkout -->
- Python version: <!-- ``python --version`` -->
- Neo4j version: <!-- 5.x community / enterprise -->
- OS: <!-- e.g. Ubuntu 22.04, Windows 11, macOS 14 -->
- Browser (if the issue is in the UI): <!-- Chrome 130, Firefox ESR, etc. -->

## Relevant logs / output

<details>
<summary>Console / API / browser-console output</summary>

```
paste here, remove any client-identifying data
```

</details>

## Additional context

Anything else that might help — screenshots, related issues, your
working theory, etc.
