# 🜄 Cauldron

**Network Attack Path Discovery**

> Throw your scans in. Get attack paths out.

```  
              ) (
           ) (   ) (
          ( o  O  o )
         .~~~~~~~~~~~.
        /    °    °   \
       |   CAULDRON    |       Cauldron 🜄
       |   ~~~ 🜄 ~~~   |       Network Attack Path Discovery
        \    °    °   /        v0.1.0
         .___________.
           |||||||||
         ^^^^^^^^^^^^
         )  )  )  )  )
        (__(__(__(__(__

```

Cauldron is a **BloodHound for the network layer** — it builds attack graphs from Nmap/Masscan scan results, enriches them with AI-powered analysis (CVE lookup, host classification, attack chain reasoning), and visualizes attack paths through an interactive web UI.

## The Problem

Every pentester on every engagement does the same thing manually:
- Stares at thousands of lines of Nmap XML output
- Mentally classifies hosts by their open port patterns
- Manually searches for CVEs matching each service version
- Keeps attack paths in their head, missing non-obvious chains
- Spends **days** on analysis that could take **minutes**

## The Solution

Cauldron automates the analytical work. Import your scans, and the system:

1. **Parses** Nmap/Masscan output into a graph database (Neo4j)
2. **Classifies** hosts by role (Domain Controller, web server, database, printer...)
3. **Enriches** with CVE data and known exploit availability
4. **Discovers** attack paths using graph algorithms + AI reasoning
5. **Visualizes** everything in an interactive graph UI

Each new scan from a different network position **enriches the graph further** — like throwing more ingredients into a cauldron.

## Quick Start

```bash
# Start Neo4j
docker compose up -d

# Install Cauldron
pip install -e ".[all]"

# Import your first scan
cauldron brew path/to/scan.xml

# See what's brewing
cauldron taste
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `cauldron brew <file>` | Import Nmap XML scan |
| `cauldron brew --source "pivot-box" <file>` | Import with scan source |
| `cauldron boil` | Run AI analysis |
| `cauldron taste` | Show graph statistics |
| `cauldron paths` | Show top attack paths |
| `cauldron pour --format pdf` | Export report |
| `cauldron reset` | Clear all data |

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Nmap XML   │────▶│    Parser    │────▶│   Neo4j     │
│  Masscan    │     │              │     │   Graph DB  │
└─────────────┘     └──────────────┘     └──────┬──────┘
                                                │
                    ┌──────────────┐             │
                    │   Claude AI  │◀────────────┤
                    │  - Classify  │             │
                    │  - CVE Match │─────────────┤
                    │  - Paths     │             │
                    └──────────────┘             │
                                                │
                    ┌──────────────┐             │
                    │   Web UI     │◀────────────┘
                    │  React +     │
                    │  Sigma.js    │
                    └──────────────┘
```

## Requirements

- Python 3.11+
- Docker & Docker Compose (for Neo4j)
- Anthropic API key (for AI features)

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check .
```

## Status

🚧 **Under active development** — this is a master's thesis project.

- [x] Nmap XML parser
- [x] Neo4j graph ingestion
- [x] CLI interface
- [ ] Host role classification
- [ ] CVE enrichment
- [ ] AI attack path analysis
- [ ] REST API
- [ ] Web UI with graph visualization
- [ ] Report generation

## License

MIT
