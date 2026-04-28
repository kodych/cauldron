# Contributing

Thanks for taking the time. Cauldron is small enough that the bar for a
useful PR is low — a real-world bug report with an Nmap XML reproducer
is gold.

## Setup

You'll need:

- Python 3.11 or newer
- Node 20 or newer (for the frontend)
- Docker (for the Neo4j you'll develop against)
- An [Anthropic API key](https://console.anthropic.com/) if you're
  touching anything in `cauldron/ai/`

```bash
git clone https://github.com/kodych/cauldron.git
cd cauldron
cp .env.example .env
$EDITOR .env

docker compose up -d           # Neo4j on :7474 (browser) / :7687 (bolt)

pip install -e ".[all]"        # backend with dev + api + ai extras
cd frontend && npm ci          # frontend deps
```

## Running

```bash
# Backend API
cauldron serve --reload         # http://127.0.0.1:8000, hot reload

# Frontend dev server (separate terminal)
cd frontend && npm run dev      # http://localhost:3000

# A useful sample brew
cauldron brew data/samples/corporate_network.xml
cauldron boil --nvd --ai
```

## Tests

```bash
pytest tests/                   # full suite
pytest tests/ -k "not cve"      # skip the slow CVE enrichment tests
pytest tests/test_nmap_parser.py -v
```

466 of the ~660 tests are pure unit tests that pass without Neo4j. The
DB-backed ones (`test_ingestion`, `test_api`, `test_analyzer`,
`test_collect`, `test_attack_paths`, `test_topology`) skip via a
`neo4j_available` fixture when the bolt port is unreachable. CI runs
without Neo4j and gates on the unit tests; for full coverage run them
locally against your dev DB.

The DB-backed tests use a `clean_db` fixture that wipes the database
before and after — **don't run them against a graph you care about.**
If you've loaded an engagement, run a subset that excludes them.

## Lint and format

```bash
ruff check cauldron/            # backend lint
ruff format cauldron/           # backend formatter (in-place)

cd frontend
npx tsc --noEmit                # type check
npm run lint                    # eslint
npm run build                   # production build smoke
```

CI runs `ruff check`, `pytest`, `tsc --noEmit`, and `npm run build` on
ubuntu-latest with Python 3.11 / 3.12 + Node 20. PRs are gated on all
four going green.

## Code style

- **English only.** Code, comments, docstrings, commit messages. The
  developer may chat in Ukrainian, but the code stays English.
- **Don't add features beyond what the task requires.** No premature
  abstraction; three similar lines beats a clever helper.
- **Comments only when the WHY isn't obvious.** Don't restate what the
  code says.
- **No AI co-author lines** in commit messages.
- **No client data** in tests, fixtures, or commits. Sample scans go
  in `data/samples/`; private engagement data stays out of the repo.

## Branching and commits

- `main` is the deploy branch. PRs land via squash-merge.
- Commit messages: lowercase scope prefix, terse imperative description.
  Examples in `git log` — match that style.
- One logical change per commit. If a refactor and a feature land
  together, split them.

## Reporting issues

For functional bugs, the most useful issue includes:

1. The CLI invocation or API call that misbehaved.
2. A minimal reproducer scan file (sanitized — no client IPs).
3. The actual vs. expected output.
4. The stack trace or error message verbatim.

Security issues should not go into public GitHub issues — see the
project's `SECURITY.md` (post-v0.1.0) for the disclosure address.

## Project structure

- [docs/architecture.md](architecture.md) — module layout, schema, design principles
- [docs/cli.md](cli.md) — CLI surface
- [docs/api.md](api.md) — REST API surface
- [docs/ai-triage.md](ai-triage.md) — what AI is used for and what it sees
