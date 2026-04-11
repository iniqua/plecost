# Plecost — Context for Claude

## Setup
```bash
pip install -e ".[dev]"           # install with dev dependencies
pip install -e ".[dev,postgres]"  # include asyncpg for PostgreSQL
```

## Development Commands
```bash
python3 -m pytest tests/unit tests/integration tests/contract tests/property -v
python3 -m ruff check plecost/ --fix
python3 -m mypy plecost/ --ignore-missing-imports
```

## Architecture
- `plecost/cli.py` — Typer entrypoint; commands: `scan`, `explain`, `update-db`, `build-db`, `sync-db`, `modules`
- `plecost/scanner.py` — `Scanner.run()` and `Scanner.run_many()` (public API for use as a library)
- `plecost/engine/` — `http_client.py` (httpx async), `context.py` (shared state), `scheduler.py` (async dependency graph)
- `plecost/modules/` — 15 detection modules; each extends `ScanModule` with `name`, `depends_on`, `async run()`
- `plecost/database/` — SQLAlchemy async; `updater.py` (NVD full build), `incremental.py` (delta sync), `downloader.py` (from release), `store.py` (queries)
- `plecost/reporters/` — `terminal.py` (Rich), `json_reporter.py` (JSON)

## Finding IDs
- Permanent format: `PC-{MODULE}-{NNN}` (e.g. `PC-MCFG-001`, `PC-CVE-CVE-2023-28121`)
- Associated remediation ID: `REM-{MODULE}-{NNN}`
- Full registry of 44 IDs in `plecost/cli.py` → `plecost explain <ID>`

## Library Usage (Celery/scripts)
```python
from plecost import Scanner, ScanOptions
result = await Scanner(ScanOptions(url="https://target.com")).run()
```

## Python Environment
- Always use `python3 -m pytest` (not bare `pytest`) — multiple Python versions on this system
- Pyright reports false positive import errors (`plecost.database.engine`, etc.) — modules exist, it's an environment issue, not a code bug

## Repository
- GitHub repo: `iniqua/plecost` (not `cr0hn/plecost`)
- Main branch: `master`
- CI minimum coverage: 75% (`--cov-fail-under=75`)

## CVE Database
- Local DB: `~/.plecost/db/plecost.db` (SQLite, SQLAlchemy async)
- `plecost build-db` — full build from NVD (maintainers, one-time)
- `plecost update-db` — download pre-built DB from GitHub releases (end users)
- `plecost sync-db` — incremental sync from `db_metadata.last_nvd_sync` (daily GitHub Action)
- NVD API rate limit: 6s between requests without API key; use `NVD_API_KEY` env var for higher limit
- Initial DB published at: `github.com/iniqua/plecost/releases/tag/db-base`

## Tests
- `asyncio_mode = "auto"` in pyproject.toml — do NOT add `@pytest.mark.asyncio` manually
- respx: use `respx.get(url).mock(return_value=httpx.Response(...))` — NOT `respx.pattern(...)`
- Functional tests against real WordPress: `PLECOST_FUNCTIONAL_TESTS=1 pytest tests/functional/`
- Test Docker WordPress: `docker-compose -f docker-compose.test.yml up -d` (port 8765)

## Docker
- `.dockerignore` has `*.md` + `!README.md` — do not remove the exception or the build will fail

## License
- PolyForm Noncommercial License 1.0.0 — free for non-commercial use; commercial use requires contacting cr0hn@cr0hn.com
- Do NOT change to MIT or any open source license without explicit authorization
