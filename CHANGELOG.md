## 2026-04-12 — incremental updater generates daily JSON patch file

### Changed
- `plecost/database/updater.py`: `process_nvd_batch()` now accepts an optional `collected: list[dict] | None = None` parameter; when provided, each processed vulnerability record (matching the daily-patch JSON schema) is appended to the list in addition to being persisted in the DB
- `plecost/database/incremental.py`: `IncrementalUpdater.__init__()` now accepts `output_patch: str | None = None`; when set, `run()` writes a daily-patch JSON file (`date`, `source`, `upsert`, `delete`) to the given path after completing the sync

---

## 2026-04-12 — JSON patch system: RejectedCve model, patch_applier module, store filtering

### Added
- `plecost/database/models.py`: new `RejectedCve` model (`rejected_cves` table) — soft-delete table for CVEs removed/disputed from NVD; never physically deletes rows
- `plecost/database/patch_applier.py`: new module implementing JSON patch application — `apply_patch()` validates then applies upserts and soft-deletes in a single transaction; `get_last_patch_date()` returns last patch timestamp; portable across SQLite and PostgreSQL via SQLAlchemy select/setattr pattern
- `plecost/database/store.py`: `CVEStore.find()` now filters out any CVE IDs present in `rejected_cves` before returning vulnerability records

---

## 2026-04-12 — Overhaul downloader.py for JSON patch system with SHA256 verification

### Changed
- `plecost/database/downloader.py`: replaced single-SQLite-download approach with a new JSON patch system:
  - New constants: `PATCHES_RELEASE_TAG`, `BASE_URL`, `INDEX_URL`, `INDEX_CHECKSUM_URL`, `FULL_JSON_URL`, `FULL_CHECKSUM_URL`
  - New async functions: `fetch_remote_index_checksum()`, `fetch_index()`, `download_full_json()`, `download_patch()`
  - Internal helpers: `_sha256_file()`, `_sha256_bytes()`, `_fetch_bytes()`, `_stream_to_file()`, `_make_headers()`
  - All downloads include SHA256 verification against checksums fetched from GitHub releases
  - `download_latest_db()` kept as deprecated legacy function for backwards compatibility

## 2026-04-12 — Audit fixes: severity bug, silent failures, themes display, 43 new tests

### Fixed
- `plecost/modules/ssl_tls.py`: PC-SSL-002 severity corrected from `MEDIUM` to `HIGH` (aligned with CLI registry)
- `plecost/modules/ssl_tls.py`: SSL error detection now catches `httpx.TransportError` (covers all transport-layer SSL/TLS failures) and checks for "tls" in addition to "ssl" and "certificate"
- `plecost/scanner.py`: replaced silent `except Exception: pass` on CVE DB load with a stderr warning directing user to run `plecost update-db`
- `plecost/scanner.py`: translated Spanish comment to English
- `plecost/reporters/terminal.py`: detected themes are now displayed in a Rich table (was missing, themes were detected but never shown)
- `plecost/database/store.py`: `CVEStore.from_url()` raises `FileNotFoundError` with actionable message when SQLite DB file doesn't exist

### Added
- `tests/unit/test_module_ssl_tls.py`: 6 tests for SSL/TLS module
- `tests/unit/test_module_debug_exposure.py`: 8 tests for debug exposure module
- `tests/unit/test_module_content_analysis.py`: 9 tests for content analysis module
- `tests/unit/test_database_engine.py`: 3 tests for database engine factory
- `tests/unit/test_database_downloader.py`: 3 tests for GitHub release downloader
- `tests/unit/test_database_updater.py`: 10 tests for NVD batch processor and Jaro-Winkler matching
- `tests/unit/test_database_incremental.py`: 3 tests for incremental NVD sync
- Total test count: 65 → 108 (+43 new tests)

### Removed
- `plecost/database/updater.py`: dead `DatabaseUpdater._upsert_vuln()` method

---

## 2026-04-11 — CVE DB guard, dead code removal, CLI envvar support

### Fixed
- `plecost/database/store.py`: `CVEStore.from_url()` now raises `FileNotFoundError` with a clear message if the SQLite file does not exist, instead of failing silently downstream
- `plecost/database/updater.py`: removed dead `DatabaseUpdater._upsert_vuln()` method that only delegated to `_upsert_vuln_free()`

### Added
- `plecost/cli.py`: added `envvar` support to key CLI options:
  - `--db-url` → `PLECOST_DB_URL` (in `update-db`, `build-db`, `sync-db` commands)
  - `--timeout` → `PLECOST_TIMEOUT` (in `scan` command)
  - `--output` → `PLECOST_OUTPUT` (in `scan` command)

---

## 2026-04-10 — i18n, mypy fixes and git hooks

### Changed
- Translated all Spanish text to English across the entire codebase (comments, docstrings, CLI messages, error messages, logs, documentation, CHANGELOG)
- Files translated: `plecost/cli.py`, `plecost/database/downloader.py`, `plecost/database/incremental.py`, `plecost/database/updater.py`, `plecost/database/models.py`, `plecost/database/store.py`, `tests/functional/test_scanner_functional.py`, `CHANGELOG.md`, `ANALYSIS.md`, `docs/cve-database-architecture-decision.md`, `docs/superpowers/specs/2026-04-10-plecost-design.md`

### Fixed
- `plecost/database/engine.py`: fixed `dict` type without arguments → `dict[str, Any]`
- `plecost/database/updater.py`: replaced all deprecated `datetime.utcnow()` with `datetime.now(timezone.utc)`, typed `params` as `dict[str, str | int]`, typed `vulns` as `list[object]`, removed redundant `from datetime import timezone` in method body
- `plecost/database/incremental.py`: added explicit `str()` cast on `row.value` to fix mypy `Returning Any` error

### Added
- `.githooks/pre-push`: pre-push hook running ruff, mypy and pytest before each push
- `.githooks/README.md`: instructions to activate the hooks with `git config core.hooksPath .githooks`

---

## [4.2.0] - 2026-04-10

### Changed
- CVE database distribution system redesigned:
  - `plecost update-db`: downloads pre-built DB from GitHub releases (fast, for end users)
  - `plecost build-db`: builds DB from scratch from NVD (for maintainers, first run)
  - `plecost sync-db`: incremental update (only new/modified CVEs since last sync)
  - GitHub Action uses incremental sync: downloads DB from previous release, applies NVD delta, publishes new release
  - `db_metadata` table in SQLite stores `last_nvd_sync` for incremental updates
  - Support for `NVD_API_KEY` environment variable (higher rate limit: 0.6s vs 6s between requests)
  - `DatabaseUpdater` accepts `years_back` and `nvd_api_key` in constructor
  - `process_nvd_batch` refactored as a free reusable function from `updater.py` and `incremental.py`
  - New module `plecost/database/downloader.py`: streaming download from GitHub releases
  - New module `plecost/database/incremental.py`: `IncrementalUpdater` for NVD delta sync
  - `.github/workflows/update-cve-db.yml` updated with `contents: write` permissions and incremental flow

---

## [4.1.0] - 2026-04-10

### Changed
- Complete redesign of the CVE database system
  - SQLAlchemy 2.0 async (aiosqlite for SQLite, asyncpg for PostgreSQL)
  - New `NormalizedVuln` model with exact version ranges (versionStartIncluding/Excluding, versionEndIncluding/Excluding)
  - Real CPE parsing from NVD with target_sw=wordpress filter
  - Inline Jaro-Winkler fuzzy matching (no extra dependency) for slug→CPE product mapping
  - Downloads the last 5 years of CVEs from NVD with pagination
  - `DatabaseUpdater` accepts `db_url` instead of `db_path` (SQLite and PostgreSQL support)
  - `CVEStore` fully async with `from_url()` factory method
  - `scanner.py`: wordlist loading and store moved to async `run()`
  - `cves.py`: `store.find()` is now called with `await`
  - `cli.py update-db`: new flag `--db-url` replacing `--db-path`
  - Removed `aiofiles` dependency, added `sqlalchemy[asyncio]>=2.0` and `aiosqlite>=0.19`
  - Unit tests updated for the new async SQLAlchemy store

---

## 2026-04-10 — Technical debate and architectural decision for the CVE database

### Added
- `docs/cve-database-architecture-decision.md`: Decision document resulting from a structured technical debate among 5 approaches (CPE Purist, WP-Specific APIs, Pre-built Dictionary, Layered Hybrid, NLP/Similarity) to solve the slug→CVE mapping problem in Plecost v4.0
  - Winning approach is Delta (Layered Hybrid): NVD for WordPress Core, specialized WP APIs (Patchstack/Wordfence) for plugins/themes, curated seed dictionary for top 500 plugins
  - Concrete technical proposal: SQLAlchemy 2.0 async models, SQLite/PostgreSQL engine factory, layered updater flow, O(1) lookup at scan time
  - Effort estimate: ~10.5 days / 1 sprint

---

## [4.0.1] - 2026-04-11

### Changed
- License changed from FSL-1.1-MIT to PolyForm Noncommercial License 1.0.0
  - Standard license drafted by lawyers, no automatic conversion to open source
  - Commercial use requires a paid license (contact: cr0hn@cr0hn.com)
  - Link: https://polyformproject.org/licenses/noncommercial/1.0.0/
- README completely rewritten in English
- Improved professional appearance: Nuclei/WPScan style, clean tables, demo output, architecture, benchmarks

---

## 2026-04-10 — Functional tests against real WordPress with Docker

### Added
- `docker-compose.test.yml`: updated with improved healthcheck (mysqladmin with credentials, curl wp-login.php) and correct environment variables
- `tests/functional/test_scanner_functional.py`: 8 functional tests verifying WordPress detection, version, findings, summary, readme.html, REST API and JSON reporter
- `tests/conftest.py`: registers the `functional` marker for pytest
- `scripts/run_functional_tests.sh`: CI helper script that starts Docker, waits for WordPress and runs the tests
- `pyproject.toml`: added `markers` in `[tool.pytest.ini_options]` with the `functional` marker

---

## 2026-04-10 — Import fixes and test quality

### Fixed
- Removed 11 unused imports in test files (`pytest`, `json`, `asyncio`, `VulnerabilityRecord`, `Plugin`, `Theme`, `User`) detected by ruff
- All 53 unit tests pass correctly
- mypy and ruff clean in `plecost/` and `tests/`

---

## [4.0.0] - 2026-04-10

### Changed
- License changed from MIT to FSL-1.1-MIT (Functional Source License)
  - Free use for research, internal audits and open source projects
  - Prohibited to offer as SaaS or paid service
  - Automatically converts to MIT after 4 years

---

## 2026-04-10 — CI/CD workflows

### Added
- `.github/workflows/docker-publish.yml`: publica imagen multi-arch (amd64/arm64) en `ghcr.io/iniqua/plecost` al hacer push a master (tag `latest`) o push de tags `v*.*.*`
- `.github/workflows/pypi-publish.yml`: publica paquete en PyPI con trusted publishing (OIDC) al hacer push de tags `v*.*.*`
- `Dockerfile`: added standard OCI labels (`source`, `description`, `licenses`) and `uvloop` installation

---

## 2026-04-10 — v4.0.0

Complete rewrite from scratch. Plecost v4.0.0 is a fully async WordPress security scanner built with httpx + asyncio.

### New Features
- 15 detection modules: fingerprint, waf, plugins, themes, users, xmlrpc, rest_api, misconfigs, directory_listing, http_headers, ssl_tls, debug_exposure, content_analysis, auth, cves
- Async task scheduler with explicit dependency graph (maximum parallelism)
- Full Python library API: `from plecost import Scanner, ScanOptions`
- Stable finding IDs (PC-XXX-NNN) for dashboard integration
- Daily CVE database updates via GitHub Actions
- Rich terminal reporter with colored output and tables
- JSON reporter for automation pipelines
- Typer CLI with commands: scan, update-db, modules list, explain
- Docker support: `ghcr.io/cr0hn/plecost`
- Celery-compatible async scanner
- TDD: 62 tests across unit/integration/contract/property suites

### Architecture
- Python 3.11+, httpx, typer, rich, packaging, SQLite
- `pyproject.toml` with hatchling build backend
- Optional uvloop for better async performance

---

Version 1.1.2
=============

Improvements and fixes
----------------------

- Fixed issue: #18 (https://github.com/iniqua/plecost/issues/18)

New features
------------

- Added option to set custom hostname. Issue #20 (https://github.com/iniqua/plecost/issues/20)


Version 1.1.1
=============

Internal modifications
----------------------

- Improved CVE database. Now it implement full-text queries to locate plugins CVEs.
- Improved internal system that does the scan -> increased the performance
- Minor PEP8 improvements.
- Changed BeatufilSoup 4 HTML parser in favor of Lxml -> more fault tolerant & performance

Improvements and fixes
----------------------

- Fixed the plugin update system to the new Wordpress scaffolding.
- Fixed CVE update system. Now It tracks all CVEs until me updating moment.
- Performance improvements.
- Now Plecost runs on Python: 3.3, 3.4, 3.5 and 3.6
- Updated Wordpress plugin list
- Updated CVE database

New features
------------

- Added new system to detect remote wordpress version, based in version links of statics

Version 1.0.0
=============

Internal modifications
----------------------

- Code REWRITTEN in Python 3.
- Removed threads support in favor of asyncio connections.

Improvements and fixes
----------------------

- Improved (a lot) the performance, thanks to asyncio module.
- Improved vulnerability search for plugins.
- Improved verbosity feature, adding different verbosity levels, not only one.
- Fixed a lot of bugs.

New features
------------

- Added vulnerability search for wordpress version. Now Plecost indicated CVEs to installed wordpress.
- Added progress bars
- Automatic learning of site redirects and follow them.
- Possibility of install using pip
- Added command line option to consult plugins vulnerabilities and CVE database.
- Added CVE searcher for outdated wordpress versions.