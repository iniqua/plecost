## [unreleased] — 2026-04-14

### Added
- Full internationalization (i18n) support with `plecost/locales/en.json` and `es.json`
- `--lang` CLI flag on `scan`, `explain`, and `modules list` commands to force output language
- `PLECOST_LANG` environment variable for language selection (lower priority than `--lang`)
- Language auto-detection from system locale (`LANG`, `LC_ALL`) with English fallback
- `plecost/i18n.py` module with `t(key, **kwargs)` and `set_language(lang)` API
- New languages can be added by dropping a JSON file in `plecost/locales/`

### Changed
- `reporters/terminal.py`: all hardcoded labels replaced with `t()` calls
- `modules/wp_ecommerce.py`: all Finding strings now use i18n keys (13 findings localized)
- `modules/misconfigs.py`: `_CHECKS` tuples use i18n keys; `_check()` calls `t()` at runtime
- `cli.py`: `explain` and `modules list` commands fully localized

---

## [Unreleased] — 2026-04-14

### Fixed
- **plugins**: passive scan no longer overwrites a found `?ver=` version with `None` when the same plugin slug appears multiple times in the HTML; now keeps the best version seen across all occurrences
- **themes**: same fix — first occurrence without `?ver=` is now upgraded if a later occurrence has the parameter
- **plugins / themes**: passive detection window for `?ver=` extended from 100 to 200 characters after the path match, reducing missed versions on deeper resource paths
- **plugins / themes**: plugins/themes detected passively but absent from the brute-force wordlist now receive a targeted `readme.txt` / `style.css` fetch to recover the version instead of always showing `unknown`
- 6 new regression tests (3 plugins + 3 themes) covering the three fixed scenarios

### Added
- `webshells` module: remote webshell detection for WordPress sites
  - `KnownPathsDetector`: probes ~100-300 known webshell filenames across WP directories; includes catch-all preflight guard to eliminate false positives
  - `UploadsPhpDetector`: detects PHP execution in `wp-content/uploads/` across all year/month subdirs (2020–present)
  - `MuPluginsDetector`: probes must-use plugins directory (`wp-content/mu-plugins/`) — primary vector for persistent backdoors in 2024-2025 attacks
  - `ResponseFingerprintDetector`: fingerprints HTTP response bodies against China Chopper, WSO/FilesMan, b374k, c99shell, Godzilla/Behinder, and polyglot image/PHP families
  - `ChecksumsDetector` (requires credentials): verifies 20 high-risk WordPress core files via `api.wordpress.org/core/checksums/`
  - `FakePluginRestDetector` (requires credentials): uses `/wp-json/wp/v2/plugins` with Basic Auth to detect unauthorized or hidden plugins
- 6 new finding IDs: `PC-WSH-001`, `PC-WSH-100`, `PC-WSH-150`, `PC-WSH-200`, `PC-WSH-250`, `PC-WSH-300`
- Module option `--module-option webshells:wordlist=extended` activates ~300-path wordlist
- Module option `--module-option webshells:detectors=name1,name2` runs only specified detectors
- `FakePluginRestDetector` in `plecost/modules/webshells/detectors/fake_plugins.py` — queries WP REST API `/wp-json/wp/v2/plugins` with Basic Auth and flags any active plugin not previously detected by passive scanning, emits `PC-WSH-300` (HIGH, CVSS 7.5)
- 4 unit tests in `tests/unit/test_module_webshells_fake_plugins.py`: fake plugin flagged, known plugin skipped, no credentials skipped, 401 response skipped
- `UploadsPhpDetector` in `plecost/modules/webshells/detectors/uploads_php.py` — probes `wp-content/uploads/` (root and dated year/month subdirectories) for accessible PHP files, emits `PC-WSH-100` (CRITICAL, CVSS 9.8) on any HTTP 200 response
- 3 unit tests in `tests/unit/test_module_webshells_uploads.py`: PHP in uploads root, PHP in dated subdir, no finding on 403
- `KnownPathsDetector` in `plecost/modules/webshells/detectors/known_paths.py` — probes known webshell filenames across common WordPress directories, emits `PC-WSH-001` (CRITICAL, CVSS 9.8) on hit
- Preflight catch-all guard: detects sites that return 200 for arbitrary paths and skips scan to avoid mass false positives
- Content-type FP guard: only flags responses with `text/html`, `text/plain`, or `application/x-httpd-php` content types
- 4 unit tests in `tests/unit/test_module_webshells_known_paths.py`: 200/text-html hit, all-404, image content-type FP guard, catch-all site skip
- `magecart` module: detects Magecart/card-skimming JavaScript on WooCommerce and WP eCommerce checkout pages via blocklist lookup (`PC-MGC-000` through `PC-MGC-004`)
- `MagecartDomain` ORM model and `get_magecart_domains()` store query in `plecost/database/`
- `MagecartInfo` dataclass in `plecost/models.py`; added `magecart` field to `ScanResult` and `ScanContext`
- `download_magecart_domains()` in `plecost/database/downloader.py` for fetching blocklist from GitHub releases
- `apply_magecart_patch()` in `plecost/database/patch_applier.py` for applying domain blocklist updates
- 5 new finding IDs: `PC-MGC-000` (INFO), `PC-MGC-001` (CRITICAL), `PC-MGC-002` (CRITICAL), `PC-MGC-003` (HIGH), `PC-MGC-004` (MEDIUM)
- Unit tests for `MagecartModule` (`tests/unit/test_module_magecart.py`): 14 tests covering `_should_run`, URL generation, detection per category, summary emission, graceful 404 handling, inline/same-domain script filtering, and store call verification
- DB-layer tests for `MagecartDomain` store queries (`tests/unit/test_database_magecart.py`): active domain matching, empty-list guard, soft-delete exclusion
- Contract test update: `PC-MGC-000` through `PC-MGC-004` added to `KNOWN_FINDING_IDS` in `tests/contract/test_finding_ids.py`

## [Unreleased] - 2026-04-14 (magecart module implementation)

### Added
- New `magecart` security module (`plecost/modules/magecart.py`) detecting Magecart / card-skimming JavaScript on WooCommerce and WP eCommerce checkout pages
- Scans `/checkout`, `/cart`, `/?pagename=checkout`, `/?pagename=cart` via passive GET requests
- Extracts external script `src` attributes and checks domains against the local CVE database blocklist
- Finding IDs: PC-MGC-000 (INFO summary), PC-MGC-001 (CRITICAL, Magecart domain on checkout), PC-MGC-002 (CRITICAL, dropper on checkout), PC-MGC-003 (HIGH, exfiltrator on checkout), PC-MGC-004 (MEDIUM, known domain on non-checkout page)
- Severity mapping supports three domain categories: `magecart`, `dropper`, `exfiltrator`
- `ctx.magecart` populated with `MagecartInfo` (detected, pages_scanned, scripts_analyzed, malicious_domains)
- Module only runs when WooCommerce or WP eCommerce is detected (`depends_on: fingerprint, woocommerce, wp_ecommerce`)

## [Unreleased] - 2026-04-13

### Added
- Extended `tests/property/test_robustness.py` with three new Hypothesis tests: `plugins._VER_RE` never raises on arbitrary text, all `_FINDINGS_REGISTRY` IDs match the `PC-<MODULE>-<ID>` pattern, and `ScanContext.url` never retains a trailing slash
- New `tests/contract/test_json_output_schema.py` with 10 golden/schema tests verifying the JSON output contract: required top-level keys, ecommerce fields always present, Finding field completeness, ScanSummary keys, Severity serialized as uppercase string, timestamp as ISO string, correct types for lists/booleans/numbers
- 8 new unit tests for `FingerprintModule` covering `_try_feed()`, `_try_rest_api()`, and `_try_wp_paths()` (normal server and WAF blanket scenarios)

## [4.2.0] - 2026-04-13

### Added
- New `wp_ecommerce` security module detecting misconfigurations and vulnerabilities in WP eCommerce (wp-e-commerce) plugin
- 13 new finding IDs: PC-WPEC-000 through PC-WPEC-010, PC-WPEC-020, PC-WPEC-021
- Passive checks: plugin directory listing, uploads directory exposure, digital downloads directory exposure, admin script exposure (db-backup.php, display-log.php), ChronoPay gateway detection and callback endpoint check
- Semi-active checks (--module-option wpec:mode=semi-active): CVE-2024-1514 (ChronoPay SQL Injection) and CVE-2026-1235 (PHP Object Injection) detection
- PC-WPEC-003: always-emitted finding flagging WP eCommerce as abandoned since 2020 with unpatched CVEs
- `wp_ecommerce` JSON section in scan output with version, active_gateways, and checks_run

---

## [4.1.0] — 2026-04-13

### Added
- New `woocommerce` module for detecting vulnerabilities and misconfigurations in WooCommerce and its official plugins (Payments, Blocks, Stripe Gateway)
- Generic per-module options system: `--module-option MODULE:KEY=VALUE` in CLI and `ScanOptions.module_options` in library API
- 16 new finding IDs: PC-WC-000 to PC-WC-021
- `WooCommerceInfo` dataclass in `ScanResult` with dedicated section in JSON output
- Passive checks: WooCommerce fingerprinting, sub-plugin detection (Payments, Blocks, Stripe), REST API open without auth, wc-logs directory listing, uploads directory exposure
- Semi-active checks (require `--module-option woocommerce:mode=semi-active`): CVE-2023-28121 (WooCommerce Payments auth bypass, CVSS 9.8) and CVE-2023-34000 (Stripe Gateway IDOR, CVSS 7.5)
- Authenticated checks (require consumer key/secret in module_options): system-status and payment-gateways
- 25 unit tests with respx

### Fixed
- `Scanner.run_many()` now propagates `module_options` to all targets in multi-target scans

---

## 2026-04-13 — Per-plugin CVE detail tables in scan output

### Added
- `PluginVuln` dataclass in `models.py`: lightweight CVE record for display (cve_id, title, severity, cvss_score, has_exploit, version_range)
- `Plugin.vulns: list[PluginVuln]` field: all known CVEs for the plugin slug regardless of installed version
- `Plugin.vuln_count` property: derived from `len(vulns)`
- `CVEStore.find_all_by_slug()`: returns all non-rejected CVEs for a slug without version filtering
- Terminal reporter: per-plugin CVE tables after the summary table, sorted by severity (CRITICAL first), with color-coded severity and exploit indicator

### Changed
- `CVEsModule.run()`: populates `plugin.vulns` for every detected plugin via `find_all_by_slug()`
- `CVEStore.count_by_slug()` replaced by `find_all_by_slug()` (count derived from result length)

---

## 2026-04-13 — README: remove build-db/sync-db sections, fix CVE DB refs, update workflows

### Changed
- `README.md`: removed `build-db` and `sync-db` entries from Table of Contents
- `README.md`: updated Environment Variables table — dropped `NVD_API_KEY` row, narrowed `PLECOST_DB_URL` scope to `update-db`
- `README.md`: removed CLI Reference sections for `plecost build-db` and `plecost sync-db`
- `README.md`: updated "Which command to use?" table to reference `plecost-db` repo
- `README.md`: updated "How it works" — `update-db` release URL points to `Plecost/plecost-db`, items 2/3 reference `plecost-db` commands with repo links
- `README.md`: updated `docs/cve-patch-system/` link to `https://github.com/Plecost/plecost-db/tree/main/docs/cve-patch-system`
- `README.md`: updated "Using PostgreSQL" section — removed `build-db` command, added `plecost-db build-db` block
- `README.md`: removed "NVD API rate limiting during build-db" troubleshooting section
- `README.md`: fixed from-source install path (`cd plecost` instead of `cd plecost/src`)
- `.github/workflows/ci.yml`: removed `v3.0.0` from push branch triggers; added `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true`
- `.github/workflows/docker-publish.yml`: added `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true`
- `.github/workflows/pypi-publish.yml`: added `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true`

---

## 2026-04-13 — Eliminar build-db/sync-db, mover módulos/workflows/docs a plecost-db

### Removed
- `plecost/cli.py`: eliminados comandos `build-db` y `sync-db` del CLI
- `plecost/database/updater.py`: módulo de generación inicial de BD (movido a plecost-db)
- `plecost/database/incremental.py`: módulo de sincronización incremental (movido a plecost-db)
- `tests/unit/test_database_updater.py`, `tests/unit/test_database_incremental.py`, `tests/integration/test_database_updater.py`
- `.github/workflows/update-cve-db.yml`, `.github/workflows/update-databases.yml` (movidos a plecost-db)
- `docs/cve-patch-system/` y `docs/cve-database-architecture-decision.md` (movidos a plecost-db)

### Changed
- `plecost/database/downloader.py`: `GITHUB_REPO` apunta ahora a `Plecost/plecost-db`
- `tests/unit/test_database_downloader.py`: URLs actualizadas a `Plecost/plecost-db`

---

## 2026-04-12 — Add tests for patch_applier (13 tests, 0% → coverage)

### Added
- `tests/unit/test_database_patch_applier.py`: 13 tests covering apply_patch, validation, deletes, idempotence, date tracking

---

## 2026-04-12 — README: document JSON patch system

### Changed
- `README.md`: added "How the patch system works" table explaining incremental update sizes and link to docs/cve-patch-system/

---

## 2026-04-12 — update-db: improved error messages for first-run and network failures

### Changed
- `plecost/cli.py`: `update-db` distinguishes 404/401/5xx/ConnectError with actionable messages
- `plecost/cli.py`: first-run message explains that subsequent updates will be small

---

## 2026-04-12 — Minor fixes: .gitignore and Dockerfile

### Fixed
- `.gitignore`: added `.hypothesis/` to ignore hypothesis test database files
- `Dockerfile`: removed duplicate uvloop installation (already included via [fast] extra)

---

## 2026-04-12 — patch_applier: batching and progress logging

### Changed
- `plecost/database/patch_applier.py`: `_apply_upserts()` flushes every 2000 records to avoid memory pressure with large full.json files
- `plecost/database/patch_applier.py`: added `logging` calls at INFO/DEBUG level for progress visibility
- `plecost/database/patch_applier.py`: extracted `_build_values()` helper to remove duplication

---

## 2026-04-12 — Fix GitHub Actions workflow: consistent DB path + guaranteed patch file

### Fixed
- `.github/workflows/update-cve-db.yml`: use single `DB_PATH` env var for consistent DB path across all steps
- `.github/workflows/update-cve-db.yml`: generate empty patch JSON if sync-db produces no output

---

## 2026-04-12 — docs: detailed technical documentation for the CVE JSON patch system

### Added
- `docs/cve-patch-system/README.md`: overview, system diagram, quick-reference command table, index of all documents in the folder
- `docs/cve-patch-system/architecture.md`: full technical architecture — motivation for JSON over SQLite, GitHub release artifact layout, step-by-step client and CI flows, database model reference (`NormalizedVuln`, `RejectedCve`, `DbMetadata`), CPE-to-slug mapping explanation, rejected CVE audit trail rationale
- `docs/cve-patch-system/file-formats.md`: complete format specification for every artifact — `index.json`, `index.checksum`, `patch-YYYY-MM-DD.json`, `full.json`, `full.checksum` — with annotated examples derived from the actual code and field-level reference tables
- `docs/cve-patch-system/operations.md`: operational guide covering first install, daily update, CI failure recovery, manual CVE rejection via SQL, PostgreSQL usage, and common troubleshooting scenarios
- `docs/cve-patch-system/code-guide.md`: developer guide for extending the system — adding patch format fields, integrating new CVE sources (Wordfence/Patchstack), extension points in `patch_applier.py`, testing patterns, and common pitfalls

---

## 2026-04-12 — update-db uses JSON patch system; sync-db supports --output-patch; new CI workflow

### Changed
- `plecost/cli.py` — `update-db` command now uses the JSON patch system instead of downloading a monolithic SQLite file:
  - New `--force-full` flag forces re-download of `full.json` even if patches are available
  - New helper coroutines `_update_db_async()`, `_get_metadata()`, `_set_metadata()` implement the full patch flow:
    1. Fetch remote `index.checksum` (~64 bytes) and compare with locally stored value in `db_metadata`
    2. If different (or `--force-full`): download `full.json` on first run, then apply all missing daily patches
    3. Store updated `index_checksum` in `db_metadata` after success
  - `update-db` still only supports SQLite; PostgreSQL users should use `build-db`
- `plecost/cli.py` — `sync-db` command now passes `--output-patch` option through to `IncrementalUpdater`
- `.github/workflows/update-cve-db.yml` — replaced old workflow (download SQLite + publish) with new patch-generation workflow:
  - Downloads existing DB via `plecost update-db`
  - Runs `plecost sync-db --output-patch patch-YYYY-MM-DD.json` to generate today's patch
  - Downloads existing patch files from the `db-patches` release
  - Builds `full.json` (all upserts/deletes merged) and `index.json` with SHA256 for each patch
  - Publishes everything (full.json, full.checksum, index.json, index.checksum, patch-*.json) to the `db-patches` release tag (overwriting)

---

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
- `.github/workflows/docker-publish.yml`: publica imagen multi-arch (amd64/arm64) en `ghcr.io/Plecost/plecost` al hacer push a main (tag `latest`) o push de tags `v*.*.*`
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

- Fixed issue: #18 (https://github.com/Plecost/plecost/issues/18)

New features
------------

- Added option to set custom hostname. Issue #20 (https://github.com/Plecost/plecost/issues/20)


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