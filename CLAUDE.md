# Plecost — Context for Claude

## Gestión del contexto
- Si ya has leído un fichero y está en el contexto de la conversación, no vuelvas a leerlo — ya lo tienes disponible.

## Setup
```bash
pip install -e ".[dev]"           # install with dev dependencies
pip install -e ".[dev,postgres]"  # include asyncpg for PostgreSQL
```

## Development Commands
```bash
python3 -m pytest tests/unit tests/integration tests/contract tests/property -v
python3 -m pytest tests/unit tests/integration tests/contract tests/property --cov=plecost --cov-fail-under=75
python3 -m ruff check plecost/ --fix
python3 -m mypy plecost/ --ignore-missing-imports
```

## Quick Scan Examples
```bash
plecost scan https://target.com -v             # fast mode (default): top 150 plugins, top 50 themes
plecost scan https://target.com --deep -v      # full wordlist scan (4750+ plugins, 900+ themes)
plecost scan https://target.com --force        # scan even if WordPress not detected
plecost scan -T urls.txt -o report.json        # bulk scan, save JSON
```

## Concurrency Model
- The project is **pure asyncio** — do NOT introduce `threading`, `ThreadPoolExecutor`, or `concurrent.futures`
- `Rich.Live` creates an internal background thread; always wrap `asyncio.run()` in `try/finally` to call `display.stop()` on `KeyboardInterrupt`
- `ScanContext` has no locks — asyncio is single-threaded; list `.append()` is safe without synchronization

## Architecture
- `plecost/cli.py` — Typer entrypoint; commands: `scan`, `explain`, `update-db`, `build-db`, `sync-db`, `modules`
- `plecost/scanner.py` — `Scanner.run()` and `Scanner.run_many()` (public API for use as a library)
- `plecost/engine/` — `http_client.py` (httpx async), `context.py` (shared state), `scheduler.py` (async dependency graph)
- `plecost/modules/` — 19 detection modules; each extends `ScanModule` with `name`, `depends_on`, `async run()`
- `plecost/database/` — SQLAlchemy async; `updater.py` (NVD full build), `incremental.py` (delta sync), `downloader.py` (from release), `store.py` (queries)
- `plecost/database/patch_applier.py` — applies JSON patches (upserts + soft-deletes); portable SQLite/PG
- `plecost/reporters/` — `terminal.py` (Rich), `json_reporter.py` (JSON)
- `plecost/models.py` — core data types: `Finding`, `Severity`, `ScanResult`, `Plugin`, `Theme`

## Finding IDs
- Permanent format: `PC-{MODULE}-{NNN}` (e.g. `PC-MCFG-001`, `PC-CVE-CVE-2023-28121`)
- Associated remediation ID: `REM-{MODULE}-{NNN}`
- Full registry of 120 IDs in `plecost/cli.py` → `plecost explain <ID>`

## Public API
- `from plecost import Scanner, ScanOptions, ScanResult` — only these three are exported (`__all__`)
- Library usage example:
```python
from plecost import Scanner, ScanOptions
result = await Scanner(ScanOptions(url="https://target.com")).run()
# result.blocked → True if target returned 403 on pre-flight probe
```

## Python Environment
- Always use `python3 -m pytest` (not bare `pytest`) — multiple Python versions on this system
- Pyright reports false positives everywhere (unused imports, undefined variables in local imports, unused params in test mocks) — ignore them, ruff is the authoritative linter
- `python3 -m plecost` works via `plecost/__main__.py` → `plecost.cli:app`
- `tests/unit/test_i18n.py::test_t_returns_spanish_string` has a pre-existing failure — not a regression, ignore it when checking suite results

## Scanner Extensibility (Callbacks)
- `Scanner(opts, on_module_start, on_module_done, on_finding, on_module_progress)` — optional callbacks for real-time progress
- `on_module_progress(name: str, current: int, total: int)` — fired during wordlist scans (plugins, themes) with per-slug progress
- `ScanContext(opts, on_finding=cb, on_progress=cb)` — called after each `add_finding()` / `report_progress()`
- `Scheduler(modules, on_module_start=cb, on_module_done=cb)` — called before/after each module runs
- `VerboseDisplay` in `reporters/terminal.py` — Rich Live display wired to all four callbacks; used by `-v` CLI flag
- Library usage stays silent: don't pass callbacks → no output
- Progress reporting pattern: `checked = [0]` list (mutable in closure) + `finally: checked[0] += 1; ctx.report_progress(module, checked[0], total)` — same pattern as plugins/themes
- When multiple detectors run concurrently via `asyncio.gather`, ALL wordlist-scanning detectors must call `ctx.report_progress()` — if only one does, the display freezes at 100% while the others run silently

## Repository
- GitHub repo: `Plecost/plecost`
- Main branch: `main`
- CI minimum coverage: 75% (`--cov-fail-under=75`)
- The git repo root is `plecost/` (not the parent `Projects/plecost/`) — run git commands from there
- `plecost-db/` is a sibling project (separate repo) providing the CVE database infrastructure

## CVE Database
- Local DB: `~/.plecost/db/plecost.db` (SQLite, SQLAlchemy async)
- `PluginsWordlist.active_installs` + `ThemesWordlist.active_installs` — populated from WordPress.org API; existing DBs older than the `ThemesWordlist` schema change need `plecost update-db`
- `plecost build-db` — full build from NVD (maintainers, one-time)
- `plecost update-db` — incremental JSON patch system: checks index.checksum first, downloads only missing daily patches; first run downloads full.json
- `plecost sync-db` — incremental sync from `db_metadata.last_nvd_sync` (daily GitHub Action)
- `plecost sync-db --output-patch patch-YYYY-MM-DD.json` — also writes daily JSON patch file (used by CI)
- NVD API rate limit: 6s between requests without API key; use `NVD_API_KEY` env var for higher limit
- Patch files on GitHub: release tag `db-patches` — `index.json`, `full.json`, `patch-YYYY-MM-DD.json`
- Architecture docs: `docs/cve-patch-system/`

## BruteForce Module
- Activado SOLO por `opts.brute_force=True` o `module_options["brute_force"]["enabled"]="true"` — NUNCA por `--aggressive`
- `ScanOptions` nuevos campos: `brute_force: bool = False`, `brute_force_wordlist: str|None = None`, `brute_force_combine: bool = False`
- `ScanContext` nuevos atributos: `ctx.xmlrpc_accessible: bool`, `ctx.xmlrpc_multicall_available: bool` (seteados por xmlrpc module)
- Semáforo: el `await asyncio.sleep(delay)` va FUERA del bloque `async with sem:` — si va dentro bloquea slots del semáforo durante la espera
- Lectura de wordlist externa: `asyncio.to_thread(_load_wordlist, path, limit)` — `_load_wordlist` es función de módulo, NO método de clase
- Path traversal: validar con `Path(path).resolve().is_file()` antes de abrir fichero externo
- Detección de login exitoso: cookie `wordpress_logged_in_` en `Set-Cookie` (primario); redirect a `/wp-admin/` (fallback)
- PC-BRU-003 = sin usuarios para atacar; PC-BRU-007 = rate-limiting detectado — son findings distintos

## Users Module — Gotchas
- Author archives: en el bloque `except Exception`, hacer `consecutive_misses += 1` (NO `break`) — break ignoraría el contador y rompería el early-stop
- RSS `dc:creator` dedup: por username sintetizado (`name.lower().replace(" ", "")`), NO por `display_name` — evita duplicados cuando dos posts tienen el mismo autor
- REST API pagination: siempre capear con `min(total_pages, 100)` — un servidor malicioso puede devolver `X-WP-TotalPages: 999999`
- `User.source` valores válidos: `"rest_api"`, `"author_archive"`, `"wp_sitemap"`, `"rss_feed"`, `"yoast_sitemap"`, `"oembed"`, `"html_author_link"`

## XML Parsing Safety
- Antes de `ET.fromstring(r.text)`, verificar `len(r.content) < 1_048_576` (1 MB) — respuestas XML sin cota son vulnerables a XML bomb
- Aplica a todos los módulos que parsean XML: `_wp_sitemap_users`, `_yoast_author_sitemap`, `_rss_feed`, xmlrpc

## Tests
- `asyncio_mode = "auto"` in pyproject.toml — do NOT add `@pytest.mark.asyncio` manually
- respx: use `respx.get(url).mock(return_value=httpx.Response(...))` — NOT `respx.pattern(...)`
- respx catch-all: `respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))` — use as last route to handle unmatched URLs
- respx: routes are matched in order — put specific mocks before the catch-all `url__regex` route
- Coverage: use dots not slashes: `--cov=plecost.database.patch_applier` (not `plecost/database/patch_applier`)
- Funciones helper en módulos (e.g. `_load_wordlist` en `brute_force.py`) son funciones de módulo, NO métodos de clase — importarlas directamente: `from plecost.modules.brute_force import _load_wordlist`
- Functional tests against real WordPress: `PLECOST_FUNCTIONAL_TESTS=1 pytest tests/functional/`
- Test Docker WordPress: `docker-compose -f docker-compose.test.yml up -d` (port 8765)

## Environment Variables
- `PLECOST_DB_URL` — database URL for `update-db`, `build-db`, `sync-db`
- `PLECOST_TIMEOUT` — request timeout for `scan`
- `PLECOST_OUTPUT` — output file path for `scan`
- `NVD_API_KEY` — NVD API key (higher rate limit for `build-db`/`sync-db`)
- `GITHUB_TOKEN` — GitHub token for `update-db` downloads (avoids rate limiting)

## Pre-flight Check
- `Scanner._check_access()` probes the root URL before running any module — if it returns 403, `ScanResult.blocked=True` and the scheduler is skipped entirely
- Finding `PC-PRE-001` (module `pre-flight`) is emitted on block detection

## Scan Modes (Fast vs Deep)
- `ScanOptions.deep = False` by default — queries top 150 plugins + top 50 themes ordered by `active_installs DESC`
- `ScanOptions.deep = True` (CLI: `--deep`) — full wordlist (4750+ plugins, 900+ themes)
- `CVEStore.get_plugins_wordlist(top_n)` / `get_themes_wordlist(top_n)` accept optional limit
- `ThemesWordlist` has `active_installs` column; existing DBs get it via `_apply_sqlite_migrations()` in `update-db`
- Webshells module also respects `deep`: fast=147 paths, deep=294 paths, extended (`--module-option webshells:wordlist=extended`)=523 paths
- `UploadsPhpDetector` fast=273 paths (current year only), deep=1785 paths (2020→current year)

## Adding a New Module
- Create `plecost/modules/your_name.py` extending `ScanModule` with `name`, `depends_on`, `async run(ctx, http)`
- Complex modules can be subpackages: `plecost/modules/your_name/` with `module.py` (main class), `base.py` (ABC), `wordlists.py`, and `detectors/` subpackage — export via `__init__.py`
- Subpackage `__init__.py` must export the module class: `from plecost.modules.your_name.module import YourModule; __all__ = ["YourModule"]`
- `asyncio.gather(..., return_exceptions=True)` — exceptions from detectors are silently ignored (project convention); do not re-raise
- `ScanContext` useful attributes: `ctx.wordpress_version` (str|None), `ctx.plugins` (list[Plugin]), `ctx.add_plugin(plugin)`
- Register it in `plecost/scanner.py` (instantiate and add to module list)
- Add finding IDs to `_FINDINGS_REGISTRY` in `plecost/cli.py` (`explain` command)
- Add module name to `_ALL_MODULE_NAMES` in `plecost/cli.py` (verbose progress display)
- Add new IDs to `KNOWN_FINDING_IDS` in `tests/contract/test_finding_ids.py`

## Semi-Active Checks (eCommerce modules)
- CVE detection must be **boolean-only**: check for SQL error strings / deserialization patterns in `response.text[:4096]`
- **Never** use time-based detection (SLEEP, WAITFOR) — it ties up the httpx connection and starves the asyncio event loop
- `module_options` key is user-defined per module and need NOT match `name`: e.g., `wp_ecommerce` module reads `ctx.opts.module_options.get("wpec", {})` — document the key in the module's docstring or CLAUDE.md entry

## Typer Gotchas
- `tuple[str, ...]` NOT supported as parameter type — use `List[str]` from `typing` for multi-value CLI options; causes `RuntimeError: Type not yet supported: Ellipsis` at runtime
- Default for `List[str]` Typer options must be `[]` not `()`

## httpx Gotchas
- `httpx.SSLError` does not exist — catch SSL errors with `(httpx.ConnectError, httpx.TransportError)` and check `"ssl"/"tls"/"certificate"` in `str(e)`

## SQLAlchemy Async Gotchas
- Always call `await engine.dispose()` in a `try/finally` block in CLI commands — exceptions skip it otherwise
- `patch_applier._apply_upserts()` batches with `session.flush()` every 2000 records; `session.commit()` happens once at end
- `.where()` does NOT accept Python `True`/`False` as fallback conditions — build a `conditions: list` and append conditionally, then unpack with `*conditions`
- `Base.metadata.create_all` only creates missing tables, never adds columns — schema migrations need explicit `ALTER TABLE` via `_apply_sqlite_migrations()` in `cli.py` using `PRAGMA table_info(table)` to detect missing columns

## Modules That Need the Database Store
- Modules requiring DB access receive `store: CVEStore | None` in constructor (like `CVEsModule`)
- Use `if TYPE_CHECKING: from plecost.database.store import CVEStore` to avoid circular imports
- When `store is None` (DB unavailable), module must still run gracefully and emit its summary finding
- Register in `scanner.py` as `MyModule(store)` — `store` is the local variable that may be None

## asyncio.gather() Shared Mutable State
- Use `counter: list[int] = [0]` to share numeric counters across parallel coroutines safely
- asyncio is single-threaded — list.append() needs no locks

## Background Agents & Git
- When running multiple background agents that commit, tell each to commit but NOT push; do a single `git push` from the main session after all agents finish

## Docker
- `.dockerignore` has `*.md` + `!README.md` — do not remove the exception or the build will fail

## DVWP Test Environment (tests/dvwp/)
- Plugin activation under PHP 8 (`wordpress:6.6`): install all plugins first (no `--activate`), then activate in a loop with `|| true` — prevents one failure from aborting the script
- `wpdiscuz 7.0.4`: activation hook returns "Permission Denied !!!" via wp-cli — keep installed, not activated; plecost detects it via file headers
- `yith-woocommerce-wishlist 2.2.9`: PHP fatal on activation (curly-brace array syntax removed in PHP 8) — keep installed, not activated
- `wordfence 7.5.0`: needs `mkdir -p /var/www/html/wp-content/wflogs` before activation or flock() fatal error
- `wp-content/mu-plugins/` is NOT created by default — `mkdir -p` before placing fixtures
- `wp-content/uploads/.htaccess` blocks PHP execution by default — override with `Allow from all / Satisfy Any` to test webshell detectors
- china_chopper fixture: PHP file with no `echo` outputs 0 bytes → matches `len(body) == 0` fingerprint

## Finding Evidence
- Never store raw API response data in `evidence` dict — format as human-readable strings (e.g. users list as `"  • [id:N] Name (@slug) — url"` per line)

## i18n Support
- `plecost/i18n.py` — `t(key, **kwargs)` dot-notation lookup, `set_language(lang)` forced override
- Locale files: `plecost/locales/en.json` (source of truth) + `es.json`; add languages by dropping a JSON file there
- Language priority: `--lang` CLI flag → `PLECOST_LANG` env var → system locale → English fallback
- Finding ID → i18n key: `PC-WPEC-001` → `"findings.pc_wpec_001.{title,description,remediation}"`; rule: `.lower().replace("-", "_")`
- Avoid loop variable named `t` — it shadows the `t()` i18n import (use `th`, `item`, etc. instead)
- CHANGELOG is at `../CHANGELOG.md` relative to git root (`plecost/`) — use `git add ../CHANGELOG.md`

## Webshell Detection — China Chopper
- `GET /wp-content/mu-plugins/*.php → HTTP 200 + 0 bytes` es la firma EXACTA de China Chopper — NO suprimir ni bajar severidad; emitir `PC-WSH-150` CRITICAL siempre
- China Chopper es indetectable externamente por GET (diseño deliberado, Mandiant 2013) — la única confirmación válida es POST nonce probe: `printf("NONCE")` y verificar que el nonce aparezca en el body
- POST nonce probe solo activo en `--deep`; si no confirma → skip silencioso (no finding); solo reportar si confirmado al 100%
- Plan completo en `docs/china-chopper-detection-plan.md`; parámetros a probar: `password`, `cmd`, `c`, `pass`, `p`, `key` + variante `eval(base64_decode(...))`
- `security.php` de Plesk (legítimo) y China Chopper son indistinguibles por GET — no usar whitelist de nombres (publicaría lista de evasión en open source)
- El header `X-Powered-By: PleskLin` NO debe desactivar la detección — un Plesk comprometido sigue enviando ese header

## Misconfigs — install.php y upgrade.php
- `PC-MCFG-007`/`PC-MCFG-008`: usar `content_signature` POSITIVA (solo reportar si el formulario activo está presente)
- `_INSTALL_ACTIVE_RE = re.compile(r'<input[^>]+name=["\']weblog_title', re.IGNORECASE)`
- `_UPGRADE_ACTIVE_RE = re.compile(r'<(?:form|a)[^>]+(?:upgrade\.php|do_upgrade)', re.IGNORECASE)`
- NO usar listas negativas de frases ("already installed", "no upgrade required") — solo cubren en/es de ~60 locales WordPress; usar regex HTML positiva que es language-independent

## WordPress Version
- `KNOWN_LATEST_VERSION` en `wp_hardening.py` es un literal hardcodeado con fecha — verificar con `curl -s https://api.wordpress.org/core/version-check/1.7/ | python3 -c "import json,sys;print(json.load(sys.stdin)['offers'][0]['version'])"` antes de actualizar
- Versión más reciente verificada a 2026-05-24: `6.8.1` (confirmar antes de usar)

## Scoring de Hallazgos
- NO elevar severidad de un webshell sospechoso basándose en CVEs de otros plugins del mismo sitio — es correlación espuria que genera HIGH engañosos sobre archivos legítimos

## Release Process
- Antes de tagear: actualizar `version` en `pyproject.toml` — el paquete PyPI se construye desde ahí, no del tag
- Orden: bump `pyproject.toml` → commit → push → `git tag vX.Y.Z` → `git push origin vX.Y.Z` → `gh release create`
- Si el tag ya existe en remoto y hay que rehacerlo: `git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z && gh release delete vX.Y.Z --yes`

## mypy Gotchas
- `dict` sin tipo dispara `[type-arg]` en CI — usar siempre `dict[str, str]` o `dict[str, Any]`
- `result.rowcount` tras `session.execute(UPDATE)`: mypy no lo reconoce en `Result[Any]` — suprimir con `# type: ignore[attr-defined]` (no `[union-attr]`)
- mypy no está instalado globalmente — ejecutar con `source .venv/bin/activate && python3 -m mypy plecost/ --ignore-missing-imports`
- Las anotaciones "Event loop is closed" en CI son warnings pre-existentes de aiosqlite — no son fallos; CI pasa igualmente

## License
- PolyForm Noncommercial License 1.0.0 — free for non-commercial use; commercial use requires contacting cr0hn@cr0hn.com
- Do NOT change to MIT or any open source license without explicit authorization
