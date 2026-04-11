## [4.2.0] - 2026-04-10

### Changed
- Sistema de distribución de base de datos CVE rediseñado:
  - `plecost update-db`: descarga DB pre-construida desde GitHub releases (rápido, para usuarios)
  - `plecost build-db`: construye DB desde cero desde NVD (para maintainers, primera vez)
  - `plecost sync-db`: actualización incremental (solo CVEs nuevos/modificados desde última sync)
  - GitHub Action usa sync incremental: descarga DB del release anterior, aplica delta NVD, publica nuevo release
  - Tabla `db_metadata` en SQLite guarda `last_nvd_sync` para updates incrementales
  - Soporte para `NVD_API_KEY` en variable de entorno (mayor rate limit: 0.6s vs 6s entre requests)
  - `DatabaseUpdater` acepta `years_back` y `nvd_api_key` en constructor
  - `process_nvd_batch` refactorizado como función libre reutilizable desde `updater.py` e `incremental.py`
  - Nuevo módulo `plecost/database/downloader.py`: descarga streaming desde GitHub releases
  - Nuevo módulo `plecost/database/incremental.py`: `IncrementalUpdater` para sync delta NVD
  - `.github/workflows/update-cve-db.yml` actualizado con permisos `contents: write` y flujo incremental

---

## [4.1.0] - 2026-04-10

### Changed
- Rediseño completo del sistema de base de datos CVE
  - SQLAlchemy 2.0 async (aiosqlite para SQLite, asyncpg para PostgreSQL)
  - Nuevo modelo `NormalizedVuln` con rangos de versión exactos (versionStartIncluding/Excluding, versionEndIncluding/Excluding)
  - Parseo real de CPEs del NVD con filtro target_sw=wordpress
  - Fuzzy matching Jaro-Winkler inline (sin dependencias extra) para mapeo slug→CPE product
  - Descarga los últimos 5 años de CVEs del NVD paginado
  - `DatabaseUpdater` acepta `db_url` en lugar de `db_path` (soporte SQLite y PostgreSQL)
  - `CVEStore` completamente async con método `from_url()` factory
  - `scanner.py`: carga de wordlists y store movida a `run()` async
  - `cves.py`: `store.find()` ahora se llama con `await`
  - `cli.py update-db`: nuevo flag `--db-url` en lugar de `--db-path`
  - Eliminada dependencia `aiofiles`, añadidas `sqlalchemy[asyncio]>=2.0` y `aiosqlite>=0.19`
  - Tests unitarios actualizados para el nuevo store async con SQLAlchemy

---

## 2026-04-10 — Debate técnico y decisión arquitectónica de la base de datos CVE

### Added
- `docs/cve-database-architecture-decision.md`: Documento de decisión resultante de un debate técnico estructurado entre 5 enfoques (CPE Purist, APIs WP-Specific, Diccionario Pre-construido, Híbrido por Capas, NLP/Similarity) para resolver el problema de mapeo slug→CVE en Plecost v4.0
  - El enfoque ganador es Delta (Híbrido por Capas): NVD para WordPress Core, APIs especializadas WP (Patchstack/Wordfence) para plugins/themes, diccionario seed curado para top 500 plugins
  - Propuesta técnica concreta: modelos SQLAlchemy 2.0 async, engine factory SQLite/PostgreSQL, flujo de updater por capas, flujo de consulta O(1) en scan time
  - Estimación de esfuerzo: ~10.5 días / 1 sprint

---

## [4.0.1] - 2026-04-11

### Changed
- Licencia cambiada de FSL-1.1-MIT a PolyForm Noncommercial License 1.0.0
  - Licencia estándar redactada por abogados, sin conversión automática a open source
  - Uso comercial requiere licencia de pago (contacto: cr0hn@cr0hn.com)
  - Link: https://polyformproject.org/licenses/noncommercial/1.0.0/
- README reescrito completamente en inglés
- Aspecto profesional mejorado: estilo Nuclei/WPScan, tablas limpias, demo output, arquitectura, benchmarks

---

## 2026-04-10 — Tests funcionales contra WordPress real con Docker

### Added
- `docker-compose.test.yml`: actualizado con healthcheck mejorado (mysqladmin con credenciales, curl wp-login.php) y variables de entorno correctas
- `tests/functional/test_scanner_functional.py`: 8 tests funcionales que verifican detección de WordPress, versión, findings, summary, readme.html, REST API y JSON reporter
- `tests/conftest.py`: registra el marker `functional` para pytest
- `scripts/run_functional_tests.sh`: script helper para CI que levanta Docker, espera WordPress y ejecuta los tests
- `pyproject.toml`: añadido `markers` en `[tool.pytest.ini_options]` con el marker `functional`

---

## 2026-04-10 — Corrección de imports y calidad de tests

### Fixed
- Eliminados 11 imports no usados en ficheros de test (`pytest`, `json`, `asyncio`, `VulnerabilityRecord`, `Plugin`, `Theme`, `User`) detectados por ruff
- Todos los 53 tests unitarios pasan correctamente
- mypy y ruff sin errores en `plecost/` y `tests/`

---

## [4.0.0] - 2026-04-10

### Changed
- Licencia cambiada de MIT a FSL-1.1-MIT (Functional Source License)
  - Uso libre para investigación, auditorías internas y proyectos open source
  - Prohibido ofrecer como SaaS o servicio de pago
  - Convierte automáticamente a MIT tras 4 años

---

## 2026-04-10 — CI/CD workflows

### Added
- `.github/workflows/docker-publish.yml`: publica imagen multi-arch (amd64/arm64) en `ghcr.io/iniqua/plecost` al hacer push a master (tag `latest`) o push de tags `v*.*.*`
- `.github/workflows/pypi-publish.yml`: publica paquete en PyPI con trusted publishing (OIDC) al hacer push de tags `v*.*.*`
- `Dockerfile`: añadidas labels OCI estándar (`source`, `description`, `licenses`) e instalación de `uvloop`

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