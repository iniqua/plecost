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