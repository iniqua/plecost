# Plecost — Context for Claude

## Entorno Python
- Usar siempre `python3 -m pytest` (no bare `pytest`) — hay múltiples versiones Python en el sistema
- Usar `python3 -m ruff check plecost/ --fix` y `python3 -m mypy plecost/ --ignore-missing-imports`
- Pyright reporta falsos positivos de imports (`plecost.database.engine`, etc.) — los módulos existen, es problema del entorno Pyright, no del código

## Repositorio
- GitHub repo: `iniqua/plecost` (no `cr0hn/plecost`)
- Rama principal: `master`
- Cobertura mínima CI: 75% (`--cov-fail-under=75`)

## Base de datos CVE
- DB local: `~/.plecost/db/plecost.db` (SQLite, SQLAlchemy async)
- `plecost build-db` — construye desde NVD desde cero (maintainers, una vez)
- `plecost update-db` — descarga DB pre-construida desde GitHub releases (usuarios)
- `plecost sync-db` — sync incremental desde `db_metadata.last_nvd_sync` (GitHub Action diaria)
- NVD API rate limit: 6s entre requests sin API key; usar `NVD_API_KEY` env var para mayor límite
- DB inicial publicada en: `github.com/iniqua/plecost/releases/tag/db-base`

## Tests
- respx: usar `respx.get(url).mock(return_value=httpx.Response(...))` — NO `respx.pattern(...)`
- Tests funcionales contra WordPress real: `PLECOST_FUNCTIONAL_TESTS=1 pytest tests/functional/`
- Docker WordPress de test: `docker-compose -f docker-compose.test.yml up -d` (puerto 8765)

## Docker
- `.dockerignore` tiene `*.md` + `!README.md` — no eliminar la excepción o el build falla

## Licencia
- PolyForm Noncommercial License 1.0.0 — libre para uso no-comercial, comercial requiere contactar cr0hn@cr0hn.com
- NO cambiar a MIT ni a ninguna licencia open source sin autorización explícita
