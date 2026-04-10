# Análisis Técnico Completo — Plecost v3.0

> Fecha: 2026-04-10  
> Analistas: 4 agentes en paralelo (arquitectura, seguridad, dependencias, async/performance)

---

## Índice

1. [¿Qué es Plecost?](#1-qué-es-plecost)
2. [Estado Actual del Proyecto](#2-estado-actual-del-proyecto)
3. [Arquitectura y Calidad de Código](#3-arquitectura-y-calidad-de-código)
4. [Funcionalidad y Capacidades de Seguridad](#4-funcionalidad-y-capacidades-de-seguridad)
5. [Dependencias y Packaging](#5-dependencias-y-packaging)
6. [Async, Performance y Python Moderno](#6-async-performance-y-python-moderno)
7. [Plan de Modernización Prioritizado](#7-plan-de-modernización-prioritizado)

---

## 1. ¿Qué es Plecost?

Plecost es un **scanner pasivo de fingerprinting de WordPress** (black-box). No explota vulnerabilidades, sino que las detecta correlacionando información extraída del objetivo contra una base de datos local de CVEs. Sus capacidades actuales son:

- Detectar si un sitio web ejecuta WordPress
- Identificar la versión del core de WordPress instalada
- Enumerar plugins instalados mediante fuerza bruta de rutas predecibles (`/wp-content/plugins/{slug}/readme.txt`)
- Correlacionar versiones con CVEs de la NVD (National Vulnerability Database)
- Detectar plugins desactualizados
- Exportar resultados en JSON/XML

**Lo que NO hace** (gaps relevantes):
- No detecta temas (themes)
- No enumera usuarios (REST API `/wp-json/wp/v2/users`)
- No comprueba `xmlrpc.php` (hay un fichero vacío preparado)
- No detecta WAF/CDN
- No usa proxy/Tor
- No tiene ninguna técnica de stealth (es ruidoso por diseño)

---

## 2. Estado Actual del Proyecto

### El problema central: dos versiones coexistentes e incompletas

El repositorio contiene **dos implementaciones paralelas incompatibles**:

| | `_plecost/` (legacy) | `plecost/` (nueva) |
|---|---|---|
| Versión | 1.1.2 | 3.0.0 |
| Python compatible | 3.3 – 3.10 | 3.9+ |
| Async API | `@asyncio.coroutine` + `yield from` (ELIMINADO en Python 3.11) | `async/await` real |
| Estado | Funcional (en Python ≤3.10), completa | ~30% implementada, incompleta |
| Plugin scanning | Implementado y funcional | Stub (`...`) sin implementar |
| CVE search | Funcional (SQLite) | `print("load")` sin implementar |
| Reporters | JSON + XML | No implementado |

**Conclusión**: La versión nueva (`plecost/`) tiene una arquitectura mejor pero no puede hacer un scan completo. La versión vieja (`_plecost/`) funciona pero es incompatible con Python 3.11+.

### Problemas críticos inmediatos

1. **Entry point roto en `setup.py`**: apunta a `plecost_lib.__main__:main`, paquete que no existe.
2. **`setup.cfg` es de otro proyecto** (`dnsrecon` de Carlos Perez) — copy-paste accidental.
3. **Workflow de CI/CD roto**: usa NVD API 1.1 JSON que NIST apagó en marzo de 2023. La base de datos no puede actualizarse.
4. **Bug lógico en `plugin.py:81`**: el filtro `--enable-plugin` funciona al revés (usa `disable_plugins` en lugar de `only_enable_plugins`).

---

## 3. Arquitectura y Calidad de Código

### 3.1 Estructura del proyecto

```
/src/
├── setup.py                   ← ROTO: entry point apunta a paquete inexistente
├── setup.cfg                  ← INCORRECTO: pertenece a dnsrecon, no a plecost
├── requirements.txt           ← Minimalista, sin versiones pinadas
├── VERSION                    ← "3.0.0"
├── CHANGELOG.md               ← Desactualizado (parado en 2017, v1.1.2)
├── devel.rst                  ← Documentación del sistema de plugins v3
│
├── _plecost/                  ← LEGACY v1.1.2 — incompatible con Python 3.11+
│   ├── __main__.py            ← CLI legacy: argparse + run() síncrono
│   ├── api.py                 ← Entry point legacy
│   └── libs/
│       ├── data.py            ← Modelos: PlecostOptions (clase dios, 130 líneas boilerplate)
│       ├── db.py              ← SQLite: mezcla DAO + lógica de negocio + presentación
│       ├── helpers.py         ← is_remote_a_wordpress(), get_wordpress_version()
│       ├── plugins_utils.py   ← Detección plugins + lógica + UI mezclada
│       ├── reporters.py       ← Reporter ABC + JSON + XML (funcional)
│       ├── utils.py           ← download(), ConcurrentDownloader, log()
│       ├── versions.py        ← find_versions(): función God de 170 líneas
│       ├── wordlist.py        ← Manejo de wordlists
│       └── updaters/
│           ├── cves.py        ← Descarga NVD XML (deprecado), parsea, guarda SQLite
│           └── plugins.py     ← Scraping wordpress.org (probablemente roto)
│
├── plecost/                   ← NUEVA v3.0.0 — arquitectura correcta, 30% implementada
│   ├── __main__.py            ← CLI v3: argparse + asyncio.run()
│   ├── __run__.py             ← async_main(): pipeline de plugins
│   ├── models.py              ← WordpressVersion, PlecostRunningOptions (dataclasses)
│   ├── network.py             ← _HTTP(Singleton) con aiohttp
│   ├── plugin.py              ← discover_plugins(), find_plugins(), PlecostPluginsConfig
│   ├── logger.py              ← _Logger(Singleton)
│   ├── interfaces.py          ← Singleton, Serializable, MetaMongo
│   └── core_plugins/
│       ├── discover_wordpress_version/    ← IMPLEMENTADO (funciona)
│       ├── discover_wordpress_plugins/    ← STUB: on_plugin_found = ...
│       └── find_cve_in_wordpress_plugins/ ← STUB: on_start solo hace print("load")
│
├── plecost_cve_database/      ← Índices Whoosh (base de datos obsoleta, julio 2021)
└── examples/
    ├── load_plugins.py        ← Demo del plugin system con importlib puro
    └── plugins/demo_plugin_*.py
```

### 3.2 Patrones de diseño identificados

**Presentes (en `plecost/`):**
- **Singleton**: `_HTTP` y `_Logger` — implementación con metaclase. Problema: no inyectable, instanciado en module-level, imposible de mockear.
- **Plugin/Hook System**: pipeline con fases ordenadas (`001..005`) y descubrimiento dinámico. Bien diseñado, mal implementado.
- **Template Method**: `Reporter` ABC en v1 con `generate()` y `save()` abstractos.
- **Data Transfer Object**: `PlecostRunningOptions`, `WordpressVersion` como `@dataclass`.

**Ausentes o mal aplicados:**
- Sin **Dependency Injection**: todo se accede via singletons globales.
- Sin **Repository Pattern**: la DB mezcla consultas, lógica y presentación.
- El Singleton global `HTTP = _HTTP()` instanciado antes de parsear el CLI hace que `--concurrency` sea ignorado.

### 3.3 Deuda técnica específica por prioridad

#### CRÍTICA — Rompen en Python 3.11+

| Problema | Fichero:Línea | Solución |
|---|---|---|
| `@asyncio.coroutine` + `yield from` | `_plecost/libs/utils.py:225,369,405`, `helpers.py:60,136`, `plugins_utils.py:213` | Reescribir con `async/await` o eliminar `_plecost/` |
| `asyncio.Queue(loop=self.loop)` | `_plecost/libs/utils.py:359` | Eliminar argumento `loop` |
| `asyncio.Task(..., loop=loop)` | `_plecost/libs/utils.py:412` | Eliminar argumento `loop` |
| `aiohttp.Timeout(5)` | `_plecost/libs/utils.py:268` | Usar `asyncio.timeout(5)` |
| `aiohttp.ClientSession(loop=loop)` | `_plecost/libs/versions.py:106` | Eliminar argumento `loop` |
| `aiohttp.TCPConnector(verify_ssl=False)` | `_plecost/libs/versions.py:105` | Cambiar a `ssl=False` |
| `open(..., "rU")` | `_plecost/libs/wordlist.py:84`, `versions.py:197` | Cambiar a `open(..., "r", newline=None)` |

#### ALTA — Bugs y anti-patrones graves

| Problema | Fichero:Línea | Detalle |
|---|---|---|
| Bug enable/disable plugins | `plecost/plugin.py:81` | `klass.slug not in disable_plugins` debería ser `not in only_enable_plugins` |
| `is` con string literal | `_plecost/libs/helpers.py:299` | `current_version is "unknown"` — usar `==` |
| `pickle` para datos | `discover_wordpress_plugins.py:65-69` | Vector de ataque; reemplazar con JSON |
| `except Exception: pass` | `find_wordpress_version.py:100-101` | Errores silenciados |
| `open()` sin `with` | `find_cve_in_wordpress_plugins.py:61`, `reporters.py` | File descriptor leak |
| `NotImplemented` vs `NotImplementedError` | `_plecost/libs/reporters.py:99,107` | `raise NotImplemented()` es semánticamente incorrecto |
| `type(v) is dict` | `__run__.py:82` | Usar `isinstance(v, dict)` |
| Descripción `"asdfas"` | `discover_wordpress_plugins.py:26` | Placeholder en código de producción |

#### MEDIA — Calidad y mantenibilidad

- `PlecostOptions` en `_plecost/libs/data.py`: clase de 130 líneas reemplazable por `@dataclass`.
- `find_versions()` en `_plecost/libs/versions.py`: función God de 170 líneas (HTTP + detección + plugins + reporting mezclados).
- Lógica de negocio mezclada con presentación (`log()` dentro de funciones de análisis).
- Estado global vía `environ["PLECOST_LOG_LEVEL"]` — imposible hacer tests concurrentes.
- Código duplicado: `banner()`, `find_plugins()`, regexes de versión WP, etc.
- NVD 2.0 XML deprecated en 2022 — migrar a NVD REST API 2.0.

### 3.4 Testabilidad: 2/10

- No existen tests (sin `tests/`, sin `pytest.ini`, sin `conftest.py`).
- Singletons en module-level requieren monkey-patching invasivo.
- Mezcla de presentación/lógica impide mockear I/O sin tocar lógica.
- `pipeline_results` como `**kwargs` libre hace imposible verificar contratos entre etapas.

---

## 4. Funcionalidad y Capacidades de Seguridad

### 4.1 Flujo de detección completo (versión legacy — la que funciona)

```
1. HEAD/GET target → verificar disponibilidad
2. Detectar redirects (301/302/303/307) → seguir
3. GET URL aleatoria → fingerprint de página de error
4. Detectar WordPress (85% de URLs típicas deben existir):
   - /wp-includes/js/jquery/jquery.js, /wp-includes/js/wp-lists.js, etc.
   - Fallback: /wp-admin/ redirect, /wp-content/ en links HTML
5. Obtener versión WP (3 métodos en cascada):
   - Method 1: GET /readme.html → regex "Version X.X.X"
   - Method 2: GET / → regex <meta name="generator" content="WordPress X.X">
   - Method 3: ?ver= en CSS/JS links
   - Fallback: /wp-login.php, /wp-admin/css/wp-admin.css
6. Consultar CVEs del core en SQLite local
7. Probar plugins del wordlist en paralelo (concurrencia configurable):
   - URLs: /wp-content/plugins/{slug}/readme.txt y README.txt
   - Parsear "Stable tag: X.X.X"
   - Status 403 → plugin existe (versión desconocida)
   - Filtrar falsos positivos: ratio similitud con error page < 0.52
8. Para cada plugin encontrado: consultar CVEs en SQLite
```

### 4.2 Wordlists incluidas

| Fichero | Plugins |
|---|---|
| `plugin_list_10.txt` | 10 (testing rápido) |
| `plugin_list_50.txt` | 50 más populares (default) |
| `plugin_list_100.txt` | 100 |
| `plugin_list_250.txt` | 250 |
| `plugin_list_1000.txt` | 999 |
| `plugin_list_huge.txt` | 1176 |

Top plugins incluidos: Contact Form 7, Akismet, Yoast SEO, Jetpack, WooCommerce, Wordfence, W3 Total Cache.

### 4.3 Base de datos CVE

**Legacy (`_plecost/`) — SQLite con FTS4:**
- Fuente: NVD XML feeds 2.0 (DEPRECADOS — NIST los apagó en 2022)
- Filtra CPE con `~~~wordpress~~` o `:wordpress:`
- Genera automáticamente versiones anteriores vulnerables
- Búsqueda fuzzy con `difflib.SequenceMatcher` (threshold > 0.8 versión, > 0.9 nombre)
- Solo reporta si versión instalada <= versión vulnerable en DB

**Nueva (`plecost/`) — Whoosh:**
- Fuente: NVD JSON 1.1 feeds (DEPRECADOS — NIST los apagó en marzo 2023)
- Almacena: CVE ID, descripción, CVSS v3/v2, CPE, rangos de versión
- Base de datos actual en el repo: **julio 2021** (no actualizable con el código actual)

### 4.4 Capacidades de red

- `aiohttp` con semáforo por hostname (concurrencia configurable)
- SSL verification desactivada (`verify_ssl=False`)
- Timeout: 5 segundos hardcodeado (legacy)
- Sin timeout configurado en versión nueva
- Sin retry logic
- Sin proxy/Tor
- Sin rotación de User-Agent
- Sin delays entre requests
- Modo "jackass": concurrencia = 9999 (máximo ruido)

### 4.5 Formato de salida

**Legacy (funcional):**
```json
{
  "target": "http://...",
  "start_time": "...", "end_time": "...",
  "wordpress": {
    "current_version": "6.4.1",
    "last_version": "6.4.2",
    "outdated": true,
    "cves": ["CVE-2024-XXXX"]
  },
  "plugins": [{
    "plugin_name": "contact-form-7",
    "current_version": "5.8",
    "last_version": "5.9",
    "outdated": true,
    "cves": ["CVE-2023-XXXX"]
  }]
}
```

**Nueva versión**: sin sistema de reporters implementado.

### 4.6 Gaps de funcionalidad

| Gap | Prioridad | Notas |
|---|---|---|
| Base de datos CVE no actualizable | CRÍTICO | NVD 1.1 JSON apagado en 2023; migrar a NVD API 2.0 |
| Plugin scanning no implementado en v3 | CRÍTICO | `on_plugin_found = ...` en core plugin |
| CVE search no implementado en v3 | CRÍTICO | Solo `print("load")` |
| Sin detección de temas (themes) | ALTO | Misma técnica aplicable a `/wp-content/themes/` |
| Sin enumeración de usuarios | ALTO | REST API `/wp-json/wp/v2/users` trivial de implementar |
| Sin xmlrpc.php check | ALTO | Fichero existe pero vacío |
| Sin soporte proxy | MEDIO | Opción comentada en el código |
| Sin detección de WAF | MEDIO | — |
| Sin autenticación (scan de áreas privadas) | BAJO | — |

---

## 5. Dependencias y Packaging

### 5.1 Inventario de dependencias actuales

| Dependencia | Versión pinada | Estado | Veredicto |
|---|---|---|---|
| `whoosh` | ninguna | Abandonada desde 2016 (9 años sin releases) | ELIMINAR |
| `pluginbase` | ninguna | Semi-abandonada (4 años sin updates) | ELIMINAR |
| `tqdm` | ninguna | Activa (v4.67.1 disponible) | MANTENER si se usa |
| `orjson` | ninguna | Activa (v3.11.7) | MANTENER |
| `termcolor` | ninguna | Instalada v1.1.0 (2013), disponible v3.3.0 | ACTUALIZAR |
| `aiohttp` | **no declarada** | Usada pero no en requirements.txt | DECLARAR |

### 5.2 Plan de reemplazos

| Actual | Reemplazo | Justificación |
|---|---|---|
| `whoosh` | SQLite FTS5 (stdlib) | Sin dependencias extra; `sqlite3` ya en stdlib |
| `pluginbase` | `importlib.util` (stdlib) | Ya demostrado en `examples/load_plugins.py` |
| `termcolor` 1.1.0 | `termcolor>=2.4` o `rich` | `rich` es el estándar moderno para CLIs |
| `urllib.request` (en code) | `httpx[http2]` | API moderna, sync+async, type hints completos |
| `aiohttp` | `httpx` o mantener `aiohttp>=3.9` | httpx más moderno; aiohttp válido si se declara |
| NVD XML/JSON 1.1 | NVD REST API 2.0 | Las feeds 1.1 están apagadas |
| `pickle` (plugins.bin) | JSON o SQLite | Seguridad y portabilidad |

### 5.3 Dependencias de stdlib de Python 3.12 que reemplazan paquetes

- `importlib.util` → reemplaza `pluginbase`
- `sqlite3` con FTS5 → reemplaza `whoosh`
- `asyncio.timeout()` → reemplaza `aiohttp.Timeout`
- `pathlib.Path` → reemplaza `os.path` (ya en stdlib, solo modernizar uso)

### 5.4 APIs de Python eliminadas que afectan al código

| API eliminada | En qué versión de Python | Afecta a |
|---|---|---|
| `asyncio.coroutine` decorator | Python 3.11 | Todos los ficheros de `_plecost/libs/` |
| `yield from` en coroutines | Python 3.11 | Idem |
| Parámetro `loop=` en asyncio primitives | Python 3.10 | `asyncio.Queue`, `asyncio.Task` |
| `open(..., "rU")` modo universal newlines | Python 3.11 | `wordlist.py`, `versions.py` |
| `aiohttp.Timeout` | aiohttp 3.x | `utils.py` |
| `aiohttp.ClientSession(loop=loop)` | aiohttp 4+ | `versions.py` |
| `aiohttp.TCPConnector(verify_ssl=...)` | aiohttp reciente | `versions.py` |

### 5.5 pyproject.toml propuesto (completo)

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "plecost"
version = "3.0.0"
description = "WordPress fingerprinting tool and vulnerability scanner"
readme = "README.md"
license = { text = "BSD-3-Clause" }
authors = [
    { name = "Daniel Garcia (cr0hn)", email = "cr0hn@cr0hn.com" },
]
requires-python = ">=3.12"
keywords = ["wordpress", "security", "scanner", "vulnerability", "pentest"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Environment :: Console",
    "Intended Audience :: Information Technology",
    "License :: OSI Approved :: BSD Software License",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Topic :: Security",
]
dependencies = [
    "httpx[http2]>=0.27",
    "orjson>=3.9",
    "termcolor>=2.4",
    "tqdm>=4.65",
    # whoosh ELIMINADO → SQLite FTS5 (stdlib)
    # pluginbase ELIMINADO → importlib (stdlib)
]

[project.scripts]
plecost = "plecost.__main__:main"

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "pytest-cov>=5.0",
    "respx>=0.21",          # mock de httpx
    "mypy>=1.8",
    "ruff>=0.4",
    "pre-commit>=3.6",
]

[tool.hatch.build.targets.wheel]
packages = ["plecost"]

[tool.ruff]
target-version = "py312"
line-length = 100

[tool.ruff.lint]
select = ["E", "W", "F", "I", "B", "C4", "UP", "ASYNC", "S", "RUF"]
ignore = ["S101", "B008"]

[tool.ruff.lint.per-file-ignores]
"tests/**" = ["S", "B"]

[tool.mypy]
python_version = "3.12"
strict = true

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
addopts = "--cov=plecost --cov-report=term-missing"

[tool.coverage.run]
source = ["plecost"]
omit = ["tests/*", "_plecost/*"]
```

### 5.6 CI/CD — problemas y solución

**Problemas actuales en `.github/workflows/update-databases.yml`:**
- Usa Python 3.8 (EOL octubre 2024)
- `actions/checkout@v2` (obsoleto; actual: v4)
- `python3 -m plecost.bin.build_database` — módulo inexistente
- Usa NVD 1.1 JSON que NIST apagó en marzo 2023 — **lleva 2+ años roto**
- Sin workflow de tests, lint, ni publicación en PyPI

**CI/CD propuesto:**
```yaml
# .github/workflows/ci.yml
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v4
      - run: uv sync --dev
      - run: uv run ruff check .
      - run: uv run mypy plecost/
      - run: uv run pytest --cov

  update-db:
    # Solo en schedule, usa NVD API 2.0 con API key
    runs-on: ubuntu-latest
    env:
      NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v4
      - run: uv run python -m plecost --update-cve
```

---

## 6. Async, Performance y Python Moderno

### 6.1 Mapa de operaciones I/O y problemas

| Operación | Fichero | Async? | Problema |
|---|---|---|---|
| HTTP scan (plugins, version) | `plecost/network.py` | SÍ | Sin timeout; sin retry; Semaphore no configurable desde CLI |
| WordPress version detection | `find_wordpress_version.py` | SÍ | 3 métodos en secuencia, no paralelo |
| Plugin update (40 páginas) | `discover_wordpress_plugins.py` | NO — BLOQUEANTE | `urllib.request.urlopen()` en loop |
| CVE update (12 feeds) | `_plecost/libs/updaters/cves.py` | NO — BLOQUEANTE | `urlopen()` secuencial |
| Plugin scraping (~1190 requests) | `_plecost/libs/updaters/plugins.py` | NO — BLOQUEANTE | `urlopen()` por página, secuencial |
| Whoosh index search | `find_cve_in_wordpress_plugins.py` | NO — BLOQUEANTE | `ix.searcher()` síncrono |
| SQLite queries | `_plecost/libs/db.py` | NO | `sqlite3` síncrono |

### 6.2 Problemas críticos de async

**Singleton HTTP con concurrencia ignorada:**
```python
# plecost/network.py — SE CREA ANTES DE PARSEAR EL CLI
HTTP = _HTTP()  # concurrency=5 hardcodeado

# plecost/__main__.py — el argumento --concurrency NUNCA llega al Singleton
args = parser.parse_args()
asyncio.run(async_main(args.__dict__, plugins_config))
```
El usuario puede pasar `--concurrency 20` pero el Semaphore siempre tiene 5.

**Detección de versión secuencial cuando podría ser paralela:**
```python
# find_wordpress_version.py — 3 requests en cascada (~3-6s)
for method in range(1, total_checking_methods):
    coro = getattr(self, f"_get_wordpress_version_method_{method}")
    if ret := await coro(url):   # espera cada uno antes del siguiente
        break
```

**Operaciones bloqueantes en el event loop:**
- `urllib.request.urlopen()` en `discover_wordpress_plugins.py` y todos los updaters
- `pickle.dump(open(...))` sin `async with`
- Búsquedas Whoosh síncronas

### 6.3 Features de Python 3.10-3.12 aplicables

**`match/case` (Python 3.10+):**
```python
# Status HTTP codes
match status:
    case 200:
        return await resp.text(errors="ignore")
    case 301 | 302 | 303 | 307:
        return await self._follow_redirect(headers.get("location"))
    case 403:
        return None if not self.ignore_403 else ""
    case _:
        raise HttpError(f"Unexpected status: {status}")

# Selección de reporter
match splitext(filename)[1].lstrip("."):
    case "json": return ReporterJSON(filename)
    case "xml":  return ReporterXML(filename)
    case ext:    raise PlecostInvalidReportFormat(f"Format '{ext}' not supported")
```

**`asyncio.TaskGroup` (Python 3.11+):**
```python
# Plugin scanning con TaskGroup
async def scan_plugins(urls: list[str], concurrency: int = 10) -> list[PluginResult]:
    sem = asyncio.Semaphore(concurrency)
    results: list[PluginResult] = []
    lock = asyncio.Lock()

    async def check(url: str) -> None:
        async with sem:
            result = await _check_plugin(url)
            if result:
                async with lock:
                    results.append(result)

    async with asyncio.TaskGroup() as tg:
        for url in urls:
            tg.create_task(check(url))

    return results
```

**`asyncio.wait(FIRST_COMPLETED)` para versión WP:**
```python
# Lanzar los 3 métodos en paralelo y quedarse con el primero que responda
tasks = [asyncio.create_task(method(url)) for method in detection_methods]
done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
for task in pending:
    task.cancel()
```

**`asyncio.to_thread()` para código síncrono (Whoosh, SQLite):**
```python
async def search_cves_async(vendor: str) -> list[CVEInfo]:
    return await asyncio.to_thread(search_cves, vendor)
```

**Type hints modernos (Python 3.10+):**
```python
# Obsoleto (usando typing.*)
from typing import List, Tuple, Optional, Union
plugins: List[str]
version: Optional[str]
result: Union[str, None]
response: Tuple[int, str]

# Moderno (builtins nativos y | operator)
plugins: list[str]
version: str | None
result: str | None
response: tuple[int, str]
```

**f-strings con `=` para debugging (Python 3.8+):**
```python
Logger.debug(f"{plugin.slug=}, {method_name=}")
# Imprime: plugin.slug='contact-form-7', method_name='on_finding_wordpress'
```

**`pathlib.Path` en lugar de `os.path`:**
```python
# Obsoleto
import os.path as op
data_dir = op.abspath(op.join(op.dirname(__file__), "..", "resources"))

# Moderno
from pathlib import Path
DATA_DIR = (Path(__file__).parent / ".." / "resources").resolve()
DB_PATH = DATA_DIR / "cve.db"
```

### 6.4 Oportunidades de dataclasses y TypedDict

**`PlecostOptions` → `@dataclass`:**
```python
# Actual: 130 líneas con propiedades manuales y __kwargs
# Propuesto:
@dataclass
class PlecostOptions:
    target: str
    concurrency: int = 4
    proxy: dict[str, str] = field(default_factory=dict)
    wordlist: str | None = None
    jackass: bool = False
    # ... resto de atributos

    def __post_init__(self):
        if not self.target.startswith("http"):
            self.target = f"http://{self.target}"
```

**Pipeline results → `TypedDict`:**
```python
from typing import TypedDict

class WordpressFindingResult(TypedDict):
    installed_version: str
    latest_version: str
    is_outdated: bool

class PipelineResults(TypedDict, total=False):
    on_start_results: dict
    on_finding_wordpress_results: dict[str, WordpressFindingResult]
    on_plugin_discovery_results: dict
```

**HTTP responses → `NamedTuple`:**
```python
class HttpResponse(NamedTuple):
    status: int
    body: str

class HttpJsonResponse(NamedTuple):
    status: int
    data: dict
```

### 6.5 Arquitectura async propuesta para la capa de red

```python
# plecost/network.py — PROPUESTO con httpx y retry
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

class HTTP:
    def __init__(self, concurrency: int = 5):
        self._semaphore = asyncio.Semaphore(concurrency)
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "HTTP":
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=15.0),
            limits=httpx.Limits(max_connections=self._concurrency),
            http2=True,
            verify=False,  # para pentesting
        )
        return self

    async def __aexit__(self, *args) -> None:
        if self._client:
            await self._client.aclose()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(httpx.TransportError),
    )
    async def get(self, url: str) -> HttpResponse:
        async with self._semaphore:
            resp = await self._client.get(url)
            return HttpResponse(status=resp.status_code, body=resp.text)
```

### 6.6 Estimación de mejora de performance

| Operación | Tiempo actual | Tiempo propuesto | Mejora |
|---|---|---|---|
| Detección versión WP (3 métodos) | ~3-6s secuencial | ~1-2s paralelo | **3x** |
| Plugin scanning (50 plugins, conc=4) | ~25-50s | ~5-10s (TaskGroup) | **5x** |
| Plugin scanning (1000 plugins, conc=10) | ~500s | ~50-100s | **5-10x** |
| Update plugins (~1190 req. secuenciales) | ~30-60 min | ~3-5 min (paralelo) | **10-20x** |
| Update CVE (12 feeds secuenciales) | ~2-5 min | ~20-30s (paralelo) | **6-10x** |

---

## 7. Plan de Modernización Prioritizado

### Fase 1 — CRÍTICO: hacer que funcione en Python 3.12 (antes de cualquier otra cosa)

1. **Eliminar `_plecost/`** del repositorio activo. Archivar en branch `v1-legacy`. Todo el código de `_plecost/` es incompatible con Python 3.11+ y no puede correr en el objetivo Python 3.12.
2. **Corregir `setup.py`**: cambiar entry point `plecost_lib.__main__:main` → `plecost.__main__:main`.
3. **Eliminar `setup.cfg`** (pertenece a dnsrecon) y reemplazar con `pyproject.toml` completo (ver sección 5.5).
4. **Corregir bug de enable/disable plugins** en `plugin.py:81`.
5. **Implementar plugin scanning** en `discover_wordpress_plugins.py` (`on_plugin_found`).
6. **Implementar CVE search** en `find_cve_in_wordpress_plugins.py`.
7. **Migrar NVD updater** de JSON 1.1 (apagado) a NVD REST API 2.0.

### Fase 2 — ALTO: modernización async y performance

8. **Reemplazar `urllib.request`** por `httpx.AsyncClient` en todos los updaters y plugins.
9. **Inyectar cliente HTTP** como parámetro en los plugins (eliminar Singleton global; usar context manager `async with HTTP(...) as http`).
10. **Paralelizar detección de versión WP** con `asyncio.wait(FIRST_COMPLETED)`.
11. **Reemplazar `whoosh`** por SQLite FTS5 (stdlib) para el índice de CVEs.
12. **Reemplazar `pluginbase`** por `importlib.util` (ya implementado en `examples/load_plugins.py`).
13. **Usar `asyncio.to_thread()`** para queries SQLite y cualquier operación síncrona en el event loop.
14. **Usar `asyncio.TaskGroup`** (Python 3.11+) en el pipeline de plugins.

### Fase 3 — MEDIO: type safety y herramientas modernas

15. **Añadir type hints estrictos** a todos los módulos de `plecost/`.
16. **Convertir `PlecostOptions`** y clases legacy a `@dataclass` o `TypedDict`.
17. **Añadir `TypedDict`** para los resultados del pipeline.
18. **Configurar `mypy --strict`** y corregir todos los errores.
19. **Configurar `ruff`** (linter + formatter) y pasar toda la base de código.
20. **Añadir `pre-commit`** con hooks de ruff y mypy.

### Fase 4 — BAJO: tests, CI/CD y reporters

21. **Crear suite de tests** con `pytest` + `pytest-asyncio` + `respx` (mock de httpx).
22. **Implementar sistema de reporters** en la nueva arquitectura (plugin `on_before_stop`).
23. **Actualizar CI/CD**: Python 3.12, `actions/checkout@v4`, workflow de tests + lint.
24. **Actualizar CHANGELOG.md** con los cambios realizados.

### Resumen de cambios de dependencias

```
ELIMINAR:    whoosh, pluginbase, (aiohttp → reemplazar)
AÑADIR:      httpx[http2], tenacity, (SQLite FTS5 ya en stdlib)
ACTUALIZAR:  termcolor → >=2.4, orjson → >=3.9
DECLARAR:    aiohttp si se mantiene (actualmente sin declarar en requirements.txt)
DEV TOOLS:   ruff, mypy, pytest, pytest-asyncio, respx, pre-commit
```

---

## Ficheros Clave de Referencia

| Fichero | Descripción | Prioridad de cambio |
|---|---|---|
| `plecost/__main__.py` | CLI entry point | ALTA |
| `plecost/__run__.py` | Pipeline async principal | ALTA |
| `plecost/plugin.py` | Sistema de plugins (bug en línea 81) | CRÍTICA |
| `plecost/network.py` | Capa HTTP (Singleton problemático) | ALTA |
| `plecost/models.py` | Modelos de datos (bien, dataclasses) | BAJA |
| `plecost/core_plugins/discover_wordpress_version/find_wordpress_version.py` | Detección versión WP | MEDIA |
| `plecost/core_plugins/discover_wordpress_plugins/discover_wordpress_plugins.py` | Detección plugins (stub + urllib bloqueante) | CRÍTICA |
| `plecost/core_plugins/find_cve_in_wordpress_plugins/find_cve_in_wordpress_plugins.py` | CVE search + updater (NVD apagado) | CRÍTICA |
| `setup.py` | Entry point roto | CRÍTICA |
| `setup.cfg` | Copy-paste de dnsrecon — eliminar | CRÍTICA |
| `_plecost/` (directorio completo) | Código incompatible con Python 3.11+ | ELIMINAR |
| `.github/workflows/update-databases.yml` | Workflow roto (NVD 1.1 apagado) | CRÍTICA |
