# Complete Technical Analysis — Plecost v3.0

> Date: 2026-04-10  
> Analysts: 4 parallel agents (architecture, security, dependencies, async/performance)

---

## Table of Contents

1. [What is Plecost?](#1-what-is-plecost)
2. [Current Project State](#2-current-project-state)
3. [Architecture and Code Quality](#3-architecture-and-code-quality)
4. [Functionality and Security Capabilities](#4-functionality-and-security-capabilities)
5. [Dependencies and Packaging](#5-dependencies-and-packaging)
6. [Async, Performance and Modern Python](#6-async-performance-and-modern-python)
7. [Prioritized Modernization Plan](#7-prioritized-modernization-plan)

---

## 1. What is Plecost?

Plecost is a **passive WordPress fingerprinting scanner** (black-box). It does not exploit vulnerabilities but detects them by correlating information extracted from the target against a local CVE database. Its current capabilities are:

- Detect if a website runs WordPress
- Identify the installed WordPress core version
- Enumerate installed plugins by brute-forcing predictable paths (`/wp-content/plugins/{slug}/readme.txt`)
- Correlate versions with CVEs from NVD (National Vulnerability Database)
- Detect outdated plugins
- Export results in JSON/XML

**What it does NOT do** (relevant gaps):
- Does not detect themes
- Does not enumerate users (REST API `/wp-json/wp/v2/users`)
- Does not check `xmlrpc.php` (an empty file exists as a placeholder)
- Does not detect WAF/CDN
- Does not use proxy/Tor
- Has no stealth techniques (it is noisy by design)

---

## 2. Current Project State

### The central problem: two coexisting and incomplete versions

The repository contains **two incompatible parallel implementations**:

| | `_plecost/` (legacy) | `plecost/` (new) |
|---|---|---|
| Version | 1.1.2 | 3.0.0 |
| Python compatible | 3.3 – 3.10 | 3.9+ |
| Async API | `@asyncio.coroutine` + `yield from` (REMOVED in Python 3.11) | real `async/await` |
| Status | Functional (on Python ≤3.10), complete | ~30% implemented, incomplete |
| Plugin scanning | Implemented and functional | Stub (`...`) not implemented |
| CVE search | Functional (SQLite) | `print("load")` not implemented |
| Reporters | JSON + XML | Not implemented |

**Conclusion**: The new version (`plecost/`) has a better architecture but cannot complete a full scan. The old version (`_plecost/`) works but is incompatible with Python 3.11+.

### Critical immediate issues

1. **Broken entry point in `setup.py`**: points to `plecost_lib.__main__:main`, a package that does not exist.
2. **`setup.cfg` belongs to another project** (`dnsrecon` by Carlos Perez) — accidental copy-paste.
3. **Broken CI/CD workflow**: uses NVD API 1.1 JSON that NIST shut down in March 2023. The database cannot be updated.
4. **Logic bug in `plugin.py:81`**: the `--enable-plugin` filter works in reverse (uses `disable_plugins` instead of `only_enable_plugins`).

---

## 3. Architecture and Code Quality

### 3.1 Project structure

```
/src/
├── setup.py                   ← BROKEN: entry point points to non-existent package
├── setup.cfg                  ← WRONG: belongs to dnsrecon, not plecost
├── requirements.txt           ← Minimal, no pinned versions
├── VERSION                    ← "3.0.0"
├── CHANGELOG.md               ← Outdated (stopped in 2017, v1.1.2)
├── devel.rst                  ← Plugin system v3 documentation
│
├── _plecost/                  ← LEGACY v1.1.2 — incompatible with Python 3.11+
│   ├── __main__.py            ← Legacy CLI: argparse + synchronous run()
│   ├── api.py                 ← Legacy entry point
│   └── libs/
│       ├── data.py            ← Models: PlecostOptions (god class, 130 lines boilerplate)
│       ├── db.py              ← SQLite: mixes DAO + business logic + presentation
│       ├── helpers.py         ← is_remote_a_wordpress(), get_wordpress_version()
│       ├── plugins_utils.py   ← Plugin detection + logic + UI mixed together
│       ├── reporters.py       ← Reporter ABC + JSON + XML (functional)
│       ├── utils.py           ← download(), ConcurrentDownloader, log()
│       ├── versions.py        ← find_versions(): God function of 170 lines
│       ├── wordlist.py        ← Wordlist handling
│       └── updaters/
│           ├── cves.py        ← Downloads NVD XML (deprecated), parses, saves to SQLite
│           └── plugins.py     ← Scrapes wordpress.org (probably broken)
│
├── plecost/                   ← NEW v3.0.0 — correct architecture, 30% implemented
│   ├── __main__.py            ← CLI v3: argparse + asyncio.run()
│   ├── __run__.py             ← async_main(): plugin pipeline
│   ├── models.py              ← WordpressVersion, PlecostRunningOptions (dataclasses)
│   ├── network.py             ← _HTTP(Singleton) with aiohttp
│   ├── plugin.py              ← discover_plugins(), find_plugins(), PlecostPluginsConfig
│   ├── logger.py              ← _Logger(Singleton)
│   ├── interfaces.py          ← Singleton, Serializable, MetaMongo
│   └── core_plugins/
│       ├── discover_wordpress_version/    ← IMPLEMENTED (works)
│       ├── discover_wordpress_plugins/    ← STUB: on_plugin_found = ...
│       └── find_cve_in_wordpress_plugins/ ← STUB: on_start only does print("load")
│
├── plecost_cve_database/      ← Whoosh indexes (obsolete database, July 2021)
└── examples/
    ├── load_plugins.py        ← Plugin system demo using pure importlib
    └── plugins/demo_plugin_*.py
```

### 3.2 Identified design patterns

**Present (in `plecost/`):**
- **Singleton**: `_HTTP` and `_Logger` — metaclass implementation. Problem: not injectable, instantiated at module level, impossible to mock.
- **Plugin/Hook System**: pipeline with ordered phases (`001..005`) and dynamic discovery. Well designed, poorly implemented.
- **Template Method**: `Reporter` ABC in v1 with abstract `generate()` and `save()`.
- **Data Transfer Object**: `PlecostRunningOptions`, `WordpressVersion` as `@dataclass`.

**Absent or misapplied:**
- No **Dependency Injection**: everything accessed via global singletons.
- No **Repository Pattern**: the DB mixes queries, business logic and presentation.
- The global singleton `HTTP = _HTTP()` instantiated before CLI parsing causes `--concurrency` to be ignored.

### 3.3 Specific technical debt by priority

#### CRITICAL — Break on Python 3.11+

| Problem | File:Line | Solution |
|---|---|---|
| `@asyncio.coroutine` + `yield from` | `_plecost/libs/utils.py:225,369,405`, `helpers.py:60,136`, `plugins_utils.py:213` | Rewrite with `async/await` or remove `_plecost/` |
| `asyncio.Queue(loop=self.loop)` | `_plecost/libs/utils.py:359` | Remove `loop` argument |
| `asyncio.Task(..., loop=loop)` | `_plecost/libs/utils.py:412` | Remove `loop` argument |
| `aiohttp.Timeout(5)` | `_plecost/libs/utils.py:268` | Use `asyncio.timeout(5)` |
| `aiohttp.ClientSession(loop=loop)` | `_plecost/libs/versions.py:106` | Remove `loop` argument |
| `aiohttp.TCPConnector(verify_ssl=False)` | `_plecost/libs/versions.py:105` | Change to `ssl=False` |
| `open(..., "rU")` | `_plecost/libs/wordlist.py:84`, `versions.py:197` | Change to `open(..., "r", newline=None)` |

#### HIGH — Serious bugs and anti-patterns

| Problem | File:Line | Detail |
|---|---|---|
| Bug enable/disable plugins | `plecost/plugin.py:81` | `klass.slug not in disable_plugins` should be `not in only_enable_plugins` |
| `is` with string literal | `_plecost/libs/helpers.py:299` | `current_version is "unknown"` — use `==` |
| `pickle` for data | `discover_wordpress_plugins.py:65-69` | Attack vector; replace with JSON |
| `except Exception: pass` | `find_wordpress_version.py:100-101` | Silenced errors |
| `open()` without `with` | `find_cve_in_wordpress_plugins.py:61`, `reporters.py` | File descriptor leak |
| `NotImplemented` vs `NotImplementedError` | `_plecost/libs/reporters.py:99,107` | `raise NotImplemented()` is semantically wrong |
| `type(v) is dict` | `__run__.py:82` | Use `isinstance(v, dict)` |
| Description `"asdfas"` | `discover_wordpress_plugins.py:26` | Placeholder in production code |

#### MEDIUM — Quality and maintainability

- `PlecostOptions` in `_plecost/libs/data.py`: 130-line class replaceable with `@dataclass`.
- `find_versions()` in `_plecost/libs/versions.py`: God function of 170 lines (HTTP + detection + plugins + reporting mixed together).
- Business logic mixed with presentation (`log()` inside analysis functions).
- Global state via `environ["PLECOST_LOG_LEVEL"]` — impossible to run concurrent tests.
- Duplicated code: `banner()`, `find_plugins()`, WP version regexes, etc.
- NVD 2.0 XML deprecated in 2022 — migrate to NVD REST API 2.0.

### 3.4 Testability: 2/10

- No tests exist (no `tests/`, no `pytest.ini`, no `conftest.py`).
- Module-level singletons require invasive monkey-patching.
- Mixed presentation/logic prevents mocking I/O without touching logic.
- `pipeline_results` as free `**kwargs` makes it impossible to verify contracts between stages.

---

## 4. Functionality and Security Capabilities

### 4.1 Complete detection flow (legacy version — the one that works)

```
1. HEAD/GET target → verify availability
2. Detect redirects (301/302/303/307) → follow
3. GET random URL → error page fingerprint
4. Detect WordPress (85% of typical URLs must exist):
   - /wp-includes/js/jquery/jquery.js, /wp-includes/js/wp-lists.js, etc.
   - Fallback: /wp-admin/ redirect, /wp-content/ in HTML links
5. Get WP version (3 cascading methods):
   - Method 1: GET /readme.html → regex "Version X.X.X"
   - Method 2: GET / → regex <meta name="generator" content="WordPress X.X">
   - Method 3: ?ver= in CSS/JS links
   - Fallback: /wp-login.php, /wp-admin/css/wp-admin.css
6. Query core CVEs in local SQLite
7. Test wordlist plugins in parallel (configurable concurrency):
   - URLs: /wp-content/plugins/{slug}/readme.txt and README.txt
   - Parse "Stable tag: X.X.X"
   - Status 403 → plugin exists (unknown version)
   - Filter false positives: similarity ratio with error page < 0.52
8. For each plugin found: query CVEs in SQLite
```

### 4.2 Included wordlists

| File | Plugins |
|---|---|
| `plugin_list_10.txt` | 10 (quick testing) |
| `plugin_list_50.txt` | 50 most popular (default) |
| `plugin_list_100.txt` | 100 |
| `plugin_list_250.txt` | 250 |
| `plugin_list_1000.txt` | 999 |
| `plugin_list_huge.txt` | 1176 |

Top plugins included: Contact Form 7, Akismet, Yoast SEO, Jetpack, WooCommerce, Wordfence, W3 Total Cache.

### 4.3 CVE database

**Legacy (`_plecost/`) — SQLite with FTS4:**
- Source: NVD XML feeds 2.0 (DEPRECATED — NIST shut them down in 2022)
- Filters CPE with `~~~wordpress~~` or `:wordpress:`
- Automatically generates earlier vulnerable versions
- Fuzzy search with `difflib.SequenceMatcher` (threshold > 0.8 version, > 0.9 name)
- Only reports if installed version <= vulnerable version in DB

**New (`plecost/`) — Whoosh:**
- Source: NVD JSON 1.1 feeds (DEPRECATED — NIST shut them down in March 2023)
- Stores: CVE ID, description, CVSS v3/v2, CPE, version ranges
- Current database in the repo: **July 2021** (cannot be updated with current code)

### 4.4 Network capabilities

- `aiohttp` with semaphore per hostname (configurable concurrency)
- SSL verification disabled (`verify_ssl=False`)
- Timeout: 5 seconds hardcoded (legacy)
- No timeout configured in new version
- No retry logic
- No proxy/Tor
- No User-Agent rotation
- No delays between requests
- "jackass" mode: concurrency = 9999 (maximum noise)

### 4.5 Output format

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

**New version**: no reporter system implemented.

### 4.6 Functionality gaps

| Gap | Priority | Notes |
|---|---|---|
| CVE database cannot be updated | CRITICAL | NVD 1.1 JSON shut down in 2023; migrate to NVD API 2.0 |
| Plugin scanning not implemented in v3 | CRITICAL | `on_plugin_found = ...` in core plugin |
| CVE search not implemented in v3 | CRITICAL | Only `print("load")` |
| No theme detection | HIGH | Same technique applicable to `/wp-content/themes/` |
| No user enumeration | HIGH | REST API `/wp-json/wp/v2/users` trivial to implement |
| No xmlrpc.php check | HIGH | File exists but is empty |
| No proxy support | MEDIUM | Option commented out in code |
| No WAF detection | MEDIUM | — |
| No authentication (scan of private areas) | LOW | — |

---

## 5. Dependencies and Packaging

### 5.1 Current dependency inventory

| Dependency | Pinned version | Status | Verdict |
|---|---|---|---|
| `whoosh` | none | Abandoned since 2016 (9 years without releases) | REMOVE |
| `pluginbase` | none | Semi-abandoned (4 years without updates) | REMOVE |
| `tqdm` | none | Active (v4.67.1 available) | KEEP if used |
| `orjson` | none | Active (v3.11.7) | KEEP |
| `termcolor` | none | Installed v1.1.0 (2013), available v3.3.0 | UPDATE |
| `aiohttp` | **not declared** | Used but not in requirements.txt | DECLARE |

### 5.2 Replacement plan

| Current | Replacement | Justification |
|---|---|---|
| `whoosh` | SQLite FTS5 (stdlib) | No extra dependencies; `sqlite3` already in stdlib |
| `pluginbase` | `importlib.util` (stdlib) | Already demonstrated in `examples/load_plugins.py` |
| `termcolor` 1.1.0 | `termcolor>=2.4` or `rich` | `rich` is the modern standard for CLIs |
| `urllib.request` (in code) | `httpx[http2]` | Modern API, sync+async, complete type hints |
| `aiohttp` | `httpx` or keep `aiohttp>=3.9` | httpx more modern; aiohttp valid if declared |
| NVD XML/JSON 1.1 | NVD REST API 2.0 | The 1.1 feeds are shut down |
| `pickle` (plugins.bin) | JSON or SQLite | Security and portability |

### 5.3 Python 3.12 stdlib dependencies replacing packages

- `importlib.util` → replaces `pluginbase`
- `sqlite3` with FTS5 → replaces `whoosh`
- `asyncio.timeout()` → replaces `aiohttp.Timeout`
- `pathlib.Path` → replaces `os.path` (already in stdlib, just modernize usage)

### 5.4 Removed Python APIs that affect the code

| Removed API | Python version | Affects |
|---|---|---|
| `asyncio.coroutine` decorator | Python 3.11 | All files in `_plecost/libs/` |
| `yield from` in coroutines | Python 3.11 | Same |
| `loop=` parameter in asyncio primitives | Python 3.10 | `asyncio.Queue`, `asyncio.Task` |
| `open(..., "rU")` universal newlines mode | Python 3.11 | `wordlist.py`, `versions.py` |
| `aiohttp.Timeout` | aiohttp 3.x | `utils.py` |
| `aiohttp.ClientSession(loop=loop)` | aiohttp 4+ | `versions.py` |
| `aiohttp.TCPConnector(verify_ssl=...)` | recent aiohttp | `versions.py` |

### 5.5 Proposed pyproject.toml (complete)

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

### 5.6 CI/CD — problems and solution

**Current issues in `.github/workflows/update-databases.yml`:**
- Uses Python 3.8 (EOL October 2024)
- `actions/checkout@v2` (obsolete; current: v4)
- `python3 -m plecost.bin.build_database` — non-existent module
- Uses NVD 1.1 JSON that NIST shut down in March 2023 — **broken for 2+ years**
- No test, lint or PyPI publishing workflow

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

## 6. Async, Performance and Modern Python

### 6.1 I/O operations map and issues

| Operation | File | Async? | Problem |
|---|---|---|---|
| HTTP scan (plugins, version) | `plecost/network.py` | YES | No timeout; no retry; Semaphore not configurable from CLI |
| WordPress version detection | `find_wordpress_version.py` | YES | 3 methods sequentially, not in parallel |
| Plugin update (40 pages) | `discover_wordpress_plugins.py` | NO — BLOCKING | `urllib.request.urlopen()` in loop |
| CVE update (12 feeds) | `_plecost/libs/updaters/cves.py` | NO — BLOCKING | `urlopen()` sequential |
| Plugin scraping (~1190 requests) | `_plecost/libs/updaters/plugins.py` | NO — BLOCKING | `urlopen()` per page, sequential |
| Whoosh index search | `find_cve_in_wordpress_plugins.py` | NO — BLOCKING | synchronous `ix.searcher()` |
| SQLite queries | `_plecost/libs/db.py` | NO | synchronous `sqlite3` |

### 6.2 Critical async issues

**HTTP Singleton with ignored concurrency:**
```python
# plecost/network.py — CREATED BEFORE CLI IS PARSED
HTTP = _HTTP()  # concurrency=5 hardcoded

# plecost/__main__.py — --concurrency argument NEVER reaches the Singleton
args = parser.parse_args()
asyncio.run(async_main(args.__dict__, plugins_config))
```
The user can pass `--concurrency 20` but the Semaphore always has 5.

**Sequential version detection when it could be parallel:**
```python
# find_wordpress_version.py — 3 cascading requests (~3-6s)
for method in range(1, total_checking_methods):
    coro = getattr(self, f"_get_wordpress_version_method_{method}")
    if ret := await coro(url):   # waits for each one before the next
        break
```

**Blocking operations in the event loop:**
- `urllib.request.urlopen()` in `discover_wordpress_plugins.py` and all updaters
- `pickle.dump(open(...))` without `async with`
- Synchronous Whoosh searches

### 6.3 Applicable Python 3.10-3.12 features

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

# Reporter selection
match splitext(filename)[1].lstrip("."):
    case "json": return ReporterJSON(filename)
    case "xml":  return ReporterXML(filename)
    case ext:    raise PlecostInvalidReportFormat(f"Format '{ext}' not supported")
```

**`asyncio.TaskGroup` (Python 3.11+):**
```python
# Plugin scanning with TaskGroup
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

**`asyncio.wait(FIRST_COMPLETED)` for WP version:**
```python
# Launch all 3 methods in parallel and use whichever responds first
tasks = [asyncio.create_task(method(url)) for method in detection_methods]
done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
for task in pending:
    task.cancel()
```

**`asyncio.to_thread()` for synchronous code (Whoosh, SQLite):**
```python
async def search_cves_async(vendor: str) -> list[CVEInfo]:
    return await asyncio.to_thread(search_cves, vendor)
```

**Modern type hints (Python 3.10+):**
```python
# Obsolete (using typing.*)
from typing import List, Tuple, Optional, Union
plugins: List[str]
version: Optional[str]
result: Union[str, None]
response: Tuple[int, str]

# Modern (native builtins and | operator)
plugins: list[str]
version: str | None
result: str | None
response: tuple[int, str]
```

**f-strings with `=` for debugging (Python 3.8+):**
```python
Logger.debug(f"{plugin.slug=}, {method_name=}")
# Prints: plugin.slug='contact-form-7', method_name='on_finding_wordpress'
```

**`pathlib.Path` instead of `os.path`:**
```python
# Obsoleto
import os.path as op
data_dir = op.abspath(op.join(op.dirname(__file__), "..", "resources"))

# Moderno
from pathlib import Path
DATA_DIR = (Path(__file__).parent / ".." / "resources").resolve()
DB_PATH = DATA_DIR / "cve.db"
```

### 6.4 Dataclass and TypedDict opportunities

**`PlecostOptions` → `@dataclass`:**
```python
# Current: 130 lines with manual properties and __kwargs
# Proposed:
@dataclass
class PlecostOptions:
    target: str
    concurrency: int = 4
    proxy: dict[str, str] = field(default_factory=dict)
    wordlist: str | None = None
    jackass: bool = False
    # ... remaining attributes

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

### 6.5 Proposed async architecture for the network layer

```python
# plecost/network.py — PROPOSED with httpx and retry
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
            verify=False,  # for pentesting
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

### 6.6 Performance improvement estimate

| Operation | Current time | Proposed time | Improvement |
|---|---|---|---|
| WP version detection (3 methods) | ~3-6s sequential | ~1-2s parallel | **3x** |
| Plugin scanning (50 plugins, conc=4) | ~25-50s | ~5-10s (TaskGroup) | **5x** |
| Plugin scanning (1000 plugins, conc=10) | ~500s | ~50-100s | **5-10x** |
| Update plugins (~1190 sequential req.) | ~30-60 min | ~3-5 min (parallel) | **10-20x** |
| Update CVE (12 sequential feeds) | ~2-5 min | ~20-30s (parallel) | **6-10x** |

---

## 7. Prioritized Modernization Plan

### Phase 1 — CRITICAL: make it work on Python 3.12 (before anything else)

1. **Remove `_plecost/`** from the active repository. Archive in branch `v1-legacy`. All `_plecost/` code is incompatible with Python 3.11+ and cannot run on the target Python 3.12.
2. **Fix `setup.py`**: change entry point `plecost_lib.__main__:main` → `plecost.__main__:main`.
3. **Remove `setup.cfg`** (belongs to dnsrecon) and replace with complete `pyproject.toml` (see section 5.5).
4. **Fix the enable/disable plugins bug** in `plugin.py:81`.
5. **Implement plugin scanning** in `discover_wordpress_plugins.py` (`on_plugin_found`).
6. **Implement CVE search** in `find_cve_in_wordpress_plugins.py`.
7. **Migrate the NVD updater** from JSON 1.1 (shut down) to NVD REST API 2.0.

### Phase 2 — HIGH: async modernization and performance

8. **Replace `urllib.request`** with `httpx.AsyncClient` in all updaters and plugins.
9. **Inject the HTTP client** as a parameter in plugins (remove global Singleton; use context manager `async with HTTP(...) as http`).
10. **Parallelize WP version detection** with `asyncio.wait(FIRST_COMPLETED)`.
11. **Replace `whoosh`** with SQLite FTS5 (stdlib) for the CVE index.
12. **Replace `pluginbase`** with `importlib.util` (already implemented in `examples/load_plugins.py`).
13. **Use `asyncio.to_thread()`** for SQLite queries and any synchronous operation in the event loop.
14. **Use `asyncio.TaskGroup`** (Python 3.11+) in the plugin pipeline.

### Phase 3 — MEDIUM: type safety and modern tooling

15. **Add strict type hints** to all modules in `plecost/`.
16. **Convert `PlecostOptions`** and legacy classes to `@dataclass` or `TypedDict`.
17. **Add `TypedDict`** for pipeline results.
18. **Configure `mypy --strict`** and fix all errors.
19. **Configure `ruff`** (linter + formatter) and apply across the entire codebase.
20. **Add `pre-commit`** with ruff and mypy hooks.

### Phase 4 — LOW: tests, CI/CD and reporters

21. **Create test suite** with `pytest` + `pytest-asyncio` + `respx` (httpx mock).
22. **Implement reporter system** in the new architecture (plugin `on_before_stop`).
23. **Update CI/CD**: Python 3.12, `actions/checkout@v4`, tests + lint workflow.
24. **Update CHANGELOG.md** with the changes made.

### Dependency change summary

```
REMOVE:   whoosh, pluginbase, (aiohttp → replace)
ADD:      httpx[http2], tenacity, (SQLite FTS5 already in stdlib)
UPDATE:   termcolor → >=2.4, orjson → >=3.9
DECLARE:  aiohttp if kept (currently undeclared in requirements.txt)
DEV TOOLS: ruff, mypy, pytest, pytest-asyncio, respx, pre-commit
```

---

## Key Reference Files

| File | Description | Change priority |
|---|---|---|
| `plecost/__main__.py` | CLI entry point | HIGH |
| `plecost/__run__.py` | Main async pipeline | HIGH |
| `plecost/plugin.py` | Plugin system (bug at line 81) | CRITICAL |
| `plecost/network.py` | HTTP layer (problematic Singleton) | HIGH |
| `plecost/models.py` | Data models (good, dataclasses) | LOW |
| `plecost/core_plugins/discover_wordpress_version/find_wordpress_version.py` | WP version detection | MEDIUM |
| `plecost/core_plugins/discover_wordpress_plugins/discover_wordpress_plugins.py` | Plugin detection (stub + blocking urllib) | CRITICAL |
| `plecost/core_plugins/find_cve_in_wordpress_plugins/find_cve_in_wordpress_plugins.py` | CVE search + updater (NVD shut down) | CRITICAL |
| `setup.py` | Broken entry point | CRITICAL |
| `setup.cfg` | Copy-paste from dnsrecon — remove | CRITICAL |
| `_plecost/` (full directory) | Code incompatible with Python 3.11+ | REMOVE |
| `.github/workflows/update-databases.yml` | Broken workflow (NVD 1.1 shut down) | CRITICAL |
