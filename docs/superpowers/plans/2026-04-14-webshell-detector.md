# Webshell Detector Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `webshells` detection module to plecost that finds PHP webshells on WordPress sites via remote HTTP probing, with optional deeper checks when WordPress admin credentials are provided.

**Architecture:** A single `webshells` ScanModule that internally runs 6 independent `BaseDetector` subclasses in parallel via `asyncio.gather`. Four detectors run without credentials (black-box), two require WordPress admin credentials. The module lives in a subpackage `plecost/modules/webshells/` to keep concerns separated at scale.

**Tech Stack:** Python 3.11+, httpx (already in project), respx (tests), asyncio, hashlib (stdlib). No new dependencies.

---

## Context for the Implementer

Read `plecost/CLAUDE.md` before starting — it covers all project conventions. Key points:

- `ScanOptions.credentials: tuple[str, str] | None` — NOT separate `user`/`password` fields
- `ctx.url` is already `opts.url.rstrip("/")` — no need to strip yourself
- Tests: `asyncio_mode = "auto"` — do NOT add `@pytest.mark.asyncio`
- respx: `respx.get(url).mock(...)` NOT `respx.pattern(...)`; use `respx.route(url__regex=r".*").mock(...)` as catch-all
- Finding ID format: `PC-WSH-NNN` where NNN is exactly 3 digits (enforced by contract test)
- Run tests with `python3 -m pytest` not bare `pytest`
- Credentials check in modules: `if not ctx.opts.credentials: return`

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `plecost/modules/webshells/__init__.py` | Create | Exports `WebshellsModule` |
| `plecost/modules/webshells/base.py` | Create | `BaseDetector` ABC |
| `plecost/modules/webshells/wordlists.py` | Create | All embedded wordlists |
| `plecost/modules/webshells/module.py` | Create | `WebshellsModule(ScanModule)` |
| `plecost/modules/webshells/detectors/__init__.py` | Create | Empty |
| `plecost/modules/webshells/detectors/known_paths.py` | Create | `KnownPathsDetector` |
| `plecost/modules/webshells/detectors/uploads_php.py` | Create | `UploadsPhpDetector` |
| `plecost/modules/webshells/detectors/mu_plugins.py` | Create | `MuPluginsDetector` |
| `plecost/modules/webshells/detectors/response_fp.py` | Create | `ResponseFingerprintDetector` |
| `plecost/modules/webshells/detectors/checksums.py` | Create | `ChecksumsDetector` |
| `plecost/modules/webshells/detectors/fake_plugins.py` | Create | `FakePluginRestDetector` |
| `plecost/scanner.py` | Modify | Register `WebshellsModule` |
| `plecost/cli.py` | Modify | Add to `_ALL_MODULE_NAMES` + `_FINDINGS_REGISTRY` |
| `tests/contract/test_finding_ids.py` | Modify | Add `PC-WSH-*` IDs |
| `tests/unit/test_module_webshells_known_paths.py` | Create | Tests for `KnownPathsDetector` |
| `tests/unit/test_module_webshells_uploads.py` | Create | Tests for `UploadsPhpDetector` |
| `tests/unit/test_module_webshells_mu_plugins.py` | Create | Tests for `MuPluginsDetector` |
| `tests/unit/test_module_webshells_response_fp.py` | Create | Tests for `ResponseFingerprintDetector` |
| `tests/unit/test_module_webshells_checksums.py` | Create | Tests for `ChecksumsDetector` |
| `tests/unit/test_module_webshells_fake_plugins.py` | Create | Tests for `FakePluginRestDetector` |
| `tests/unit/test_module_webshells_module.py` | Create | Integration test for `WebshellsModule` |
| `CHANGELOG.md` | Modify | Document new module |

---

## Task 0: Base Infrastructure

**Files:**
- Create: `plecost/modules/webshells/__init__.py`
- Create: `plecost/modules/webshells/base.py`
- Create: `plecost/modules/webshells/wordlists.py`
- Create: `plecost/modules/webshells/detectors/__init__.py`

- [ ] **Step 1: Create the package skeleton**

```bash
mkdir -p plecost/modules/webshells/detectors
touch plecost/modules/webshells/__init__.py
touch plecost/modules/webshells/detectors/__init__.py
```

- [ ] **Step 2: Write `plecost/modules/webshells/base.py`**

```python
from __future__ import annotations
from abc import ABC, abstractmethod
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding


class BaseDetector(ABC):
    """Base class for all webshell detection strategies."""

    name: str = ""
    requires_auth: bool = False

    @abstractmethod
    async def detect(
        self, ctx: ScanContext, http: PlecostHTTPClient
    ) -> list[Finding]: ...
```

- [ ] **Step 3: Write `plecost/modules/webshells/wordlists.py`**

```python
from __future__ import annotations
from datetime import date

# ── Common webshell filenames (families: c99, r57, WSO, b374k, P.A.S., Alfa, Godzilla)
WEBSHELL_FILENAMES_CORE: list[str] = [
    # Direct names
    "c99.php", "c99shell.php", "r57.php", "r57shell.php",
    "wso.php", "b374k.php", "alfa.php", "shell.php", "cmd.php",
    "webshell.php", "backdoor.php", "indoxploit.php", "pas.php",
    # Camouflage — imitating WP/generic files
    "cache.php", "settings.php", "config.php", "update.php",
    "install.php", "error.php", "maintenance.php", "css.php",
    "style.php", "functions.php", "license.php", "readme.php",
    # Upload-themed names
    "image.php", "img.php", "upload.php", "file.php", "thumb.php",
    # Short/random names common in automated attacks
    "1.php", "2.php", "x.php", "a.php", "z.php",
    # WordPress-impersonating names
    "wp.php", "wp-tmp.php", "wp-feed.php", "wp-core.php",
    "wp-cache.php", "wp-debug.php", "wp-backup.php",
]

WEBSHELL_FILENAMES_EXTENDED: list[str] = WEBSHELL_FILENAMES_CORE + [
    "tool.php", "tools.php", "manager.php", "admin.php", "panel.php",
    "console.php", "terminal.php", "exec.php", "run.php", "system.php",
    "sh.php", "php.php", "info.php", "test.php", "tmp.php",
    "temp.php", "old.php", "new.php", "bk.php", "log.php",
    "cgi.php", "pass.php", "db.php", "sql.php", "wp-load.php",
    "wp-user.php", "wp-post.php", "wp-admin.php", "wp-conf.php",
    "index2.php", "index3.php", "wp2.php",
]

_WEBSHELL_DIRS_CORE: list[str] = [
    "/wp-content/uploads/",
    "/wp-content/mu-plugins/",
    "/wp-includes/css/",
    "/wp-includes/images/",
    "/wp-admin/css/",
    "/wp-admin/includes/",
    "/",
]

# All combinations of dirs × filenames
WEBSHELL_PATHS_CORE: list[str] = [
    d + name
    for d in _WEBSHELL_DIRS_CORE
    for name in WEBSHELL_FILENAMES_CORE
]

WEBSHELL_PATHS_EXTENDED: list[str] = [
    d + name
    for d in _WEBSHELL_DIRS_CORE
    for name in WEBSHELL_FILENAMES_EXTENDED
] + [
    # Specific known paths seen in real attacks
    "/wp-content/plugins/blnmrpb/index.php",
    "/wp-content/plugins/akismet/index2.php",
    "/wp-content/uploads/wflogs/rules.php",
    "/wp-content/uploads/gravity_forms/shell.php",
    "/wp-includes/pomo/index.php",
]

# ── Filenames probed in wp-content/uploads/ (with year/month paths)
UPLOADS_PHP_NAMES: list[str] = [
    "c99.php", "r57.php", "wso.php", "shell.php", "cmd.php",
    "backdoor.php", "upload.php", "file.php", "image.php",
    "img.php", "cache.php", "wp.php", "1.php", "x.php",
    "alfa.php", "webshell.php", "b374k.php", "config.php",
    "update.php", "thumb.php", "functions.php",
]

def _uploads_paths() -> list[str]:
    """Generate year/month upload paths from 2020 to current year."""
    paths: list[str] = []
    current_year = date.today().year
    for year in range(2020, current_year + 1):
        for month in range(1, 13):
            prefix = f"/wp-content/uploads/{year}/{month:02d}/"
            for name in UPLOADS_PHP_NAMES:
                paths.append(prefix + name)
    # Also probe root of uploads
    for name in UPLOADS_PHP_NAMES:
        paths.append("/wp-content/uploads/" + name)
    return paths

UPLOADS_PROBE_PATHS: list[str] = _uploads_paths()

# ── Filenames probed in mu-plugins (seen in real attacks 2024-2025, Sucuri research)
MU_PLUGINS_NAMES: list[str] = [
    "index.php", "redirect.php", "custom-js-loader.php",
    "loader.php", "wp-plugin.php", "cache.php", "update.php",
    "maintenance.php", "autoload.php", "init.php", "bootstrap.php",
    "hook.php", "filter.php", "security.php", "admin.php",
    "db.php", "object-cache.php", "advanced-cache.php",
    "plugin.php", "load.php", "wp-cache.php", "wp.php",
    "functions.php", "config.php", "settings.php",
]

# ── WordPress core files to verify via checksums API
WP_CORE_FILES_TO_CHECK: list[str] = [
    "wp-login.php",
    "wp-includes/functions.php",
    "wp-includes/class-wp-hook.php",
    "wp-includes/plugin.php",
    "wp-includes/load.php",
    "wp-admin/includes/plugin.php",
    "wp-settings.php",
    "index.php",
    "wp-blog-header.php",
    "xmlrpc.php",
    "wp-cron.php",
    "wp-includes/ms-functions.php",
    "wp-includes/class-wp-error.php",
    "wp-includes/capabilities.php",
    "wp-includes/user.php",
    "wp-admin/admin.php",
    "wp-admin/admin-ajax.php",
    "wp-admin/admin-post.php",
    "wp-admin/includes/misc.php",
    "wp-admin/includes/file.php",
]
```

- [ ] **Step 4: Verify files exist**

```bash
python3 -c "from plecost.modules.webshells.wordlists import WEBSHELL_PATHS_CORE, UPLOADS_PROBE_PATHS, MU_PLUGINS_NAMES; print(len(WEBSHELL_PATHS_CORE), 'core paths,', len(UPLOADS_PROBE_PATHS), 'upload paths')"
```

Expected output contains two numbers greater than 100 and 1000 respectively.

- [ ] **Step 5: Commit**

```bash
git add plecost/modules/webshells/ 
git commit --author="Dani <cr0hn@cr0hn.com>" -m "feat(webshells): add module skeleton, BaseDetector, and wordlists"
```

---

## Task 1: KnownPathsDetector

**Files:**
- Create: `plecost/modules/webshells/detectors/known_paths.py`
- Create: `tests/unit/test_module_webshells_known_paths.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_module_webshells_known_paths.py`:

```python
import pytest
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Severity
from plecost.modules.webshells.detectors.known_paths import KnownPathsDetector


@pytest.fixture
def ctx():
    c = ScanContext(ScanOptions(url="https://example.com"))
    c.is_wordpress = True
    return c


async def test_reports_finding_when_known_path_returns_200(ctx):
    """A known webshell path returning 200 with text/html must emit PC-WSH-001."""
    async with respx.mock:
        # Preflight: random path returns 404 (not a catch-all site)
        respx.get("https://example.com/plecost-probe-nonexistent.php").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://example.com/wp-content/uploads/shell.php").mock(
            return_value=httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text="<html>shell output</html>",
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            detector = KnownPathsDetector()
            findings = await detector.detect(ctx, http)
    assert any(f.id == "PC-WSH-001" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


async def test_no_finding_when_all_paths_404(ctx):
    """No findings if all probed paths return 404."""
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            detector = KnownPathsDetector()
            findings = await detector.detect(ctx, http)
    assert findings == []


async def test_no_finding_on_image_content_type(ctx):
    """A known path returning 200 with image/jpeg must NOT emit a finding (FP guard)."""
    async with respx.mock:
        respx.get("https://example.com/plecost-probe-nonexistent.php").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://example.com/wp-content/uploads/shell.php").mock(
            return_value=httpx.Response(
                200,
                headers={"content-type": "image/jpeg"},
                content=b"\xff\xd8\xff",
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            detector = KnownPathsDetector()
            findings = await detector.detect(ctx, http)
    assert findings == []


async def test_skips_when_catch_all_site(ctx):
    """If the site returns 200 for all paths (catch-all), skip to avoid mass FPs."""
    async with respx.mock:
        # Preflight returns 200 — catch-all site
        respx.get("https://example.com/plecost-probe-nonexistent.php").mock(
            return_value=httpx.Response(200, text="<html>404 page</html>")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200, text="page"))
        async with PlecostHTTPClient(ctx.opts) as http:
            detector = KnownPathsDetector()
            findings = await detector.detect(ctx, http)
    assert findings == []
```

- [ ] **Step 2: Run to verify it fails**

```bash
python3 -m pytest tests/unit/test_module_webshells_known_paths.py -v
```

Expected: `ImportError` or `ModuleNotFoundError` — the detector doesn't exist yet.

- [ ] **Step 3: Implement `plecost/modules/webshells/detectors/known_paths.py`**

```python
from __future__ import annotations
import asyncio
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.webshells.base import BaseDetector
from plecost.modules.webshells.wordlists import WEBSHELL_PATHS_CORE, WEBSHELL_PATHS_EXTENDED

_ALLOWED_CONTENT_TYPES = {"text/html", "text/plain", "application/x-httpd-php"}
_PREFLIGHT_PATH = "/plecost-probe-nonexistent.php"


class KnownPathsDetector(BaseDetector):
    """
    Probes known webshell filenames in common WordPress directories.
    Uses --module-option webshells:wordlist=extended for the larger wordlist.
    """

    name = "known_paths"
    requires_auth = False

    async def detect(
        self, ctx: ScanContext, http: PlecostHTTPClient
    ) -> list[Finding]:
        # Preflight: detect catch-all sites (return 200 for everything)
        try:
            r = await http.get(ctx.url + _PREFLIGHT_PATH)
            if r.status_code == 200:
                return []  # catch-all — skip to avoid mass false positives
        except Exception:
            pass

        wordlist_tier = ctx.opts.module_options.get("webshells", {}).get("wordlist", "core")
        paths = WEBSHELL_PATHS_EXTENDED if wordlist_tier == "extended" else WEBSHELL_PATHS_CORE

        findings: list[Finding] = []
        sem = asyncio.Semaphore(ctx.opts.concurrency)

        async def _probe(path: str) -> None:
            async with sem:
                try:
                    url = ctx.url + path
                    r = await http.get(url)
                    if r.status_code != 200:
                        return
                    ct = r.headers.get("content-type", "").split(";")[0].strip().lower()
                    if ct not in _ALLOWED_CONTENT_TYPES:
                        return
                    findings.append(Finding(
                        id="PC-WSH-001",
                        remediation_id="REM-WSH-001",
                        title="Known webshell path is accessible",
                        severity=Severity.CRITICAL,
                        description=(
                            f"A file matching a known webshell filename was found at `{url}`. "
                            "This strongly indicates the site has been compromised."
                        ),
                        evidence={"url": url, "status_code": str(r.status_code), "content_type": ct},
                        remediation=(
                            "Immediately remove the suspicious file. Audit all files in "
                            "wp-content/uploads, mu-plugins, and plugin directories. "
                            "Change all WordPress and database credentials."
                        ),
                        references=[
                            "https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF",
                            "https://github.com/nsacyber/Mitigating-Web-Shells",
                        ],
                        cvss_score=9.8,
                        module="webshells",
                    ))
                except Exception:
                    pass

        await asyncio.gather(*[_probe(p) for p in paths])
        return findings
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python3 -m pytest tests/unit/test_module_webshells_known_paths.py -v
```

Expected: 4 tests PASSED.

- [ ] **Step 5: Commit**

```bash
git add plecost/modules/webshells/detectors/known_paths.py tests/unit/test_module_webshells_known_paths.py
git commit --author="Dani <cr0hn@cr0hn.com>" -m "feat(webshells): add KnownPathsDetector with preflight catch-all guard"
```

---

## Task 2: UploadsPhpDetector

**Files:**
- Create: `plecost/modules/webshells/detectors/uploads_php.py`
- Create: `tests/unit/test_module_webshells_uploads.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_module_webshells_uploads.py`:

```python
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Severity
from plecost.modules.webshells.detectors.uploads_php import UploadsPhpDetector


def make_ctx():
    c = ScanContext(ScanOptions(url="https://example.com"))
    c.is_wordpress = True
    return c


async def test_reports_php_in_uploads_root():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get("https://example.com/wp-content/uploads/shell.php").mock(
            return_value=httpx.Response(200, text="<?php system($_GET['cmd']); ?>")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            detector = UploadsPhpDetector()
            findings = await detector.detect(ctx, http)
    assert any(f.id == "PC-WSH-100" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


async def test_reports_php_in_dated_subdir():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get("https://example.com/wp-content/uploads/2024/03/backdoor.php").mock(
            return_value=httpx.Response(200, text="webshell")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            detector = UploadsPhpDetector()
            findings = await detector.detect(ctx, http)
    assert any(f.id == "PC-WSH-100" for f in findings)


async def test_no_finding_when_uploads_returns_403():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.route(url__regex=r".*/wp-content/uploads/.*\.php").mock(
            return_value=httpx.Response(403)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            detector = UploadsPhpDetector()
            findings = await detector.detect(ctx, http)
    assert findings == []
```

- [ ] **Step 2: Run to verify it fails**

```bash
python3 -m pytest tests/unit/test_module_webshells_uploads.py -v
```

Expected: `ImportError`.

- [ ] **Step 3: Implement `plecost/modules/webshells/detectors/uploads_php.py`**

```python
from __future__ import annotations
import asyncio
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.webshells.base import BaseDetector
from plecost.modules.webshells.wordlists import UPLOADS_PROBE_PATHS


class UploadsPhpDetector(BaseDetector):
    """
    Detects PHP files in wp-content/uploads/ returning HTTP 200.
    WordPress must never execute PHP from uploads — any 200 here is CRITICAL.
    """

    name = "uploads_php"
    requires_auth = False

    async def detect(
        self, ctx: ScanContext, http: PlecostHTTPClient
    ) -> list[Finding]:
        findings: list[Finding] = []
        sem = asyncio.Semaphore(ctx.opts.concurrency)

        async def _probe(path: str) -> None:
            async with sem:
                try:
                    url = ctx.url + path
                    r = await http.get(url)
                    if r.status_code != 200:
                        return
                    findings.append(Finding(
                        id="PC-WSH-100",
                        remediation_id="REM-WSH-100",
                        title="PHP file executable in wp-content/uploads",
                        severity=Severity.CRITICAL,
                        description=(
                            f"A PHP file was found accessible at `{url}`. "
                            "WordPress should never execute PHP files from the uploads directory. "
                            "This indicates a webshell or a critically misconfigured server."
                        ),
                        evidence={"url": url, "status_code": "200"},
                        remediation=(
                            "Remove the PHP file immediately. Add or restore the .htaccess file "
                            "in wp-content/uploads/ to deny PHP execution:\n\n"
                            "<Files *.php>\n  deny from all\n</Files>"
                        ),
                        references=[
                            "https://blog.sucuri.net/2021/04/wordpress-file-upload-vulnerability.html",
                        ],
                        cvss_score=9.8,
                        module="webshells",
                    ))
                except Exception:
                    pass

        await asyncio.gather(*[_probe(p) for p in UPLOADS_PROBE_PATHS])
        return findings
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/unit/test_module_webshells_uploads.py -v
```

Expected: 3 tests PASSED.

- [ ] **Step 5: Commit**

```bash
git add plecost/modules/webshells/detectors/uploads_php.py tests/unit/test_module_webshells_uploads.py
git commit --author="Dani <cr0hn@cr0hn.com>" -m "feat(webshells): add UploadsPhpDetector"
```

---

## Task 3: MuPluginsDetector

**Files:**
- Create: `plecost/modules/webshells/detectors/mu_plugins.py`
- Create: `tests/unit/test_module_webshells_mu_plugins.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_module_webshells_mu_plugins.py`:

```python
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Severity
from plecost.modules.webshells.detectors.mu_plugins import MuPluginsDetector


async def test_reports_php_in_mu_plugins():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            return_value=httpx.Response(200, text="<?php eval($_POST['x']); ?>")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    assert any(f.id == "PC-WSH-150" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


async def test_no_finding_when_all_mu_plugins_404():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    assert findings == []


async def test_no_finding_on_403():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.route(url__regex=r".*/mu-plugins/.*").mock(return_value=httpx.Response(403))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    assert findings == []
```

- [ ] **Step 2: Run to verify it fails**

```bash
python3 -m pytest tests/unit/test_module_webshells_mu_plugins.py -v
```

Expected: `ImportError`.

- [ ] **Step 3: Implement `plecost/modules/webshells/detectors/mu_plugins.py`**

```python
from __future__ import annotations
import asyncio
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.webshells.base import BaseDetector
from plecost.modules.webshells.wordlists import MU_PLUGINS_NAMES

_MU_PLUGINS_BASE = "/wp-content/mu-plugins/"


class MuPluginsDetector(BaseDetector):
    """
    Detects PHP files in wp-content/mu-plugins/ returning HTTP 200.
    Must-Use plugins load automatically and are invisible in the WP admin panel.
    This is a primary vector for persistent WordPress backdoors (Sucuri 2024-2025).
    """

    name = "mu_plugins"
    requires_auth = False

    async def detect(
        self, ctx: ScanContext, http: PlecostHTTPClient
    ) -> list[Finding]:
        findings: list[Finding] = []
        sem = asyncio.Semaphore(ctx.opts.concurrency)

        async def _probe(name: str) -> None:
            async with sem:
                try:
                    url = ctx.url + _MU_PLUGINS_BASE + name
                    r = await http.get(url)
                    if r.status_code != 200:
                        return
                    findings.append(Finding(
                        id="PC-WSH-150",
                        remediation_id="REM-WSH-150",
                        title="Suspicious PHP file in wp-content/mu-plugins",
                        severity=Severity.CRITICAL,
                        description=(
                            f"A PHP file was found at `{url}`. "
                            "Must-Use plugins load automatically on every WordPress request "
                            "and are hidden from the admin plugin list — making them a preferred "
                            "location for persistent backdoors."
                        ),
                        evidence={"url": url, "status_code": "200"},
                        remediation=(
                            "Review and remove any unexpected files in wp-content/mu-plugins/. "
                            "Legitimate must-use plugins are intentionally installed by developers "
                            "and should be documented."
                        ),
                        references=[
                            "https://blog.sucuri.net/2025/03/hidden-malware-strikes-again-mu-plugins-under-attack.html",
                            "https://www.bleepingcomputer.com/news/security/hackers-abuse-wordpress-mu-plugins-to-hide-malicious-code/",
                        ],
                        cvss_score=9.8,
                        module="webshells",
                    ))
                except Exception:
                    pass

        await asyncio.gather(*[_probe(name) for name in MU_PLUGINS_NAMES])
        return findings
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/unit/test_module_webshells_mu_plugins.py -v
```

Expected: 3 tests PASSED.

- [ ] **Step 5: Commit**

```bash
git add plecost/modules/webshells/detectors/mu_plugins.py tests/unit/test_module_webshells_mu_plugins.py
git commit --author="Dani <cr0hn@cr0hn.com>" -m "feat(webshells): add MuPluginsDetector (mu-plugins vector 2024-2025)"
```

---

## Task 4: ResponseFingerprintDetector

**Files:**
- Create: `plecost/modules/webshells/detectors/response_fp.py`
- Create: `tests/unit/test_module_webshells_response_fp.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_module_webshells_response_fp.py`:

```python
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Severity
from plecost.modules.webshells.detectors.response_fp import ResponseFingerprintDetector


async def test_detects_china_chopper_blank_200():
    """China Chopper returns exactly empty body with 200 OK."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get("https://example.com/plecost-probe-nonexistent.php").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://example.com/wp-content/uploads/shell.php").mock(
            return_value=httpx.Response(200, content=b"", headers={"content-type": "text/html"})
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await ResponseFingerprintDetector().detect(ctx, http)
    assert any(f.id == "PC-WSH-200" for f in findings)
    assert any("china_chopper" in f.evidence.get("family", "") for f in findings)


async def test_detects_wso_form_parameters():
    """WSO shell has a form with fields: a, c, p1, p2, p3, charset."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    wso_html = '<form><input name="a"><input name="c"><input name="charset"></form>'
    async with respx.mock:
        respx.get("https://example.com/plecost-probe-nonexistent.php").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://example.com/wp-content/uploads/wso.php").mock(
            return_value=httpx.Response(200, text=wso_html, headers={"content-type": "text/html"})
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await ResponseFingerprintDetector().detect(ctx, http)
    assert any("wso" in f.evidence.get("family", "") for f in findings)


async def test_detects_b374k_string():
    """b374k shell contains the string 'b374k' in its body."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get("https://example.com/plecost-probe-nonexistent.php").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://example.com/wp-content/uploads/b374k.php").mock(
            return_value=httpx.Response(200, text="<html>b374k shell v3.2</html>",
                                        headers={"content-type": "text/html"})
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await ResponseFingerprintDetector().detect(ctx, http)
    assert any("b374k" in f.evidence.get("family", "") for f in findings)


async def test_detects_polyglot_image_php():
    """A file starting with GIF89a but containing <?php is a polyglot webshell."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    polyglot = b"GIF89a<?php system($_GET['cmd']); ?>"
    async with respx.mock:
        respx.get("https://example.com/plecost-probe-nonexistent.php").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://example.com/wp-content/uploads/image.php").mock(
            return_value=httpx.Response(200, content=polyglot,
                                        headers={"content-type": "text/html"})
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await ResponseFingerprintDetector().detect(ctx, http)
    assert any("polyglot" in f.evidence.get("family", "") for f in findings)


async def test_no_finding_on_normal_html():
    """A 200 response with normal WordPress HTML must not trigger a finding."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    normal_html = "<html><head><title>My Blog</title></head><body><p>Hello</p></body></html>"
    async with respx.mock:
        respx.get("https://example.com/plecost-probe-nonexistent.php").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://example.com/wp-content/uploads/cache.php").mock(
            return_value=httpx.Response(200, text=normal_html,
                                        headers={"content-type": "text/html"})
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await ResponseFingerprintDetector().detect(ctx, http)
    # Normal HTML with no webshell signatures must produce no findings
    assert findings == []
```

- [ ] **Step 2: Run to verify it fails**

```bash
python3 -m pytest tests/unit/test_module_webshells_response_fp.py -v
```

Expected: `ImportError`.

- [ ] **Step 3: Implement `plecost/modules/webshells/detectors/response_fp.py`**

```python
from __future__ import annotations
import asyncio
import re
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.webshells.base import BaseDetector
from plecost.modules.webshells.wordlists import WEBSHELL_PATHS_CORE, WEBSHELL_PATHS_EXTENDED

_PREFLIGHT_PATH = "/plecost-probe-nonexistent.php"
_ALLOWED_CONTENT_TYPES = {"text/html", "text/plain", "application/x-httpd-php"}

# Image magic bytes (polyglot detection)
_MAGIC_GIF = b"GIF89a"
_MAGIC_JPEG = b"\xff\xd8\xff"
_MAGIC_PNG = b"\x89PNG"
_PHP_OPEN_TAG = b"<?php"

# WSO parameter fingerprint — all 3 must be present
_WSO_PARAMS = [b'name="a"', b'name="c"', b'name="charset"']


def _fingerprint(body: bytes) -> str | None:
    """Return family name if body matches a known webshell fingerprint, else None."""
    # China Chopper: empty body (0 bytes)
    if len(body) == 0:
        return "china_chopper"

    # Godzilla/Behinder response markers
    if b"->|" in body or b"|<-" in body:
        return "godzilla_behinder"

    # WSO/FilesMan: form with a, c, charset parameters
    if all(p in body for p in _WSO_PARAMS):
        return "wso_filesman"

    # b374k: contains 'b374k' string
    if b"b374k" in body.lower():
        return "b374k"

    # c99shell: contains 'c99shell'
    if b"c99shell" in body.lower():
        return "c99shell"

    # Polyglot image/PHP: starts with image magic bytes but contains PHP
    for magic in (_MAGIC_GIF, _MAGIC_JPEG, _MAGIC_PNG):
        if body.startswith(magic) and _PHP_OPEN_TAG in body:
            return "polyglot_image_php"

    return None


class ResponseFingerprintDetector(BaseDetector):
    """
    Probes known webshell paths and fingerprints the response body
    against known webshell family signatures.
    Only reports when a fingerprint matches — higher confidence than path-only.
    """

    name = "response_fp"
    requires_auth = False

    async def detect(
        self, ctx: ScanContext, http: PlecostHTTPClient
    ) -> list[Finding]:
        # Preflight: detect catch-all sites
        try:
            r = await http.get(ctx.url + _PREFLIGHT_PATH)
            if r.status_code == 200:
                return []
        except Exception:
            pass

        wordlist_tier = ctx.opts.module_options.get("webshells", {}).get("wordlist", "core")
        paths = WEBSHELL_PATHS_EXTENDED if wordlist_tier == "extended" else WEBSHELL_PATHS_CORE

        findings: list[Finding] = []
        sem = asyncio.Semaphore(ctx.opts.concurrency)

        async def _probe(path: str) -> None:
            async with sem:
                try:
                    url = ctx.url + path
                    r = await http.get(url)
                    if r.status_code != 200:
                        return
                    ct = r.headers.get("content-type", "").split(";")[0].strip().lower()
                    if ct not in _ALLOWED_CONTENT_TYPES:
                        return
                    family = _fingerprint(r.content)
                    if family is None:
                        return
                    findings.append(Finding(
                        id="PC-WSH-200",
                        remediation_id="REM-WSH-200",
                        title=f"Webshell fingerprint matched: {family}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"A response from `{url}` matches the fingerprint of the "
                            f"'{family}' webshell family. The server is almost certainly compromised."
                        ),
                        evidence={"url": url, "family": family, "status_code": "200"},
                        remediation=(
                            "The site is compromised. Immediately take the site offline, "
                            "remove the webshell, audit all files for additional backdoors, "
                            "and rotate all credentials (WordPress, database, FTP, hosting)."
                        ),
                        references=[
                            "https://www.recordedfuture.com/blog/web-shell-analysis-part-1",
                            "https://github.com/nsacyber/Mitigating-Web-Shells",
                        ],
                        cvss_score=10.0,
                        module="webshells",
                    ))
                except Exception:
                    pass

        await asyncio.gather(*[_probe(p) for p in paths])
        return findings
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/unit/test_module_webshells_response_fp.py -v
```

Expected: 5 tests PASSED.

- [ ] **Step 5: Commit**

```bash
git add plecost/modules/webshells/detectors/response_fp.py tests/unit/test_module_webshells_response_fp.py
git commit --author="Dani <cr0hn@cr0hn.com>" -m "feat(webshells): add ResponseFingerprintDetector (China Chopper, WSO, b374k, polyglot)"
```

---

## Task 5: ChecksumsDetector

**Files:**
- Create: `plecost/modules/webshells/detectors/checksums.py`
- Create: `tests/unit/test_module_webshells_checksums.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_module_webshells_checksums.py`:

```python
import hashlib
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Severity
from plecost.modules.webshells.detectors.checksums import ChecksumsDetector


def _make_ctx_with_creds(version: str = "6.4.2") -> ScanContext:
    opts = ScanOptions(url="https://example.com", credentials=("admin", "secret"))
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    ctx.wordpress_version = version
    return ctx


async def test_reports_modified_core_file():
    """A core file with a different MD5 hash must emit PC-WSH-250."""
    ctx = _make_ctx_with_creds()
    original_content = b"<?php // original wp-login.php content"
    modified_content = b"<?php @eval($_POST['x']); // original wp-login.php content"
    expected_md5 = hashlib.md5(original_content).hexdigest()
    checksums_json = {"checksums": {"wp-login.php": expected_md5}}

    async with respx.mock:
        respx.get(
            "https://api.wordpress.org/core/checksums/1.0/?version=6.4.2&locale=en_US"
        ).mock(return_value=httpx.Response(200, json=checksums_json))
        respx.get("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(200, content=modified_content)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await ChecksumsDetector().detect(ctx, http)
    assert any(f.id == "PC-WSH-250" for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


async def test_no_finding_when_hash_matches():
    """No finding if the downloaded file matches the official MD5."""
    ctx = _make_ctx_with_creds()
    content = b"<?php // official wp-login.php"
    expected_md5 = hashlib.md5(content).hexdigest()
    checksums_json = {"checksums": {"wp-login.php": expected_md5}}

    async with respx.mock:
        respx.get(
            "https://api.wordpress.org/core/checksums/1.0/?version=6.4.2&locale=en_US"
        ).mock(return_value=httpx.Response(200, json=checksums_json))
        respx.get("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(200, content=content)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await ChecksumsDetector().detect(ctx, http)
    assert findings == []


async def test_skips_when_version_unknown():
    """If wordpress_version is None, detector must skip gracefully."""
    opts = ScanOptions(url="https://example.com", credentials=("admin", "secret"))
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    ctx.wordpress_version = None  # version not detected

    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await ChecksumsDetector().detect(ctx, http)
    assert findings == []


async def test_skips_when_no_credentials():
    """Without credentials, the detector must not run."""
    opts = ScanOptions(url="https://example.com")  # no credentials
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    ctx.wordpress_version = "6.4.2"

    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await ChecksumsDetector().detect(ctx, http)
    assert findings == []
```

- [ ] **Step 2: Run to verify it fails**

```bash
python3 -m pytest tests/unit/test_module_webshells_checksums.py -v
```

Expected: `ImportError`.

- [ ] **Step 3: Implement `plecost/modules/webshells/detectors/checksums.py`**

```python
from __future__ import annotations
import asyncio
import hashlib
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.webshells.base import BaseDetector
from plecost.modules.webshells.wordlists import WP_CORE_FILES_TO_CHECK

_CHECKSUMS_API = "https://api.wordpress.org/core/checksums/1.0/?version={version}&locale={locale}"


class ChecksumsDetector(BaseDetector):
    """
    Verifies WordPress core file integrity using the official WordPress checksums API.
    Requires WordPress admin credentials and a detected WP version.
    """

    name = "checksums"
    requires_auth = True

    async def detect(
        self, ctx: ScanContext, http: PlecostHTTPClient
    ) -> list[Finding]:
        if not ctx.opts.credentials:
            return []
        if not ctx.wordpress_version:
            return []

        locale = getattr(ctx, "wordpress_locale", "en_US") or "en_US"
        api_url = _CHECKSUMS_API.format(version=ctx.wordpress_version, locale=locale)

        try:
            r = await http.get(api_url)
            if r.status_code != 200:
                return []
            data = r.json()
            checksums: dict[str, str] = data.get("checksums", {})
            if not checksums:
                return []
        except Exception:
            return []

        findings: list[Finding] = []
        sem = asyncio.Semaphore(ctx.opts.concurrency)

        async def _check(file_path: str) -> None:
            expected_md5 = checksums.get(file_path)
            if not expected_md5:
                return
            async with sem:
                try:
                    url = ctx.url + "/" + file_path
                    r = await http.get(url)
                    if r.status_code != 200:
                        return
                    actual_md5 = hashlib.md5(r.content).hexdigest()
                    if actual_md5 == expected_md5:
                        return
                    findings.append(Finding(
                        id="PC-WSH-250",
                        remediation_id="REM-WSH-250",
                        title=f"WordPress core file modified: {file_path}",
                        severity=Severity.HIGH,
                        description=(
                            f"The core file `{file_path}` has been modified. "
                            f"Expected MD5: `{expected_md5}`, actual: `{actual_md5}`. "
                            "Modified core files can indicate a backdoor or unauthorized customization."
                        ),
                        evidence={
                            "file": file_path,
                            "expected_md5": expected_md5,
                            "actual_md5": actual_md5,
                            "url": url,
                        },
                        remediation=(
                            "Verify whether this modification is authorized. "
                            "If not, restore the original file from a clean WordPress installation "
                            f"(version {ctx.wordpress_version})."
                        ),
                        references=[
                            "https://developer.wordpress.org/reference/functions/get_core_checksums/",
                        ],
                        cvss_score=7.5,
                        module="webshells",
                    ))
                except Exception:
                    pass

        await asyncio.gather(*[_check(f) for f in WP_CORE_FILES_TO_CHECK])
        return findings
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/unit/test_module_webshells_checksums.py -v
```

Expected: 4 tests PASSED.

- [ ] **Step 5: Commit**

```bash
git add plecost/modules/webshells/detectors/checksums.py tests/unit/test_module_webshells_checksums.py
git commit --author="Dani <cr0hn@cr0hn.com>" -m "feat(webshells): add ChecksumsDetector via WordPress.org checksums API"
```

---

## Task 6: FakePluginRestDetector

**Files:**
- Create: `plecost/modules/webshells/detectors/fake_plugins.py`
- Create: `tests/unit/test_module_webshells_fake_plugins.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_module_webshells_fake_plugins.py`:

```python
import base64
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Plugin, Severity
from plecost.modules.webshells.detectors.fake_plugins import FakePluginRestDetector


def _make_ctx_with_creds() -> ScanContext:
    opts = ScanOptions(url="https://example.com", credentials=("admin", "secret"))
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    # Add one known legitimate plugin
    ctx.add_plugin(Plugin(
        slug="woocommerce", version="8.0.0", latest_version="8.0.0",
        url="https://example.com/wp-content/plugins/woocommerce/"
    ))
    return ctx


async def test_detects_fake_plugin_not_in_ctx():
    """A plugin returned by REST API but NOT in ctx.plugins is flagged."""
    ctx = _make_ctx_with_creds()
    rest_response = [
        {
            "plugin": "blnmrpb/index.php",
            "name": "blnmrpb",
            "status": "active",
        }
    ]
    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/plugins").mock(
            return_value=httpx.Response(200, json=rest_response)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await FakePluginRestDetector().detect(ctx, http)
    assert any(f.id == "PC-WSH-300" for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


async def test_no_finding_for_known_plugin():
    """A plugin that IS in ctx.plugins must not be flagged."""
    ctx = _make_ctx_with_creds()
    rest_response = [
        {
            "plugin": "woocommerce/woocommerce.php",
            "name": "WooCommerce",
            "status": "active",
        }
    ]
    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/plugins").mock(
            return_value=httpx.Response(200, json=rest_response)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await FakePluginRestDetector().detect(ctx, http)
    assert findings == []


async def test_skips_when_no_credentials():
    """Without credentials, the detector must skip gracefully."""
    opts = ScanOptions(url="https://example.com")
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200, json=[]))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await FakePluginRestDetector().detect(ctx, http)
    assert findings == []


async def test_skips_when_rest_api_returns_401():
    """If REST API returns 401, skip gracefully without error."""
    ctx = _make_ctx_with_creds()
    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/plugins").mock(
            return_value=httpx.Response(401, json={"code": "rest_forbidden"})
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await FakePluginRestDetector().detect(ctx, http)
    assert findings == []
```

- [ ] **Step 2: Run to verify it fails**

```bash
python3 -m pytest tests/unit/test_module_webshells_fake_plugins.py -v
```

Expected: `ImportError`.

- [ ] **Step 3: Implement `plecost/modules/webshells/detectors/fake_plugins.py`**

```python
from __future__ import annotations
import base64
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.webshells.base import BaseDetector


class FakePluginRestDetector(BaseDetector):
    """
    Uses the WordPress REST API (/wp-json/wp/v2/plugins) with Basic Auth to list all
    installed plugins, then flags any plugin that is not in the plugins detected by
    the passive/brute-force plugins module (ctx.plugins).

    Requires WordPress admin credentials.
    """

    name = "fake_plugins"
    requires_auth = True

    async def detect(
        self, ctx: ScanContext, http: PlecostHTTPClient
    ) -> list[Finding]:
        if not ctx.opts.credentials:
            return []

        username, password = ctx.opts.credentials
        auth_header = base64.b64encode(f"{username}:{password}".encode()).decode()

        try:
            r = await http.get(
                f"{ctx.url}/wp-json/wp/v2/plugins",
                headers={"Authorization": f"Basic {auth_header}"},
            )
            if r.status_code not in (200,):
                return []
            plugins_data: list[dict] = r.json()
        except Exception:
            return []

        # Build set of known-legitimate slugs from passive/brute-force scan
        known_slugs = {p.slug.lower() for p in ctx.plugins}

        findings: list[Finding] = []
        for plugin in plugins_data:
            plugin_file: str = plugin.get("plugin", "")
            # plugin_file is "slug/main-file.php" — extract slug
            slug = plugin_file.split("/")[0].lower() if "/" in plugin_file else plugin_file.lower()
            if not slug:
                continue
            if slug in known_slugs:
                continue  # legitimate plugin, already detected by plugins module

            findings.append(Finding(
                id="PC-WSH-300",
                remediation_id="REM-WSH-300",
                title=f"Unrecognized plugin found via REST API: {slug}",
                severity=Severity.HIGH,
                description=(
                    f"The WordPress REST API reports a plugin with slug `{slug}` "
                    f"(file: `{plugin_file}`) is installed and active. "
                    "This plugin was not detected during passive scanning, which can indicate "
                    "a fake or hidden plugin used as a backdoor."
                ),
                evidence={
                    "slug": slug,
                    "plugin_file": plugin_file,
                    "plugin_name": plugin.get("name", ""),
                },
                remediation=(
                    "Verify whether this plugin is intentionally installed. "
                    "If unknown, deactivate and delete it immediately. "
                    "Inspect its source code for malicious content."
                ),
                references=[
                    "https://blog.sucuri.net/2020/01/webshell-in-fake-plugin-blnmrpb-directory.html",
                ],
                cvss_score=7.5,
                module="webshells",
            ))

        return findings
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/unit/test_module_webshells_fake_plugins.py -v
```

Expected: 4 tests PASSED.

- [ ] **Step 5: Commit**

```bash
git add plecost/modules/webshells/detectors/fake_plugins.py tests/unit/test_module_webshells_fake_plugins.py
git commit --author="Dani <cr0hn@cr0hn.com>" -m "feat(webshells): add FakePluginRestDetector via WP REST API"
```

---

## Task 7: WebshellsModule + Integration Test

**Files:**
- Create: `plecost/modules/webshells/module.py`
- Modify: `plecost/modules/webshells/__init__.py`
- Create: `tests/unit/test_module_webshells_module.py`

- [ ] **Step 1: Write the failing integration test**

Create `tests/unit/test_module_webshells_module.py`:

```python
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.webshells import WebshellsModule


async def test_module_name_and_deps():
    mod = WebshellsModule()
    assert mod.name == "webshells"
    assert "fingerprint" in mod.depends_on
    assert "plugins" in mod.depends_on


async def test_module_adds_findings_to_ctx():
    """Full module run: a known path returning 200 must add findings to ctx."""
    opts = ScanOptions(url="https://example.com")
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    async with respx.mock:
        # Preflight → not catch-all
        respx.get("https://example.com/plecost-probe-nonexistent.php").mock(
            return_value=httpx.Response(404)
        )
        # One known webshell path returns 200 with text/html
        respx.get("https://example.com/wp-content/uploads/shell.php").mock(
            return_value=httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text="<html>shell</html>",
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(opts) as http:
            await WebshellsModule().run(ctx, http)
    assert len(ctx.findings) > 0


async def test_auth_detectors_skipped_without_credentials():
    """Detectors requiring auth must not run if no credentials are set."""
    opts = ScanOptions(url="https://example.com")  # no credentials
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    ctx.wordpress_version = "6.4.2"
    # If auth detectors ran, they'd call api.wordpress.org — those calls would fail
    # under respx.mock without explicit mocks, causing errors
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(opts) as http:
            # Should not raise
            await WebshellsModule().run(ctx, http)
```

- [ ] **Step 2: Run to verify it fails**

```bash
python3 -m pytest tests/unit/test_module_webshells_module.py -v
```

Expected: `ImportError` for `WebshellsModule`.

- [ ] **Step 3: Implement `plecost/modules/webshells/module.py`**

```python
from __future__ import annotations
import asyncio
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.modules.base import ScanModule
from plecost.modules.webshells.base import BaseDetector
from plecost.modules.webshells.detectors.known_paths import KnownPathsDetector
from plecost.modules.webshells.detectors.uploads_php import UploadsPhpDetector
from plecost.modules.webshells.detectors.mu_plugins import MuPluginsDetector
from plecost.modules.webshells.detectors.response_fp import ResponseFingerprintDetector
from plecost.modules.webshells.detectors.checksums import ChecksumsDetector
from plecost.modules.webshells.detectors.fake_plugins import FakePluginRestDetector


class WebshellsModule(ScanModule):
    """
    Remote webshell detection for WordPress.

    Black-box detectors (no credentials required):
      - known_paths: probes ~100-300 known webshell filenames in WP directories
      - uploads_php: detects PHP execution in wp-content/uploads
      - mu_plugins: detects PHP files in wp-content/mu-plugins
      - response_fp: fingerprints response bodies against known webshell families

    Grey-box detectors (requires --user / --password):
      - checksums: verifies WP core file integrity via api.wordpress.org
      - fake_plugins: detects unknown plugins via WP REST API

    Module options (--module-option webshells:KEY=VALUE):
      - wordlist=core (default) | extended   — wordlist size for path probing
      - detectors=name1,name2               — run only specified detectors
    """

    name = "webshells"
    depends_on = ["fingerprint", "plugins"]

    _all_detectors: list[BaseDetector] = [
        KnownPathsDetector(),
        UploadsPhpDetector(),
        MuPluginsDetector(),
        ResponseFingerprintDetector(),
        ChecksumsDetector(),
        FakePluginRestDetector(),
    ]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        options = ctx.opts.module_options.get("webshells", {})

        # Filter by detectors option if specified
        enabled_names: set[str] | None = None
        if "detectors" in options:
            enabled_names = {n.strip() for n in options["detectors"].split(",")}

        active: list[BaseDetector] = []
        for detector in self._all_detectors:
            if enabled_names is not None and detector.name not in enabled_names:
                continue
            if detector.requires_auth and not ctx.opts.credentials:
                continue
            active.append(detector)

        results = await asyncio.gather(
            *[d.detect(ctx, http) for d in active],
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, list):
                for finding in result:
                    ctx.add_finding(finding)
            # exceptions are silently ignored (project convention)
```

- [ ] **Step 4: Update `plecost/modules/webshells/__init__.py`**

```python
from plecost.modules.webshells.module import WebshellsModule

__all__ = ["WebshellsModule"]
```

- [ ] **Step 5: Run all webshell tests**

```bash
python3 -m pytest tests/unit/test_module_webshells_module.py tests/unit/test_module_webshells_known_paths.py tests/unit/test_module_webshells_uploads.py tests/unit/test_module_webshells_mu_plugins.py tests/unit/test_module_webshells_response_fp.py tests/unit/test_module_webshells_checksums.py tests/unit/test_module_webshells_fake_plugins.py -v
```

Expected: all tests PASSED.

- [ ] **Step 6: Commit**

```bash
git add plecost/modules/webshells/module.py plecost/modules/webshells/__init__.py tests/unit/test_module_webshells_module.py
git commit --author="Dani <cr0hn@cr0hn.com>" -m "feat(webshells): add WebshellsModule orchestrator with parallel detector dispatch"
```

---

## Task 8: Register Module in scanner.py and cli.py

**Files:**
- Modify: `plecost/scanner.py`
- Modify: `plecost/cli.py`

- [ ] **Step 1: Register in `plecost/scanner.py`**

Add the import at line ~27 (after the last module import):

```python
from plecost.modules.webshells import WebshellsModule
```

Add to the `modules` list at line ~124 (after `MagecartModule`):

```python
        modules: list[ScanModule] = [
            FingerprintModule(), WAFModule(),
            PluginsModule(wordlist=plugin_wl),
            ThemesModule(wordlist=theme_wl),
            UsersModule(), XMLRPCModule(), RESTAPIModule(),
            MisconfigsModule(), DirectoryListingModule(),
            HTTPHeadersModule(), SSLTLSModule(),
            DebugExposureModule(), ContentAnalysisModule(), AuthModule(),
            WooCommerceModule(),
            WPECommerceModule(),
            MagecartModule(store),
            WebshellsModule(),   # ← add this line
        ]
```

- [ ] **Step 2: Verify scanner import works**

```bash
python3 -c "from plecost.scanner import Scanner; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Add to `_ALL_MODULE_NAMES` in `plecost/cli.py`**

Find the `_ALL_MODULE_NAMES` list (line ~16) and add `"webshells"`:

```python
_ALL_MODULE_NAMES = [
    "fingerprint", "waf", "plugins", "themes", "users", "xmlrpc",
    "rest_api", "misconfigs", "directory_listing", "http_headers",
    "ssl_tls", "debug_exposure", "content_analysis", "auth", "cves",
    "woocommerce",
    "wp_ecommerce",
    "magecart",
    "webshells",   # ← add this line
]
```

- [ ] **Step 4: Add findings to `_FINDINGS_REGISTRY` in `plecost/cli.py`**

Find `_FINDINGS_REGISTRY` dict and add at the end (before the closing `}`):

```python
    "PC-WSH-001": {
        "title": "Known webshell path is accessible",
        "severity": "CRITICAL",
        "description": "A file matching a known webshell filename was found accessible via HTTP.",
        "remediation": "Remove the file immediately. Audit all wp-content directories. Rotate all credentials.",
        "references": [
            "https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF",
            "https://github.com/nsacyber/Mitigating-Web-Shells",
        ],
        "remediation_id": "REM-WSH-001",
    },
    "PC-WSH-100": {
        "title": "PHP file executable in wp-content/uploads",
        "severity": "CRITICAL",
        "description": "A PHP file is accessible and executable inside wp-content/uploads, which should never execute PHP.",
        "remediation": "Remove the file. Add .htaccess to uploads/ to deny PHP execution.",
        "references": [],
        "remediation_id": "REM-WSH-100",
    },
    "PC-WSH-150": {
        "title": "Suspicious PHP file in wp-content/mu-plugins",
        "severity": "CRITICAL",
        "description": "A PHP file matching a known backdoor name was found in must-use plugins directory.",
        "remediation": "Review and remove unexpected files from wp-content/mu-plugins/.",
        "references": [
            "https://blog.sucuri.net/2025/03/hidden-malware-strikes-again-mu-plugins-under-attack.html",
        ],
        "remediation_id": "REM-WSH-150",
    },
    "PC-WSH-200": {
        "title": "Webshell family fingerprint matched in HTTP response",
        "severity": "CRITICAL",
        "description": "The response from a PHP file matches a known webshell family signature.",
        "remediation": "The site is compromised. Take offline, remove webshell, audit all files, rotate all credentials.",
        "references": [
            "https://www.recordedfuture.com/blog/web-shell-analysis-part-1",
        ],
        "remediation_id": "REM-WSH-200",
    },
    "PC-WSH-250": {
        "title": "WordPress core file has been modified",
        "severity": "HIGH",
        "description": "A WordPress core file does not match the official checksum for the installed version.",
        "remediation": "Verify if the modification is authorized. If not, restore the file from a clean WP installation.",
        "references": [
            "https://developer.wordpress.org/reference/functions/get_core_checksums/",
        ],
        "remediation_id": "REM-WSH-250",
    },
    "PC-WSH-300": {
        "title": "Unrecognized plugin detected via WordPress REST API",
        "severity": "HIGH",
        "description": "The WordPress REST API reports an active plugin that was not detected during passive scanning.",
        "remediation": "Verify the plugin is intentionally installed. If unknown, remove it and inspect for malicious code.",
        "references": [
            "https://blog.sucuri.net/2020/01/webshell-in-fake-plugin-blnmrpb-directory.html",
        ],
        "remediation_id": "REM-WSH-300",
    },
```

- [ ] **Step 5: Verify CLI import works**

```bash
python3 -c "from plecost.cli import app; print('OK')"
```

Expected: `OK`

- [ ] **Step 6: Run full test suite (excluding functional)**

```bash
python3 -m pytest tests/unit tests/integration tests/contract -v --tb=short 2>&1 | tail -20
```

Expected: no failures.

- [ ] **Step 7: Commit**

```bash
git add plecost/scanner.py plecost/cli.py
git commit --author="Dani <cr0hn@cr0hn.com>" -m "feat(webshells): register WebshellsModule in scanner and CLI"
```

---

## Task 9: Contract Tests + CHANGELOG

**Files:**
- Modify: `tests/contract/test_finding_ids.py`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add `PC-WSH-*` IDs to contract test**

Open `tests/contract/test_finding_ids.py` and add to `KNOWN_FINDING_IDS`:

```python
KNOWN_FINDING_IDS = [
    # ... existing IDs ...
    "PC-WSH-001", "PC-WSH-100", "PC-WSH-150",
    "PC-WSH-200", "PC-WSH-250", "PC-WSH-300",
]
```

- [ ] **Step 2: Run contract test**

```bash
python3 -m pytest tests/contract/test_finding_ids.py -v
```

Expected: all tests PASSED.

- [ ] **Step 3: Run full suite with coverage**

```bash
python3 -m pytest tests/unit tests/integration tests/contract tests/property --cov=plecost --cov-fail-under=75 -q 2>&1 | tail -10
```

Expected: coverage ≥ 75%, no failures.

- [ ] **Step 4: Run linter and type checker**

```bash
python3 -m ruff check plecost/ --fix
python3 -m mypy plecost/ --ignore-missing-imports
```

Fix any issues before proceeding.

- [ ] **Step 5: Update CHANGELOG.md**

Add at the top of `CHANGELOG.md`:

```markdown
## [Unreleased] — 2026-04-14

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
```

- [ ] **Step 6: Final commit**

```bash
git add tests/contract/test_finding_ids.py CHANGELOG.md
git commit --author="Dani <cr0hn@cr0hn.com>" -m "feat(webshells): add contract tests and CHANGELOG entry for webshell module"
```

---

## Verification

After all tasks are complete, run this final check:

```bash
# Full test suite
python3 -m pytest tests/unit tests/integration tests/contract tests/property --cov=plecost --cov-fail-under=75 -q

# Verify the module appears in the CLI
python3 -m plecost modules

# Quick sanity scan (replace with a test URL)
python3 -m plecost scan https://test-wp-site.example.com --modules webshells -v
```
