# Plecost v4.0 — Design Spec

> Date: 2026-04-10
> Status: Approved

---

## 1. Overview

Plecost is the best black-box security analysis tool for WordPress. It detects vulnerabilities in core, plugins and themes, enumerates users, identifies insecure configurations and correlates everything with a daily-updated CVE database.

**Design principles:**
- 100% automated — zero interaction during the scan
- Dual mode: interactive CLI (Typer + Rich) and Python library (for Celery workers, APIs, etc.)
- Async task graph with explicit dependencies (maximum parallelism)
- httpx + asyncio; uvloop as optional dependency
- Each finding has a stable permanent ID for external dashboards

---

## 2. Arquitectura General

### Estructura de paquete

```
plecost/
├── cli.py                      # Typer app — punto de entrada CLI
├── engine/
│   ├── scheduler.py            # Grafo de tareas async con dependencias
│   ├── context.py              # ScanContext: shared state between modules
│   └── http_client.py          # httpx.AsyncClient wrapper (proxy, auth, stealth)
├── modules/                    # Independent detection modules
│   ├── base.py                 # Clase base ScanModule
│   ├── fingerprint.py
│   ├── plugins.py
│   ├── themes.py
│   ├── users.py
│   ├── xmlrpc.py
│   ├── rest_api.py
│   ├── cves.py
│   ├── misconfigs.py
│   ├── directory_listing.py
│   ├── http_headers.py
│   ├── ssl_tls.py
│   ├── debug_exposure.py
│   ├── content_analysis.py
│   ├── waf.py
│   └── auth.py
├── database/
│   ├── updater.py              # Descarga y procesa CVE DB (usado por GitHub Action)
│   └── store.py                # Lectura local de la DB (SQLite + JSON)
├── reporters/
│   ├── terminal.py             # Rich: tablas, paneles, progress bars
│   └── json_reporter.py        # Volcado JSON estructurado
└── models.py                   # Dataclasses: ScanResult, Finding, Plugin, etc.
```

### Execution flow

```
CLI/Library → ScanOptions → ScanContext → Scheduler
                                              │
                    ┌─────────────────────────┤
                    ↓                         ↓
             [fingerprint]               [waf] (parallel from the start)
                    │
        ┌───────────┼───────────┬──────────┬──────────┬──────────┐
        ↓           ↓           ↓          ↓          ↓          ↓
    [plugins]   [themes]    [users]    [xmlrpc]  [misconfigs] [auth]
        │           │                                            │
        └─────┬─────┘                                    [auth_checks]
              ↓
           [cves]
              │
      [Terminal Reporter]
      [JSON Reporter]
```

---

## 3. Detection Modules

### Dependency graph

| Module | Depends on | Runs in parallel with |
|--------|-----------|---------------------------|
| fingerprint | — | waf |
| waf | — | fingerprint |
| plugins | fingerprint | themes, users, xmlrpc, misconfigs, http_headers, ssl_tls, debug_exposure, content_analysis, rest_api |
| themes | fingerprint | plugins, users, xmlrpc, ... |
| users | fingerprint | plugins, themes, ... |
| xmlrpc | fingerprint | plugins, themes, ... |
| rest_api | fingerprint | plugins, themes, ... |
| misconfigs | fingerprint | plugins, themes, ... |
| directory_listing | fingerprint | plugins, themes, ... |
| http_headers | fingerprint | plugins, themes, ... |
| ssl_tls | fingerprint | plugins, themes, ... |
| debug_exposure | fingerprint | plugins, themes, ... |
| content_analysis | fingerprint | plugins, themes, ... |
| auth | fingerprint | plugins, themes, ... |
| cves | plugins, themes | — |

### Capabilities per module

#### fingerprint
- WP version via meta generator tag
- WP version via `/readme.html` and `/readme.txt` (stable tag)
- WP version via query params `?ver=X.X.X` in JS/CSS
- WP version via file hashes in `/wp-includes/`
- WP version via RSS/Atom feed (`<generator>`)
- WP version via versioned assets in `wp-login.php`
- Active theme detection
- WordPress detection (prerequisite for all other modules)

#### plugins
- Fuerza bruta de ~59.000 slugs de plugins WordPress.org
- Passive plugin detection via paths in HTML source
- Version via `/wp-content/plugins/{slug}/readme.txt`
- Version via query params `?ver=X.X` in plugin assets
- Detection of abandoned plugins (closed on WP.org)
- Comparison of installed version vs. latest available

#### themes
- Brute force of ~2,600 WordPress.org theme slugs
- Passive detection via paths in HTML source
- Version via `/wp-content/themes/{slug}/style.css` (Version: comment)
- Version via `/wp-content/themes/{slug}/readme.txt`
- Inactive installed themes

#### users
- Enumeration via author archives `/?author=1` up to N
- Enumeration via REST API `/wp-json/wp/v2/users`
- Enumeration via RSS/Atom feeds (`<dc:creator>`)
- Enumeration via oEmbed response (author metadata)
- Login differential (different response for valid vs invalid user)
- Verification of "admin" user with ID=1

#### xmlrpc
- Detection of accessible `xmlrpc.php`
- `system.listMethods` available
- `pingback.ping` enabled (amplification DoS)
- Brute force via `system.multicall` (N attempts in 1 request)

#### rest_api
- `/wp-json/wp/v2/users` exposes usernames publicly
- CORS misconfiguration in REST API
- oEmbed endpoint exposes user information
- REST API link exposed in HTML header (`rel="https://api.w.org/"`)
- Application Passwords enabled

#### cves
- Correlation of WP core version with local CVE DB
- Correlation of each detected plugin with local CVE DB
- Correlation of each detected theme with local CVE DB
- CVSS 3.1 severity (Critical/High/Medium/Low)
- Public exploit available flag
- Exact affected version ranges

#### misconfigs
- `/wp-config.php` accessible
- wp-config backups: `.bak`, `.wp-config.php.swp`, `~`
- `/.env` accessible
- `/.git/` accessible
- `/debug.log` accessible
- `*.sql`, `*.bak` in root
- `/wp-admin/install.php` accessible
- `/wp-admin/upgrade.php` accessible
- `/readme.html` and `/license.txt` (version disclosure)
- `/wlwmanifest.xml` in header (Windows Live Writer)
- `wp-cron.php` externally accessible
- Default DB table prefix (`wp_`) — inferred from behavior
- Security keys not configured or weak — inferred from errors
- `DISALLOW_FILE_EDIT` not active — inferred from editor access

#### directory_listing
- Directory indexing at `/wp-content/`
- Directory indexing at `/wp-content/plugins/`
- Directory indexing at `/wp-content/themes/`
- Directory indexing at `/wp-content/uploads/`
- Media enumeration via `/?p=1`, `/?p=2`, ...

#### http_headers
- `Strict-Transport-Security` (HSTS) absent
- `X-Frame-Options` absent
- `X-Content-Type-Options` absent
- `Content-Security-Policy` absent
- `Referrer-Policy` absent
- `Permissions-Policy` absent
- `X-XSS-Protection` absent
- `Server` header exposes web server version
- `X-Powered-By` exposes PHP version

#### ssl_tls
- Valid and non-expired SSL certificate
- HTTP → HTTPS redirect absent
- HSTS preload
- TLS 1.0/1.1 still supported (deprecated)

#### debug_exposure
- `WP_DEBUG = true` active (errors in HTTP responses)
- `WP_DEBUG_LOG = true` (log accessible)
- `WP_DEBUG_DISPLAY = true` (errors visible on screen)
- `display_errors = On` in PHP
- `expose_php = On` in PHP
- `allow_url_include = On` in PHP (RFI risk)

#### content_analysis
- Suspicious third-party scripts (card skimming patterns)
- Unexpected external iframes
- Hardcoded secrets in public JS (API keys, tokens with regex)

#### waf
- WAF/CDN detection by headers and behavior
- Identification: Cloudflare, Sucuri, WordFence, Imperva, AWS WAF, Akamai, Fastly

#### auth
- Login with credentials (`--user` / `--password`)
- Verification of access to `/wp-admin`
- Active 2FA detection
- Additional checks in admin panel (authenticated)
- Open user registration (`anyone_can_register`)

---

## 4. CLI

### Commands

```bash
# Basic scan
plecost scan https://target.com

# Full scan with authentication
plecost scan https://target.com --user admin --password secret

# With proxy and concurrency
plecost scan https://target.com --proxy http://127.0.0.1:8080 --concurrency 20

# Specific modules only
plecost scan https://target.com --modules fingerprint,plugins,cves

# Exclude modules
plecost scan https://target.com --skip-modules content_analysis,waf

# Stealth mode (delays, random user-agent, passive detection only)
plecost scan https://target.com --stealth

# Aggressive mode (maximum concurrency, full brute-force)
plecost scan https://target.com --aggressive

# JSON output
plecost scan https://target.com --output report.json

# Update CVE database
plecost update-db

# List available modules
plecost modules list

# Show detail for a finding by ID
plecost explain PC-XMLRPC-002
```

### Global flags

| Flag | Description | Default |
|------|-------------|---------|
| `--concurrency N` | Number of parallel requests | 10 |
| `--timeout N` | Timeout per request (seconds) | 10 |
| `--proxy URL` | HTTP/SOCKS5 proxy | None |
| `--user-agent UA` | Custom User-Agent | Plecost/4.0 |
| `--random-user-agent` | Rotate User-Agent randomly | False |
| `--stealth` | Silent mode: delays + passive only | False |
| `--aggressive` | Aggressive mode: max concurrency | False |
| `--output FILE` | Save JSON to file | None |
| `--no-color` | Disable terminal colors | False |
| `--quiet` | Only show critical/high findings | False |
| `--force` | Continue even if WP not detected | False |
| `--disable-tls-checks` | Do not verify SSL certificates | False |

---

## 5. Library API

```python
from plecost import Scanner, ScanOptions

options = ScanOptions(
    url="https://target.com",
    concurrency=10,
    timeout=10,
    proxy="http://127.0.0.1:8080",      # optional
    modules=["fingerprint", "plugins", "cves"],  # None = all
    skip_modules=[],
    credentials=("admin", "secret"),    # optional
    stealth=False,
    aggressive=False,
    user_agent="Plecost/4.0",
    random_user_agent=False,
    verify_ssl=True,
    force=False,
)

scanner = Scanner(options)
result: ScanResult = await scanner.run()

# Structured access
print(result.wordpress_version)
print(result.is_wordpress)
for finding in result.findings:
    print(f"[{finding.severity}] {finding.id}: {finding.title}")
    print(f"  Remediation: {finding.remediation}")

result.to_json("report.json")
```

The `Scanner` is completely independent from Typer. The CLI is just a presentation layer on top of it.

---

## 6. Data Model

### Finding (individual finding)

```python
@dataclass
class Finding:
    id: str                    # "PC-MCFG-001" — stable and permanent
    remediation_id: str        # "REM-MCFG-001" — stable remediation ID
    title: str                 # Short finding title
    severity: Severity         # CRITICAL / HIGH / MEDIUM / LOW / INFO
    description: str           # What was found and why it is a problem
    evidence: dict             # URL, headers, response snippet, etc.
    remediation: str           # What to do to fix it
    references: list[str]      # CVE links, OWASP, WP docs
    cvss_score: float | None   # Only for CVEs
    module: str                # Module that detected it
```

### Stable IDs by category

| Prefix | Category |
|---------|-----------|
| `PC-FP-NNN` | Fingerprint / version disclosure |
| `PC-USR-NNN` | User enumeration |
| `PC-AUTH-NNN` | Authentication |
| `PC-XMLRPC-NNN` | XML-RPC |
| `PC-REST-NNN` | REST API |
| `PC-CVE-NNN` | CVE in core/plugin/theme |
| `PC-MCFG-NNN` | Misconfiguration |
| `PC-DIR-NNN` | Directory listing |
| `PC-HDR-NNN` | HTTP headers |
| `PC-SSL-NNN` | SSL/TLS |
| `PC-DBG-NNN` | Debug exposure |
| `PC-CNT-NNN` | Content analysis |
| `PC-WAF-NNN` | WAF detection |
| `PC-PLG-NNN` | Plugin-specific |
| `PC-THM-NNN` | Theme-specific |

IDs are **permanent** across versions. They are not reused or renumbered even if a check is removed.

### ScanResult

```python
@dataclass
class ScanResult:
    scan_id: str               # UUID per execution
    url: str
    timestamp: datetime
    duration_seconds: float
    is_wordpress: bool
    wordpress_version: str | None
    plugins: list[Plugin]
    themes: list[Theme]
    users: list[User]
    waf_detected: str | None
    findings: list[Finding]
    summary: ScanSummary       # Count by severity
```

---

## 7. CVE Database

### Strategy
- GitHub Action updates the DB **daily** using NVD API 2.0 + public WPScan Vulnerability DB
- The DB is published as a **release artifact** on GitHub (SQLite + pre-processed JSON)
- Plecost downloads the DB with `plecost update-db` (verifies SHA256 hash)
- The DB is stored in `~/.plecost/db/`

### SQLite Structure
```sql
-- Vulnerabilities indexed by software + version
CREATE TABLE vulnerabilities (
    id TEXT PRIMARY KEY,        -- "PC-CVE-001" or CVE-YYYY-NNNNN
    software_type TEXT,         -- "core" | "plugin" | "theme"
    software_slug TEXT,         -- "wordpress" | "woocommerce" | "twentytwentyfour"
    version_from TEXT,
    version_to TEXT,
    cvss_score REAL,
    severity TEXT,
    title TEXT,
    description TEXT,
    remediation TEXT,
    references TEXT,            -- JSON array
    has_exploit INTEGER,        -- 0 | 1
    published_at TEXT
);

-- Plugin wordlist (known slugs)
CREATE TABLE plugins_wordlist (
    slug TEXT PRIMARY KEY,
    last_updated TEXT,
    active_installs INTEGER
);

-- Theme wordlist
CREATE TABLE themes_wordlist (
    slug TEXT PRIMARY KEY,
    last_updated TEXT
);
```

---

## 8. Distribution

### pip
```bash
pip install plecost
pip install plecost[fast]    # includes uvloop
```

### Docker
```bash
docker run --rm ghcr.io/cr0hn/plecost scan https://target.com
docker run --rm ghcr.io/cr0hn/plecost scan https://target.com \
  --proxy http://host.docker.internal:8080 \
  --output /data/report.json \
  -v $(pwd):/data
```

---

## 9. Testing Strategy

### Test types

#### Unit tests (`tests/unit/`)
- HTML, feed, header parsing (no network)
- Version correlation with CVE DB (DB mocks)
- Stable IDs: no duplicates, correct format, none change between versions
- Dataclass serialization/deserialization
- Each finding has its associated remediation

#### Integration tests (`tests/integration/`)
- Scheduler: dependency graph, correct parallelism
- HTTP client: proxy, auth, timeouts, retries (with respx mock)
- CVE DB download and parsing
- Reporters: valid JSON, complete and with all fields

#### Functional tests (`tests/functional/`)
- Docker Compose spins up deliberately vulnerable WordPress 6.x
- End-to-end scan verifies **exact** expected findings
- Authenticated scan detects additional findings
- Stealth mode generates fewer requests
- CLI via subprocess: flags, valid JSON output

#### Contract tests (`tests/contract/`)
- `Scanner(options).run()` always returns a complete `ScanResult`
- `PC-XXX-NNN` and `REM-XXX-NNN` IDs are invariant between versions
- The public API does not break between minor versions

#### Property-based tests (`tests/property/`)
- Malformed/extreme URLs do not crash the scanner
- Rare or malformed WP/plugin versions do not crash the parser
- Truncated/malformed HTTP responses do not crash the modules

### Infrastructure
- **pytest** + **pytest-asyncio**
- **respx** for mocking httpx in unit/integration
- **Docker Compose** with WordPress 6.x + MySQL + vulnerable plugins for functional tests
- **Hypothesis** for property-based tests
- **coverage** with a minimum threshold of 80%
- **GitHub Actions**: unit + integration on each PR; functional tests daily

### Test WordPress Docker
The `docker-compose.test.yml` includes:
- WordPress with deliberately outdated version
- Known vulnerable plugins installed (e.g.: WP File Manager < 6.9)
- `WP_DEBUG=true`, directory listing enabled
- XML-RPC active, REST API unrestricted
- "admin" user with weak password
- Security headers absent

---

## 10. GitHub Actions

### `update-cve-db.yml` (daily)
1. Downloads vulnerabilities from NVD API 2.0 (WordPress + plugins + themes)
2. Downloads updated plugin wordlist from WordPress.org
3. Builds SQLite + pre-processed JSON
4. Publishes as release artifact with SHA256
5. Updates `db/latest.json` with URL and hash

### `ci.yml` (on each PR)
1. Linting (ruff)
2. Type checking (mypy)
3. Unit tests
4. Integration tests
5. Coverage report

### `docker.yml` (on each release)
1. Build Docker image
2. Push to `ghcr.io/cr0hn/plecost`

---

## 11. README

The README will include:
- Plecost logo/ASCII art banner
- Badges: CI, pip version, Docker pulls, CVE DB last update
- Demo GIF of a complete scan
- Installation (pip, Docker)
- Quick usage (3 examples in 30 seconds)
- Complete module and capabilities table
- Finding IDs table
- Comparison with WPScan, Wordfence, ScanTower
- Contributing guide
- License
