```
██████╗ ██╗     ███████╗ ██████╗ ██████╗ ███████╗████████╗
██╔══██╗██║     ██╔════╝██╔════╝██╔═══██╗██╔════╝╚══██╔══╝
██████╔╝██║     █████╗  ██║     ██║   ██║███████╗   ██║
██╔═══╝ ██║     ██╔══╝  ██║     ██║   ██║╚════██║   ██║
██║     ███████╗███████╗╚██████╗╚██████╔╝███████║   ██║
╚═╝     ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝   ╚═╝
                                                  v4.0.0
```

# Plecost — Professional WordPress Security Scanner

[![CI](https://github.com/Plecost/plecost/actions/workflows/ci.yml/badge.svg)](https://github.com/Plecost/plecost/actions)
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Fplecost%2Fplecost-blue)](https://ghcr.io/plecost/plecost)
[![PyPI](https://img.shields.io/pypi/v/plecost.svg)](https://pypi.org/project/plecost/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![License: PolyForm NC](https://img.shields.io/badge/License-PolyForm%20NC%201.0-blue)](https://polyformproject.org/licenses/noncommercial/1.0.0/)

**Fully async, zero-interaction WordPress security scanner built for professionals.**

Plecost v4.0 detects vulnerabilities in WordPress core, plugins, and themes — enumerates users, identifies misconfigurations, and correlates everything against a daily-updated CVE database. Built on Python 3.11+ with `httpx` and `asyncio`, it runs as a CLI tool, a Python library, or inside Celery workers with a consistent, automation-friendly output format.

---

## Table of Contents

- [Demo](#demo)
- [Quick Start](#quick-start)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Examples](#basic-examples)
  - [Multi-Target Workflow](#multi-target-workflow)
  - [All Flags](#all-flags)
- [Environment Variables](#environment-variables)
- [CLI Commands Reference](#cli-commands-reference)
  - [plecost scan](#plecost-scan)
  - [plecost update-db](#plecost-update-db)
  - [plecost modules list](#plecost-modules-list)
  - [plecost explain](#plecost-explain)
- [CVE Database Management](#cve-database-management)
  - [How the patch system works](#how-the-patch-system-works)
- [Detection Modules](#detection-modules)
- [Finding IDs](#finding-ids)
- [Output Formats](#output-formats)
- [Library Usage](#library-usage)
- [Architecture](#architecture)
- [Performance](#performance)
- [Troubleshooting](#troubleshooting)
- [Comparison](#comparison)
- [License](#license)

---

## Demo

```
$ plecost scan https://example.com

  Plecost v4.0 — WordPress Security Scanner
  Target: https://example.com
  Started: 2026-04-12 09:00:00

  [+] WordPress detected: 6.4.2
  [+] WAF detected: Cloudflare

  Plugins discovered (3)
  ┌─────────────────────┬─────────┬──────────────────┐
  │ Plugin              │ Version │ Status           │
  ├─────────────────────┼─────────┼──────────────────┤
  │ woocommerce         │ 8.2.1   │ Vulnerable       │
  │ contact-form-7      │ 5.8     │ OK               │
  │ elementor           │ 3.17.0  │ OK               │
  └─────────────────────┴─────────┴──────────────────┘

  Themes discovered (1)
  ┌──────────────────┬─────────┬────────────┐
  │ Theme            │ Version │ Status     │
  ├──────────────────┼─────────┼────────────┤
  │ twentytwentyfour │ 1.2     │ OK         │
  └──────────────────┴─────────┴────────────┘

  Findings (7)
  ┌────────────────┬──────────────────────────────────────────┬──────────┐
  │ ID             │ Title                                    │ Severity │
  ├────────────────┼──────────────────────────────────────────┼──────────┤
  │ PC-CVE-001     │ WooCommerce SQLi (CVE-2023-28121)        │ CRITICAL │
  │ PC-MCFG-009    │ readme.html discloses WordPress version  │ LOW      │
  │ PC-HDR-001     │ Missing Strict-Transport-Security        │ MEDIUM   │
  │ PC-USR-001     │ User enumeration via REST API            │ MEDIUM   │
  │ PC-XMLRPC-001  │ XML-RPC interface accessible             │ MEDIUM   │
  │ PC-SSL-001     │ HTTP does not redirect to HTTPS          │ HIGH     │
  │ PC-REST-001    │ REST API user data exposed               │ LOW      │
  └────────────────┴──────────────────────────────────────────┴──────────┘

  Summary: 1 Critical  1 High  3 Medium  2 Low
  Duration: 4.2s
```

---

## Quick Start

```bash
# Install
pip install plecost

# Download the CVE database (first time)
plecost update-db

# Run a scan
plecost scan https://target.com

# Authenticated scan with JSON output
plecost scan https://target.com --user admin --password secret --output report.json

# Stealth mode (random UA, passive checks only)
plecost scan https://target.com --stealth
```

---

## Requirements

- **Python 3.11 or later**
- **pip** (or Docker, see [Installation](#installation))
- SQLite3 (included in Python's standard library)
- Internet access for CVE database updates (NVD API)

---

## Installation

### pip

```bash
pip install plecost
pip install plecost[fast]    # includes uvloop for higher throughput
```

### From source

```bash
git clone https://github.com/Plecost/plecost.git
cd plecost
pip install -e .
pip install -e ".[dev]"      # include dev/test dependencies
```

### Docker

```bash
docker run --rm ghcr.io/Plecost/plecost scan https://target.com

# With proxy and JSON output saved locally
docker run --rm -v $(pwd):/data ghcr.io/Plecost/plecost scan https://target.com \
  --proxy http://host.docker.internal:8080 \
  --output /data/report.json
```

---

## Usage

### Basic Examples

```bash
# Scan with authentication
plecost scan https://target.com --user admin --password secret

# Route through a proxy (Burp Suite, OWASP ZAP, SOCKS5)
plecost scan https://target.com --proxy http://127.0.0.1:8080
plecost scan https://target.com --proxy socks5://127.0.0.1:1080

# Run only specific modules
plecost scan https://target.com --modules fingerprint,plugins,cves

# Skip modules you don't need
plecost scan https://target.com --skip-modules content_analysis,waf

# Aggressive mode (max concurrency: 50 parallel requests)
plecost scan https://target.com --aggressive

# Stealth mode (random User-Agent, passive detection only, slower)
plecost scan https://target.com --stealth

# Save results as JSON
plecost scan https://target.com --output report.json

# Suppress low-severity findings (show HIGH and CRITICAL only)
plecost scan https://target.com --quiet

# Scan without verifying SSL certificate
plecost scan https://target.com --no-verify-ssl

# Force scan even if WordPress is not detected
plecost scan https://target.com --force
```

### Multi-Target Workflow

```bash
# Scan a list of targets and save individual JSON reports
while read url; do
  plecost scan "$url" --output "reports/$(echo $url | tr '/:' '_').json" --quiet
done < targets.txt
```

### All Flags

| Flag | Description | Default | Env Var |
|------|-------------|---------|---------|
| `--concurrency N` | Number of parallel requests | 10 | — |
| `--timeout N` | Request timeout in seconds | 10 | `PLECOST_TIMEOUT` |
| `--proxy URL` | HTTP or SOCKS5 proxy URL | None | — |
| `--user / -u` | WordPress username for authenticated scan | None | — |
| `--password / -p` | WordPress password for authenticated scan | None | — |
| `--modules` | Comma-separated list of modules to run | all | — |
| `--skip-modules` | Comma-separated list of modules to skip | none | — |
| `--stealth` | Random UA, slower pacing, passive checks only | False | — |
| `--aggressive` | Max concurrency (50 parallel requests) | False | — |
| `--output / -o` | Save JSON report to file | None | `PLECOST_OUTPUT` |
| `--random-user-agent` | Rotate User-Agent on each request | False | — |
| `--no-verify-ssl` | Skip SSL certificate verification | False | — |
| `--force` | Continue scan even if WordPress is not detected | False | — |
| `--quiet` | Show only HIGH and CRITICAL findings | False | — |

---

## Environment Variables

All key settings can be configured via environment variables, making Plecost easy to use in CI/CD pipelines, Docker Compose, and automation scripts.

| Variable | Purpose | Used by | Default |
|----------|---------|---------|---------|
| `PLECOST_TIMEOUT` | Request timeout in seconds | `scan` | 10 |
| `PLECOST_OUTPUT` | Output file path for JSON report | `scan` | — |
| `PLECOST_DB_URL` | Database URL (SQLite or PostgreSQL) | `update-db` | `sqlite:///$HOME/.plecost/db/plecost.db` |
| `GITHUB_TOKEN` | GitHub token to avoid download rate limiting | `update-db` | — |

### Example: CI/CD pipeline

```bash
export NVD_API_KEY=your-nvd-api-key
export PLECOST_DB_URL=sqlite:////data/plecost.db
export PLECOST_OUTPUT=/reports/scan.json
export PLECOST_TIMEOUT=30

plecost update-db
plecost scan https://target.com --quiet
```

### Example: Docker Compose

```yaml
services:
  scanner:
    image: ghcr.io/Plecost/plecost
    environment:
      - PLECOST_TIMEOUT=30
      - PLECOST_OUTPUT=/reports/scan.json
      - NVD_API_KEY=${NVD_API_KEY}
    volumes:
      - ./reports:/reports
    command: scan https://target.com
```

---

## CLI Commands Reference

### plecost scan

Scans a WordPress target and reports findings.

```bash
plecost scan https://target.com [OPTIONS]
```

See [All Flags](#all-flags) for the full option list.

### plecost update-db

Downloads the latest pre-built CVE database from GitHub releases. This is the recommended command for **end users** — fast, no NVD API access required.

```bash
plecost update-db [--db-url sqlite:///path/to/plecost.db] [--token GITHUB_TOKEN]
```

| Option | Description | Env Var |
|--------|-------------|---------|
| `--db-url` | Database destination URL | `PLECOST_DB_URL` |
| `--token` | GitHub token (optional, avoids rate limiting) | `GITHUB_TOKEN` |

### plecost modules list

Lists all available detection modules with their names and dependency graph.

```bash
plecost modules list
```

### plecost explain

Prints the full technical description, impact, and remediation steps for any finding ID.

```bash
plecost explain PC-XMLRPC-002
plecost explain PC-CVE-CVE-2023-28121
plecost explain PC-MCFG-009
```

---

## CVE Database Management

Plecost ships with a local SQLite CVE database covering WordPress core, plugins, and themes. The database is stored at:

```
~/.plecost/db/plecost.db      (Linux / macOS)
%USERPROFILE%\.plecost\db\plecost.db    (Windows)
```

### Which command to use?

| Scenario | Command |
|----------|---------|
| First install / update as end user | `plecost update-db` |
| Self-hosted or custom DB generation | [`plecost-db build-db`](https://github.com/Plecost/plecost-db) |
| Daily CI/CD incremental update | [`plecost-db sync-db`](https://github.com/Plecost/plecost-db) |

### How it works

1. **`update-db`** — Downloads a pre-built, compressed database from the [latest GitHub release](https://github.com/Plecost/plecost-db/releases). Fast (~1 MB download, seconds to complete).

2. **`plecost-db build-db`** — Queries the [NVD API v2.0](https://nvd.nist.gov/developers/vulnerabilities) for all `keywordSearch=wordpress` CVEs from the past N years. Parses CPE 2.3 entries, applies Jaro-Winkler fuzzy matching to correlate CVE product names against ~50,000 known plugin/theme slugs, and stores results in SQLite. Slow (30–60 min without API key). See [plecost-db](https://github.com/Plecost/plecost-db).

3. **`plecost-db sync-db`** — Reads the `last_nvd_sync` timestamp from the database, fetches only CVEs modified since that date via `lastModStartDate`, and upserts new or updated records. Runs daily via GitHub Actions. See [plecost-db](https://github.com/Plecost/plecost-db).

### How the patch system works

Plecost uses an **incremental JSON patch system** instead of downloading a full SQLite database each day:

| Run | What happens | Typical size |
|-----|-------------|--------------|
| First `update-db` | Downloads `full.json` with all historical CVEs | ~10–50 MB |
| Subsequent `update-db` | Downloads only today's patch (new/modified CVEs) | <100 KB |
| No changes | Compares checksum only, downloads nothing | 64 bytes |

Each daily patch is a self-contained JSON file verified with SHA256 before being applied.
For architecture details, see [`plecost-db/docs/cve-patch-system/`](https://github.com/Plecost/plecost-db/tree/main/docs/cve-patch-system).

### Using PostgreSQL

Plecost supports PostgreSQL for production or team deployments:

```bash
pip install plecost[postgres]

plecost scan https://target.com --db-url postgresql+asyncpg://user:pass@host/plecost
# or via env var:
export PLECOST_DB_URL=postgresql+asyncpg://user:pass@host/plecost
```

To build the database into PostgreSQL, use [`plecost-db`](https://github.com/Plecost/plecost-db):

```bash
plecost-db build-db --db-url postgresql+asyncpg://user:pass@host/plecost
```

---

## Detection Modules

Plecost ships **15 independent detection modules** that run in parallel, with an explicit dependency graph for maximum throughput.

| Module | Description | Finding IDs |
|--------|-------------|-------------|
| `fingerprint` | WordPress version detection via meta tag, readme, RSS, feed, wp-login | PC-FP-001, PC-FP-002 |
| `waf` | WAF/CDN detection: Cloudflare, Sucuri, Wordfence, Imperva, AWS WAF, Akamai, Fastly | PC-WAF-001 |
| `plugins` | Plugin enumeration: passive HTML scan + brute-force against `readme.txt` | PC-PLG-NNN |
| `themes` | Theme enumeration: passive + brute-force via `style.css` | PC-THM-001 |
| `users` | User enumeration via REST API and author archive pages | PC-USR-001, PC-USR-002 |
| `xmlrpc` | XML-RPC checks: access, `pingback.ping` (DoS vector), `system.listMethods` | PC-XMLRPC-001/002/003 |
| `rest_api` | REST API exposure: link disclosure, oEmbed, CORS misconfiguration | PC-REST-001/002/003 |
| `misconfigs` | 12 misconfiguration checks: `wp-config.php`, `.env`, `.git`, `debug.log`, etc. | PC-MCFG-001 to 012 |
| `directory_listing` | Open directory listing in `wp-content/` subdirectories | PC-DIR-001 to 004 |
| `http_headers` | Missing security headers: HSTS, CSP, X-Frame-Options, X-Content-Type, etc. | PC-HDR-001 to 008 |
| `ssl_tls` | SSL/TLS hygiene: HTTP→HTTPS redirect, certificate validity, HSTS preload | PC-SSL-001/002/003 |
| `debug_exposure` | `WP_DEBUG` active, PHP version disclosure via headers | PC-DBG-001, PC-DBG-003 |
| `content_analysis` | Card skimming scripts, suspicious iframes, hardcoded API keys/secrets | PC-CNT-001/002/003 |
| `auth` | Authenticated checks: login verification, open user registration | PC-AUTH-001/002 |
| `cves` | CVE correlation for core + plugins + themes against daily-updated local DB | PC-CVE-{CVE-ID} |

---

## Finding IDs

All finding IDs follow a stable, permanent naming convention. IDs will never be renamed or reassigned — safe to reference in dashboards, ticketing systems, and automation rules.

| Prefix | Category | Examples |
|--------|----------|---------|
| `PC-FP-NNN` | Fingerprint / version disclosure | PC-FP-001 (meta tag), PC-FP-002 (readme.html) |
| `PC-USR-NNN` | User enumeration | PC-USR-001 (REST API), PC-USR-002 (author archives) |
| `PC-AUTH-NNN` | Authentication issues | PC-AUTH-001 (login verified), PC-AUTH-002 (open registration) |
| `PC-XMLRPC-NNN` | XML-RPC exposure | PC-XMLRPC-001 (accessible), PC-XMLRPC-002 (pingback DoS) |
| `PC-REST-NNN` | REST API exposure | PC-REST-001 to 003 |
| `PC-CVE-{ID}` | CVE correlations | PC-CVE-CVE-2024-1234 |
| `PC-MCFG-NNN` | Misconfigurations | PC-MCFG-001 (wp-config.php exposed) to PC-MCFG-012 |
| `PC-DIR-NNN` | Directory listing | PC-DIR-001 to PC-DIR-004 |
| `PC-HDR-NNN` | HTTP security headers | PC-HDR-001 (HSTS missing) to PC-HDR-008 (X-Powered-By) |
| `PC-SSL-NNN` | SSL/TLS hygiene | PC-SSL-001 to PC-SSL-003 |
| `PC-DBG-NNN` | Debug exposure | PC-DBG-001 (WP_DEBUG active), PC-DBG-003 (PHP version leak) |
| `PC-CNT-NNN` | Malicious content | PC-CNT-001 (card skimmer), PC-CNT-002 (iframe), PC-CNT-003 (secrets) |
| `PC-WAF-NNN` | WAF detection | PC-WAF-001 |

Use `plecost explain <ID>` for full technical description and remediation steps for any finding.

---

## Output Formats

### Terminal output (default)

Rich-formatted tables with color-coded severities. Use `--quiet` to suppress LOW/MEDIUM findings.

### JSON output

```bash
plecost scan https://target.com --output report.json
```

The JSON report follows this schema:

```json
{
  "url": "https://target.com",
  "scanned_at": "2026-04-12T09:00:00Z",
  "is_wordpress": true,
  "wordpress_version": "6.4.2",
  "waf_detected": "Cloudflare",
  "plugins": [
    { "slug": "woocommerce", "version": "8.2.1" }
  ],
  "themes": [
    { "slug": "twentytwentyfour", "version": "1.2" }
  ],
  "users": ["admin", "editor"],
  "findings": [
    {
      "id": "PC-CVE-CVE-2023-28121",
      "remediation_id": "REM-CVE-CVE-2023-28121",
      "title": "WooCommerce SQLi (CVE-2023-28121)",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "description": "...",
      "remediation": "Update WooCommerce to version 7.8.0 or later.",
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-28121"],
      "evidence": { "plugin": "woocommerce", "version": "8.2.1" },
      "module": "cves"
    }
  ],
  "summary": {
    "critical": 1,
    "high": 1,
    "medium": 3,
    "low": 2
  },
  "duration_seconds": 4.2
}
```

---

## Library Usage

Plecost is designed as a first-class Python library for use in security automation pipelines, CI/CD gates, and vulnerability management platforms.

### Standalone Script

```python
import asyncio
from plecost import Scanner, ScanOptions

async def scan():
    options = ScanOptions(
        url="https://target.com",
        concurrency=10,
        timeout=10,
        proxy="http://127.0.0.1:8080",               # optional
        modules=["fingerprint", "plugins", "cves"],   # None = all modules
        skip_modules=[],
        credentials=("admin", "secret"),              # optional
        stealth=False,
        aggressive=False,
    )

    scanner = Scanner(options)
    result = await scanner.run()

    print(f"WordPress: {result.is_wordpress}")
    print(f"Version:   {result.wordpress_version}")
    print(f"WAF:       {result.waf_detected}")
    print(f"Plugins:   {len(result.plugins)}")
    print(f"Users:     {len(result.users)}")

    for finding in result.findings:
        print(f"[{finding.severity.value}] {finding.id}: {finding.title}")
        print(f"  Remediation: {finding.remediation}")

    result.to_json("report.json")

asyncio.run(scan())
```

### Celery Workers

```python
from celery import Celery
from plecost import Scanner, ScanOptions
import asyncio

app = Celery("tasks")

@app.task
def scan_wordpress(url: str) -> dict:
    opts = ScanOptions(url=url, modules=["fingerprint", "plugins", "cves"])
    result = asyncio.run(Scanner(opts).run())
    return {
        "url": result.url,
        "is_wordpress": result.is_wordpress,
        "critical": result.summary.critical,
        "high": result.summary.high,
        "findings": [f.id for f in result.findings],
    }
```

---

## Architecture

```
CLI / Python API
      │
      ▼
 ScanOptions → ScanContext
                    │
                    ▼
               Scheduler (async task graph)
                    │
      ┌─────────────┼──────────────────────────┐
      ▼             ▼                           ▼
[fingerprint]    [waf]              (runs in parallel from start)
      │
      ├──────────┬──────────┬──────────┬──────────┬────────────┐
      ▼          ▼          ▼          ▼          ▼            ▼
 [plugins]  [themes]   [users]   [xmlrpc]  [misconfigs]  [http_headers]
      │          │          │          │          │            │
      └────┬─────┘          └──────────┴──────────┴────────────┘
           ▼
        [cves]  (depends on plugins + themes results)
           │
           ▼
  [Terminal Reporter] / [JSON Reporter]
```

Each module is an independent async coroutine. The scheduler resolves dependencies and runs tasks at maximum parallelism — modules without interdependencies execute concurrently from the start.

---

## Performance

Plecost is designed for speed. All network I/O is non-blocking, and the task graph runs modules at maximum concurrency.

| Scenario | Concurrency | Avg. Duration |
|----------|-------------|---------------|
| Full scan, no WAF | 10 (default) | ~4–8s |
| Full scan, Cloudflare CDN | 10 (default) | ~8–15s |
| Aggressive mode | 50 | ~2–4s |
| Stealth mode | 3 | ~20–40s |
| Plugin brute-force (10k list) | 10 | ~90s |

Throughput scales linearly with `--concurrency` up to the target's rate limits. Use `--aggressive` for internal targets or lab environments. If you encounter 429 responses, reduce concurrency with `--concurrency 3`.

---

## Troubleshooting

### "CVE database not found"

The local CVE database has not been downloaded yet. Run:

```bash
plecost update-db
```

If you want to store the database in a custom location:

```bash
plecost update-db --db-url sqlite:////path/to/custom/plecost.db
# or:
export PLECOST_DB_URL=sqlite:////path/to/custom/plecost.db
plecost update-db
```

### Target returns 429 (rate limiting)

Reduce concurrency:

```bash
plecost scan https://target.com --concurrency 3
```

Or use stealth mode, which includes automatic pacing:

```bash
plecost scan https://target.com --stealth
```

### SSL certificate errors

For testing environments with self-signed certificates:

```bash
plecost scan https://target.com --no-verify-ssl
```

> **Warning:** Only use `--no-verify-ssl` in controlled environments. Disabling certificate verification exposes you to man-in-the-middle attacks.

### WordPress not detected

If you know the target is WordPress but it's behind a WAF or custom setup:

```bash
plecost scan https://target.com --force
```

---

## Comparison

| Feature | Plecost v4 | WPScan | Wordfence | ScanTower |
|---------|-----------|--------|-----------|-----------|
| Python library API | Yes | No | No | No |
| Async (httpx) | Yes | No | No | No |
| WAF detection (7 providers) | Yes | Yes | No | Yes |
| Plugin brute-force | Yes | Yes | No | Yes |
| CVE correlation (daily updates) | Yes | Yes (API key) | Yes | Yes |
| Content / skimmer analysis | Yes | No | Yes | No |
| Stable finding IDs | Yes | No | No | No |
| Docker native | Yes | Yes | No | No |
| Celery / library compatible | Yes | No | No | No |
| No external API dependency | Yes | No | No | No |
| PostgreSQL support | Yes | No | No | No |

---

## License

Plecost is distributed under the **[PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/)** — a standard, lawyer-drafted noncommercial license.

**Free for:**
- Personal security research and penetration testing
- Internal corporate security audits (not resold)
- Academic, educational, and public research use
- Charitable and government organizations
- Open source projects

**Requires a commercial license for:**
- Offering scanning as a service (SaaS, API)
- Including Plecost in a commercial product or paid offering
- Any use generating direct or indirect revenue

For commercial licensing inquiries: **cr0hn@cr0hn.com**

See [LICENSE](LICENSE) for full terms.

---

**Author:** Dani (cr0hn) — [cr0hn@cr0hn.com](mailto:cr0hn@cr0hn.com)
