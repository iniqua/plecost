<div align="center">
  <img src="https://avatars.githubusercontent.com/u/275428243?s=200&u=235faecc7c473dc147aa16990cbada030e4703c5&v=4" alt="Plecost" width="120" />
  <h1>Plecost</h1>
  <p><strong>Professional WordPress Security Scanner</strong></p>
  <p>Async-first, library-friendly, no external API required.</p>

  [![CI](https://github.com/Plecost/plecost/actions/workflows/ci.yml/badge.svg)](https://github.com/Plecost/plecost/actions)
  [![PyPI](https://img.shields.io/pypi/v/plecost.svg)](https://pypi.org/project/plecost/)
  [![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
  [![Docker](https://img.shields.io/badge/docker-ghcr.io%2Fplecost%2Fplecost-blue)](https://ghcr.io/plecost/plecost)
  [![License: PolyForm NC](https://img.shields.io/badge/License-PolyForm%20NC%201.0-lightgrey)](https://polyformproject.org/licenses/noncommercial/1.0.0/)
</div>

---

## Table of Contents

- [What is Plecost?](#what-is-plecost)
- [Plecost vs WPScan](#plecost-vs-wpscan)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [CVE Database](#cve-database)
- [Scanning](#scanning)
- [Detection Modules](#detection-modules)
- [WooCommerce Security](#woocommerce-security)
- [WP eCommerce Security](#wp-ecommerce-security)
- [Output Formats](#output-formats)
- [Library Usage](#library-usage)
- [Environment Variables](#environment-variables)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)
- [Local Test Environment](#local-test-environment)
- [License](#license)

---

## What is Plecost?

Plecost detects vulnerabilities in WordPress installations — core, plugins, and themes — and correlates findings against a daily-updated local CVE database. It runs as a CLI tool, a Python library, or inside task queues like Celery, with a consistent and automation-friendly output format.

**No Ruby. No API key. No subscription. No data sent to third parties on every scan.**


## Plecost vs WPScan

Plecost was built from scratch to fix the limitations teams hit in production when using WPScan: API rate caps, external data dependencies, no library API, no async architecture, and a narrow detection surface.

### At a Glance

| Capability | Plecost v4 | WPScan |
|---|:---:|:---:|
| **Language / runtime** | Python 3.11+ | Ruby |
| **Async concurrent scanning** | ✅ httpx + asyncio | ❌ |
| **Python library API** | ✅ `from plecost import Scanner` | ❌ |
| **API key required** | ❌ never | ⚠️ required for CVE data |
| **CVE data — free tier limit** | ✅ unlimited (local DB) | ❌ 25 API tokens/day |
| **Offline scanning (CVEs included)** | ✅ | ❌ |
| **Data sent to third parties on scan** | ❌ none | ⚠️ every request |
| **Docker native** | ✅ | ✅ |
| **Celery / task queue compatible** | ✅ | ❌ |
| **PostgreSQL support (shared team)** | ✅ | ❌ |

### Scanning Capabilities

| Capability | Plecost v4 | WPScan |
|---|:---:|:---:|
| Fast mode (top 150 plugins / 50 themes) | ✅ | ❌ |
| Deep mode (4,750+ plugins / 900+ themes) | ✅ | ✅ |
| Configurable concurrency (10–50 requests) | ✅ | ✅ |
| Stealth mode (random UA + passive only) | ✅ | ✅ |
| Aggressive mode (50 parallel requests) | ✅ | ✅ |
| Authenticated scans | ✅ | ✅ |
| Proxy support (HTTP + SOCKS5) | ✅ | ✅ |
| Bulk scan (multiple URLs from file) | ✅ | ❌ |
| Pre-flight 403 detection (aborts cleanly) | ✅ | ❌ |
| Per-module options (`--module-option`) | ✅ | ❌ |
| Run / skip individual modules | ✅ | ✅ |
| Selective module list (`--modules`) | ✅ | ❌ |
| Auto-retry with SSL verification disabled | ✅ | ❌ |

### Vulnerability Detection

| Capability | Plecost v4 | WPScan |
|---|:---:|:---:|
| WordPress core fingerprinting | ✅ (meta, readme, RSS, wp-login) | ✅ |
| Plugin detection — passive HTML | ✅ | ✅ |
| Plugin detection — active wordlist | ✅ 4,750+ slugs | ✅ |
| Theme detection — passive HTML | ✅ | ✅ |
| Theme detection — active wordlist | ✅ 900+ themes | ✅ |
| CVE correlation (core + plugins + themes) | ✅ local DB, daily NVD sync | ✅ API |
| Exploit availability flag per CVE | ✅ | ✅ |
| CVSS scores per finding | ✅ | ✅ |
| WAF / CDN detection | ✅ 7 providers | ⚠️ limited |
| User enumeration — REST API | ✅ | ✅ |
| User enumeration — author archives | ✅ | ✅ |
| XML-RPC — access, pingback DoS, method list | ✅ 3 checks | ⚠️ basic |
| REST API — disclosure, oEmbed, CORS | ✅ 3 checks | ❌ |
| HTTP security headers | ✅ 8 checks (HSTS, CSP, X-Frame…) | ❌ |
| SSL / TLS misconfiguration | ✅ 3 checks | ❌ |
| Misconfiguration (wp-config, .env, .git…) | ✅ 12 checks | ⚠️ partial |
| Directory listing (wp-content subdirs) | ✅ | ❌ |
| Debug mode / PHP version disclosure | ✅ | ❌ |
| Open user registration | ✅ | ❌ |
| Content / card skimmer analysis | ✅ scripts, iframes, hardcoded keys | ❌ |
| Webshell detection | ✅ 147–523 paths | ❌ |
| Malicious upload detection (PHP in uploads) | ✅ | ❌ |
| **WooCommerce dedicated module** | ✅ 22 checks | ❌ |
| **WP eCommerce dedicated module** | ✅ 22 checks | ❌ |
| Semi-active eCommerce CVE probes | ✅ boolean-only, no time-based | ❌ |
| WooCommerce REST API auth bypass | ✅ CVE-2023-28121 | ❌ |
| WooCommerce IDOR / PII disclosure | ✅ CVE-2023-34000 | ❌ |

### Output and Integration

| Capability | Plecost v4 | WPScan |
|---|:---:|:---:|
| Rich terminal output (color-coded) | ✅ | ✅ |
| JSON output (stable schema) | ✅ | ✅ |
| Verbose real-time progress (`-v`) | ✅ | ✅ |
| Quiet mode (HIGH + CRITICAL only) | ✅ | ❌ |
| **Stable permanent finding IDs** | ✅ 79 IDs (`PC-MOD-NNN`) | ❌ |
| `plecost explain <ID>` — per-finding remediation | ✅ | ❌ |
| Safe to track findings in JIRA / ticketing | ✅ IDs never change | ❌ |
| Remediation ID per finding (`REM-MOD-NNN`) | ✅ | ❌ |
| i18n / multilingual output | ✅ EN + ES | ❌ |
| Included vulnerable test environment (DVWP) | ✅ Docker Compose | ❌ |

### Data Independence

> WPScan sends every scan to `wpscan.com` to look up CVE data. On the free tier you get **25 API tokens per day** — enough for a handful of targets. Plecost keeps the entire CVE database locally, updated daily via GitHub Actions with no per-scan network call to any third-party API.

| | Plecost v4 | WPScan |
|---|:---:|:---:|
| Local CVE database (SQLite / PostgreSQL) | ✅ | ❌ |
| Data sent externally on each scan | ❌ none | ✅ to wpscan.com |
| CVE updates mechanism | GitHub Actions, NVD API v2 | SaaS subscription |
| Daily incremental patch download | ✅ (< 100 KB/day) | — |
| First-run full database download | ✅ `plecost update-db` | — |
| Works fully air-gapped after DB download | ✅ | ❌ |
| SHA256 integrity check before download | ✅ | ❌ |


## Quick Start

```bash
pip install plecost

# Download the CVE database (first time only — takes a few seconds)
plecost update-db

# Scan a target
plecost scan https://target.wordpress.com
```

That's it. No account, no API key, no daemon running in the background.


## Installation

**pip**

```bash
pip install plecost
pip install plecost[fast]      # adds uvloop for higher throughput
pip install plecost[postgres]  # adds asyncpg for PostgreSQL support
```

**Docker**

```bash
docker run --rm ghcr.io/plecost/plecost scan https://target.com

# Save JSON report to local directory
docker run --rm -v $(pwd):/data ghcr.io/plecost/plecost scan https://target.com \
  --output /data/report.json
```

**From source**

```bash
git clone https://github.com/Plecost/plecost.git
cd plecost
pip install -e ".[dev]"
```


## CVE Database

Plecost ships with a **local SQLite database** covering WordPress core, plugins, and themes. It lives at `~/.plecost/db/plecost.db` and is never sent to any external service during scans.

**The database needs to be downloaded once before the first scan, and kept up to date thereafter.**

### First-time setup

```bash
plecost update-db
```

This downloads a pre-built snapshot from [plecost-db releases](https://github.com/Plecost/plecost-db/releases) (~10–50 MB). Subsequent runs only download the daily diff — typically under 100 KB.

### Keeping it current

Run `update-db` regularly (weekly is fine for most use cases):

```bash
plecost update-db
```

Plecost checks a SHA256 checksum before downloading anything. If nothing changed since your last run, no data is transferred.

### How the update mechanism works

The [plecost-db](https://github.com/Plecost/plecost-db) repository runs a GitHub Actions workflow daily at 02:00 UTC. It queries the [NVD API v2.0](https://nvd.nist.gov/developers/vulnerabilities) for all WordPress-related CVEs modified in the last 24 hours, applies Jaro-Winkler fuzzy matching to correlate CVE product names against ~50,000 known plugin/theme slugs, and publishes a small JSON patch file as a release asset.

When you run `plecost update-db`, it:
1. Downloads `index.json` from the `plecost-db` releases (64 bytes)
2. Compares its SHA256 against the local copy
3. Downloads only the missing patch files and applies them in order
4. On first run, downloads `full.json` instead (complete history)

| Run | What's downloaded | Typical size |
|-----|-------------------|--------------|
| First time | `full.json` (all CVEs) | 10–50 MB |
| Daily update | today's patch | < 100 KB |
| Already up to date | nothing (checksum match) | 64 bytes |

### Custom database location

```bash
# SQLite at a custom path
export PLECOST_DB_URL=sqlite:////data/plecost.db
plecost update-db
plecost scan https://target.com

# PostgreSQL (shared team setup)
pip install plecost[postgres]
export PLECOST_DB_URL=postgresql+asyncpg://user:pass@host/plecost
plecost update-db
plecost scan https://target.com
```


## Scanning

### Basic scan

```
$ plecost scan https://target.com

  Plecost v4.1 — WordPress Security Scanner
  Target: https://target.com

  WordPress 6.4.2 detected  |  WAF: Cloudflare

  Plugins (3)
    woocommerce        8.2.1    VULNERABLE
    contact-form-7     5.8      OK
    elementor          3.17.0   OK

  Findings (7)
    PC-CVE-CVE-2023-28121   WooCommerce SQLi                       CRITICAL
    PC-SSL-001              HTTP does not redirect to HTTPS         HIGH
    PC-HDR-001              Missing Strict-Transport-Security       MEDIUM
    PC-USR-001              User enumeration via REST API           MEDIUM
    PC-XMLRPC-001           XML-RPC interface accessible            MEDIUM
    PC-REST-001             REST API user data exposed              LOW
    PC-MCFG-009             readme.html discloses WP version        LOW

  Summary: 1 Critical  1 High  3 Medium  2 Low  |  Duration: 4.2s
```

### Common options

```bash
# Authenticated scan
plecost scan https://target.com --user admin --password secret

# Route traffic through Burp Suite or OWASP ZAP
plecost scan https://target.com --proxy http://127.0.0.1:8080

# Run only specific detection modules
plecost scan https://target.com --modules fingerprint,plugins,cves

# Aggressive mode — 50 parallel requests (use on internal targets)
plecost scan https://target.com --aggressive

# Deep mode — full wordlist (4750+ plugins, 900+ themes); default scans top 150/50
plecost scan https://target.com --deep

# Stealth mode — random UA, passive detection only, slower
plecost scan https://target.com --stealth

# Save results as JSON
plecost scan https://target.com --output report.json

# Show only HIGH and CRITICAL findings
plecost scan https://target.com --quiet
```

### All scan flags

| Flag | Description | Default |
|------|-------------|---------|
| `--concurrency N` | Parallel requests | 10 |
| `--timeout N` | Request timeout (seconds) | 10 |
| `--proxy URL` | HTTP or SOCKS5 proxy | — |
| `--user / -u` | WordPress username | — |
| `--password / -p` | WordPress password | — |
| `--modules` | Modules to run (comma-separated) | all |
| `--skip-modules` | Modules to skip | — |
| `--stealth` | Passive mode, random UA, slower pacing | off |
| `--aggressive` | Max concurrency (50 requests) | off |
| `--output / -o` | JSON output file | — |
| `--no-verify-ssl` | Skip certificate verification | off |
| `--force` | Scan even if WordPress not detected | off |
| `--deep` | Full wordlist scan (4750+ plugins, 900+ themes); default is top 150/50 | off |
| `--verbose / -v` | Real-time module progress and findings during scan | off |
| `--quiet` | Show only HIGH and CRITICAL findings | off |
| `--module-option` | Module-specific option: `MODULE:KEY=VALUE` (repeatable) | — |


## Detection Modules

Plecost runs **18 async modules** in parallel, wired through an explicit dependency graph. Modules without interdependencies run concurrently from the start; `cves` waits for `plugins` and `themes` to complete before correlating results against the local database.

| Module | What it checks | Finding IDs |
|--------|----------------|-------------|
| `fingerprint` | WordPress version (meta, readme, RSS, wp-login) | PC-FP-001/002 |
| `waf` | WAF/CDN detection (Cloudflare, Sucuri, Wordfence, Imperva, AWS, Akamai, Fastly) | PC-WAF-001 |
| `plugins` | Plugin enumeration — passive HTML + brute-force against `readme.txt` | PC-PLG-NNN |
| `themes` | Theme detection via passive scan + `style.css` brute-force | PC-THM-001 |
| `users` | User enumeration via REST API and author archive pages | PC-USR-001/002 |
| `xmlrpc` | XML-RPC access, `pingback.ping` DoS vector, `system.listMethods` | PC-XMLRPC-001/002/003 |
| `rest_api` | REST API link disclosure, oEmbed, CORS misconfiguration | PC-REST-001/002/003 |
| `misconfigs` | 12 checks: `wp-config.php`, `.env`, `.git`, `debug.log`, directory traversal... | PC-MCFG-001–012 |
| `directory_listing` | Open directory listing in `wp-content/` subdirs | PC-DIR-001–004 |
| `http_headers` | Missing HSTS, CSP, X-Frame-Options, X-Content-Type, Referrer-Policy... | PC-HDR-001–008 |
| `ssl_tls` | HTTP→HTTPS redirect, certificate validity, HSTS preload | PC-SSL-001/002/003 |
| `debug_exposure` | Active `WP_DEBUG`, PHP version disclosure via response headers | PC-DBG-001/003 |
| `content_analysis` | Card skimming scripts, suspicious iframes, hardcoded API keys | PC-CNT-001/002/003 |
| `auth` | Authenticated checks: login verification, open user registration | PC-AUTH-001/002 |
| `cves` | CVE correlation for core + plugins + themes against local DB | PC-CVE-{CVE-ID} |
| `webshells` | Webshell detection across upload paths (147–523 paths depending on mode) | PC-WS-NNN |
| `woocommerce` | WooCommerce-specific security checks (see below) | PC-WC-000–021 |
| `wp_ecommerce` | WP eCommerce-specific security checks (see below) | PC-WPEC-000–021 |

Use `plecost explain <ID>` for full technical detail and remediation steps on any finding ID.


## WooCommerce Security

The `woocommerce` module performs dedicated security checks for WooCommerce installations and its official extensions (Payments, Blocks, Stripe Gateway). It runs automatically when WooCommerce is detected.

### Passive checks (always on)

- **Fingerprinting** — detects WooCommerce version, active extensions (Payments, Blocks, Stripe Gateway), and exposed API namespaces
- **REST API without authentication** — checks whether `/wp-json/wc/v3/customers`, `/orders`, `/coupons`, and `/system-status` are accessible without credentials (CRITICAL/HIGH)
- **Sensitive file exposure** — directory listing on `/wp-content/uploads/wc-logs/`, access to `/wp-content/uploads/woocommerce_uploads/`

### Semi-active checks (opt-in)

Semi-active checks send additional HTTP requests that could leave traces in server logs. Enable explicitly:

```bash
plecost scan https://target.com --module-option woocommerce:mode=semi-active
```

| Check | CVE | CVSS |
|-------|-----|------|
| WooCommerce Payments authentication bypass | CVE-2023-28121 | 9.8 Critical |
| WooCommerce Stripe Gateway IDOR (PII disclosure) | CVE-2023-34000 | 7.5 High |

### Authenticated checks (optional)

Provide WooCommerce REST API credentials to unlock additional checks (system configuration disclosure, payment gateway enumeration):

```bash
plecost scan https://target.com \
  --module-option woocommerce:wc_consumer_key=ck_xxx \
  --module-option woocommerce:wc_consumer_secret=cs_xxx
```

### WooCommerce JSON output

When WooCommerce is detected, the scan result includes a dedicated `woocommerce` section:

```json
{
  "woocommerce": {
    "detected": true,
    "version": "8.5.2",
    "active_plugins": ["core", "payments", "blocks", "stripe-gateway"],
    "api_namespaces": ["wc/store/v1", "wc/v3"]
  }
}
```


## WP eCommerce Security

The `wp_ecommerce` module performs dedicated security checks for the **WP eCommerce** (wp-e-commerce) plugin. It runs automatically when WP eCommerce is detected.

> **Important:** WP eCommerce has been abandoned since 2020 (last version: 3.15.1). All current installations are vulnerable to unpatched CVEs. PC-WPEC-003 is always emitted when the plugin is detected.

### Passive checks (always on)

- **Fingerprinting** — detects version via `readme.txt`, active payment gateways (ChronoPay)
- **Directory exposure** — plugin directory listing, `uploads/wpsc/`, `uploads/wpsc/digital/` (digital downloads)
- **Admin scripts** — direct access to `wpsc-admin/db-backup.php` and `wpsc-admin/display-log.php`
- **ChronoPay endpoint** — callback endpoint accessibility check

### Semi-active checks (opt-in)

Enable explicitly:

```bash
plecost scan https://target.com --module-option wpec:mode=semi-active
```

| Check | CVE | CVSS |
|-------|-----|------|
| ChronoPay SQL Injection | CVE-2024-1514 | 9.8 Critical |
| PHP Object Injection via AJAX | CVE-2026-1235 | 8.1 High |

Detection is **boolean-only** (SQL error strings, deserialization patterns) — no time-based probes.

### WP eCommerce JSON output

When WP eCommerce is detected, the scan result includes a dedicated `wp_ecommerce` section:

```json
{
  "wp_ecommerce": {
    "detected": true,
    "version": "3.15.1",
    "active_gateways": ["chronopay"],
    "checks_run": ["readme", "directories", "sensitive_files", "chronopay_endpoint"]
  }
}
```


## Output Formats

### Terminal (default)

Rich-formatted tables with color-coded severities. Use `--quiet` to suppress LOW/MEDIUM findings.

### JSON

```bash
plecost scan https://target.com --output report.json
```

```json
{
  "url": "https://target.com",
  "scanned_at": "2026-04-13T09:00:00Z",
  "is_wordpress": true,
  "wordpress_version": "6.4.2",
  "waf_detected": "Cloudflare",
  "plugins": [{ "slug": "woocommerce", "version": "8.2.1" }],
  "themes": [{ "slug": "twentytwentyfour", "version": "1.2" }],
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
  "summary": { "critical": 1, "high": 1, "medium": 3, "low": 2 },
  "duration_seconds": 4.2,
  "blocked": false,
  "woocommerce": {
    "detected": true,
    "version": "8.2.1",
    "active_plugins": ["core", "payments", "blocks"],
    "api_namespaces": ["wc/store/v1", "wc/v3"]
  },
  "wp_ecommerce": null
}
```


## Library Usage

Plecost is a first-class Python library. The same logic that powers the CLI is available as an importable API — no subprocess, no parsing CLI output.

### Standalone script

```python
import asyncio
from plecost import Scanner, ScanOptions

async def main():
    options = ScanOptions(
        url="https://target.com",
        concurrency=10,
        timeout=10,
        modules=["fingerprint", "plugins", "cves"],  # None = all modules
    )
    result = await Scanner(options).run()

    print(f"WordPress {result.wordpress_version}  |  WAF: {result.waf_detected}")
    for finding in result.findings:
        print(f"[{finding.severity.value}] {finding.id}: {finding.title}")

asyncio.run(main())
```

### Celery workers

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
        "critical": result.summary.critical,
        "findings": [f.id for f in result.findings],
    }
```


## Environment Variables

| Variable | Description | Used by |
|----------|-------------|---------|
| `PLECOST_DB_URL` | Database URL (SQLite or PostgreSQL) | `update-db`, `scan` |
| `PLECOST_TIMEOUT` | Request timeout in seconds | `scan` |
| `PLECOST_OUTPUT` | JSON output file path | `scan` |
| `GITHUB_TOKEN` | GitHub token to avoid download rate limiting | `update-db` |


## Architecture

<img src="docs/architecture.svg" alt="Plecost architecture diagram" width="780"/>

Modules without interdependencies run concurrently from the start. `cves` waits for `plugins` and `themes` to complete so it has a full list of installed software to match against the CVE database.


## Troubleshooting

**"CVE database not found"**

The local database hasn't been downloaded yet:

```bash
plecost update-db
```

**Target returns 429 (rate limiting)**

```bash
# Reduce concurrency
plecost scan https://target.com --concurrency 3

# Or use stealth mode (includes automatic pacing)
plecost scan https://target.com --stealth
```

**SSL certificate errors**

```bash
plecost scan https://target.com --no-verify-ssl
```

> Only use `--no-verify-ssl` in controlled environments.

**Target returns 403 (scanner blocked)**

Plecost detects this automatically on the pre-flight probe and aborts cleanly with finding `PC-PRE-001`. Try a different IP, a proxy, or a different User-Agent:

```bash
plecost scan https://target.com --proxy http://127.0.0.1:8080
plecost scan https://target.com --random-user-agent
```

**WordPress not detected**

```bash
plecost scan https://target.com --force
```


## Local Test Environment

A self-contained Docker Compose environment — **Damn Vulnerable WordPress (DVWP)** — is included for local testing and development. It spins up a fully configured WordPress instance with a curated set of outdated, intentionally vulnerable plugins.

Located at [`tests/dvwp/`](tests/dvwp/).

### Start

```bash
cd tests/dvwp
docker compose up -d
docker compose logs wpcli -f   # watch setup (~60s), wait for plugin table
```

Once `wpcli` exits, the environment is ready:

| URL | Credentials |
|-----|-------------|
| http://localhost:8765 | — |
| http://localhost:8765/wp-admin | `admin` / `admin` |

### Pre-installed vulnerable plugins

| Plugin | Version | CVE |
|--------|---------|-----|
| wpDiscuz | 7.0.4 | CVE-2020-24186 — unauthenticated RCE via file upload (CVSS 9.8) |
| Contact Form 7 | 5.3.1 | CVE-2020-35489 — unrestricted file upload |
| WooCommerce | 5.0.0 | CVE-2021-32790 — multiple |
| WooCommerce Payments | 3.9.0 | CVE-2023-28121 — unauthenticated privilege escalation (CVSS 9.8) |
| WooCommerce Stripe Gateway | 4.3.0 | CVE-2019-15826 — order information disclosure |
| Easy Digital Downloads | 2.11.5 | CVE-2021-39351 — stored XSS |
| Give – Donation Plugin | 2.10.3 | CVE-2021-34634 — SQL injection |
| YITH WooCommerce Wishlist | 2.2.9 | CVE-2021-24987 — stored XSS |
| Ninja Forms | 3.4.34.2 | CVE-2021-34648 — unauthenticated email injection |
| Duplicator | 1.3.26 | CVE-2020-11738 — path traversal |
| Loginizer | 1.6.3 | CVE-2020-27615 — SQL injection |
| Elementor | 3.1.2 | CVE-2022-1329 — authenticated RCE |
| WP Super Cache | 1.7.1 | CVE-2021-33203 — authenticated XSS |
| Wordfence | 7.5.0 | CVE-2021-24875 — reflected XSS |

### Run plecost against it

```bash
plecost scan http://localhost:8765 -v
plecost scan http://localhost:8765 --deep -v
```

### Reset

```bash
docker compose down -v && docker compose up -d
```

See [`tests/dvwp/README.md`](tests/dvwp/README.md) for full details.

> **Warning:** For local/isolated use only. Never expose to the internet.


## License

Plecost is distributed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/).

**Free for:** personal security research, internal corporate audits, academic and educational use, open source projects, charitable and government organizations.

**Requires a commercial license for:** scanning-as-a-service, inclusion in a commercial product, or any use generating direct or indirect revenue.

For commercial licensing: **cr0hn@cr0hn.com** (Dani) · **ffranz@mrlooquer.com** (Fran)
