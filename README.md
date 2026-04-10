```
██████╗ ██╗     ███████╗ ██████╗ ██████╗ ███████╗████████╗
██╔══██╗██║     ██╔════╝██╔════╝██╔═══██╗██╔════╝╚══██╔══╝
██████╔╝██║     █████╗  ██║     ██║   ██║███████╗   ██║
██╔═══╝ ██║     ██╔══╝  ██║     ██║   ██║╚════██║   ██║
██║     ███████╗███████╗╚██████╗╚██████╔╝███████║   ██║
╚═╝     ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝   ╚═╝
                                                  v4.0.0
```

# Plecost — The Best Black-Box WordPress Security Scanner

[![CI](https://github.com/cr0hn/plecost/actions/workflows/ci.yml/badge.svg)](https://github.com/cr0hn/plecost/actions)
[![PyPI](https://img.shields.io/pypi/v/plecost.svg)](https://pypi.org/project/plecost/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![License: FSL-1.1-MIT](https://img.shields.io/badge/License-FSL--1.1--MIT-blue.svg)](LICENSE)

Plecost v4.0 is a fully async, zero-interaction WordPress security scanner built for professionals. It detects vulnerabilities in core, plugins, and themes, enumerates users, identifies misconfigurations, and correlates everything against a daily-updated CVE database.

---

## Quick Start (30 seconds)

```bash
# Install
pip install plecost

# Scan
plecost scan https://target.com

# Full scan with auth and JSON output
plecost scan https://target.com --user admin --password secret --output report.json

# Stealth mode (random UA, passive only)
plecost scan https://target.com --stealth
```

---

## Installation

### pip
```bash
pip install plecost
pip install plecost[fast]    # includes uvloop for better performance
```

### Docker
```bash
docker run --rm ghcr.io/cr0hn/plecost scan https://target.com

# With proxy and JSON output
docker run --rm -v $(pwd):/data ghcr.io/cr0hn/plecost scan https://target.com \
  --proxy http://host.docker.internal:8080 \
  --output /data/report.json
```

---

## Features

### 15 Detection Modules

| Module | Description | Finding IDs |
|--------|-------------|-------------|
| `fingerprint` | WordPress version detection (6 methods: meta tag, readme, RSS, wp-login, feed) | PC-FP-001, PC-FP-002 |
| `waf` | WAF/CDN detection (Cloudflare, Sucuri, Wordfence, Imperva, AWS WAF, Akamai, Fastly) | PC-WAF-001 |
| `plugins` | Plugin enumeration: passive HTML scan + brute-force readme.txt | PC-PLG-NNN |
| `themes` | Theme enumeration: passive + brute-force style.css | PC-THM-001 |
| `users` | User enumeration via REST API + author archives | PC-USR-001, PC-USR-002 |
| `xmlrpc` | XML-RPC checks: access, pingback.ping (DoS), system.listMethods | PC-XMLRPC-001/002/003 |
| `rest_api` | REST API exposure: link disclosure, oEmbed, CORS misconfiguration | PC-REST-001/002/003 |
| `misconfigs` | 12 misconfiguration checks: wp-config.php, .env, .git, debug.log, etc. | PC-MCFG-001 to 012 |
| `directory_listing` | Open directory listing in wp-content/ subdirectories | PC-DIR-001 to 004 |
| `http_headers` | Missing security headers: HSTS, CSP, X-Frame-Options, etc. | PC-HDR-001 to 008 |
| `ssl_tls` | SSL/TLS: HTTP→HTTPS redirect, certificate validity, HSTS | PC-SSL-001/002/003 |
| `debug_exposure` | WP_DEBUG active, PHP version disclosure | PC-DBG-001, PC-DBG-003 |
| `content_analysis` | Card skimming scripts, suspicious iframes, hardcoded API keys | PC-CNT-001/002/003 |
| `auth` | Authenticated scan: login verification, open registration | PC-AUTH-001/002 |
| `cves` | CVE correlation for core + plugins + themes (daily updated DB) | PC-CVE-{CVE-ID} |

---

## CLI Usage

```bash
# Basic scan
plecost scan https://target.com

# With authentication
plecost scan https://target.com --user admin --password secret

# Through a proxy
plecost scan https://target.com --proxy http://127.0.0.1:8080

# Run specific modules only
plecost scan https://target.com --modules fingerprint,plugins,cves

# Skip specific modules
plecost scan https://target.com --skip-modules content_analysis,waf

# Stealth mode (random User-Agent, passive detection only)
plecost scan https://target.com --stealth

# Aggressive mode (max concurrency 50)
plecost scan https://target.com --aggressive

# JSON output
plecost scan https://target.com --output report.json

# Update CVE database
plecost update-db

# List all modules
plecost modules list

# Get info about a specific finding
plecost explain PC-XMLRPC-002
```

### All Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--concurrency N` | Parallel requests | 10 |
| `--timeout N` | Request timeout (seconds) | 10 |
| `--proxy URL` | HTTP/SOCKS5 proxy | None |
| `--user/-u` | WordPress username | None |
| `--password/-p` | WordPress password | None |
| `--modules` | Comma-separated modules to run | all |
| `--skip-modules` | Comma-separated modules to skip | none |
| `--stealth` | Random UA, slower, passive only | False |
| `--aggressive` | Max concurrency (50) | False |
| `--output/-o` | Save JSON report to file | None |
| `--random-user-agent` | Rotate User-Agent | False |
| `--no-verify-ssl` | Skip SSL certificate verification | False |
| `--force` | Continue even if not WordPress | False |
| `--quiet` | Only show HIGH and CRITICAL | False |

---

## Library Usage (Python API)

Plecost is designed as a proper Python library for use in security automation pipelines:

```python
import asyncio
from plecost import Scanner, ScanOptions

async def scan():
    options = ScanOptions(
        url="https://target.com",
        concurrency=10,
        timeout=10,
        proxy="http://127.0.0.1:8080",      # optional
        modules=["fingerprint", "plugins", "cves"],  # None = all modules
        skip_modules=[],
        credentials=("admin", "secret"),    # optional
        stealth=False,
        aggressive=False,
    )

    scanner = Scanner(options)
    result = await scanner.run()

    print(f"WordPress: {result.is_wordpress}")
    print(f"Version: {result.wordpress_version}")
    print(f"WAF: {result.waf_detected}")
    print(f"Plugins found: {len(result.plugins)}")
    print(f"Users found: {len(result.users)}")

    for finding in result.findings:
        print(f"[{finding.severity.value}] {finding.id}: {finding.title}")
        print(f"  Remediation: {finding.remediation}")

    result.to_json("report.json")

asyncio.run(scan())
```

### Use in Celery Workers

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

## Finding ID Reference

All finding IDs are stable and permanent — safe to use in dashboards and automations:

| Prefix | Category | Examples |
|--------|----------|---------|
| `PC-FP-NNN` | Fingerprint / version disclosure | PC-FP-001 (meta tag), PC-FP-002 (readme.html) |
| `PC-USR-NNN` | User enumeration | PC-USR-001 (REST API), PC-USR-002 (author archives) |
| `PC-AUTH-NNN` | Authentication | PC-AUTH-001 (login success), PC-AUTH-002 (open registration) |
| `PC-XMLRPC-NNN` | XML-RPC | PC-XMLRPC-001 (accessible), PC-XMLRPC-002 (pingback DoS) |
| `PC-REST-NNN` | REST API exposure | PC-REST-001 to 003 |
| `PC-CVE-{ID}` | CVE correlations | PC-CVE-CVE-2024-1234 |
| `PC-MCFG-NNN` | Misconfigurations | PC-MCFG-001 (wp-config.php) to PC-MCFG-012 |
| `PC-DIR-NNN` | Directory listing | PC-DIR-001 to PC-DIR-004 |
| `PC-HDR-NNN` | HTTP headers | PC-HDR-001 (HSTS) to PC-HDR-008 (X-Powered-By) |
| `PC-SSL-NNN` | SSL/TLS | PC-SSL-001 to PC-SSL-003 |
| `PC-DBG-NNN` | Debug exposure | PC-DBG-001 (WP_DEBUG), PC-DBG-003 (PHP version) |
| `PC-CNT-NNN` | Content analysis | PC-CNT-001 (skimmer), PC-CNT-002 (iframe), PC-CNT-003 (secrets) |
| `PC-WAF-NNN` | WAF detection | PC-WAF-001 |

---

## Comparison

| Feature | Plecost v4 | WPScan | Wordfence | ScanTower |
|---------|-----------|--------|-----------|-----------|
| Open source | ✅ | ✅ (partial) | ❌ | ❌ |
| Python library API | ✅ | ❌ | ❌ | ❌ |
| Async (httpx) | ✅ | ❌ | ❌ | ❌ |
| WAF detection | ✅ 7 WAFs | ✅ | ❌ | ✅ |
| Plugin brute-force | ✅ | ✅ | ❌ | ✅ |
| CVE correlation | ✅ daily | ✅ API | ✅ | ✅ |
| Content analysis | ✅ | ❌ | ✅ | ❌ |
| Stable finding IDs | ✅ | ❌ | ❌ | ❌ |
| Docker native | ✅ | ✅ | ❌ | ❌ |
| Celery-compatible | ✅ | ❌ | ❌ | ❌ |

---

## Architecture

```
CLI/Library → ScanOptions → ScanContext → Scheduler
                                              │
                    ┌─────────────────────────┤
                    ↓                         ↓
             [fingerprint]               [waf] (parallel from start)
                    │
        ┌───────────┼──────────┬──────────┬──────────┐
        ↓           ↓          ↓          ↓          ↓
    [plugins]   [themes]    [users]    [xmlrpc]  [misconfigs] ...
        │           │
        └─────┬─────┘
              ↓
           [cves]
              │
    [Terminal Reporter] [JSON Reporter]
```

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Write tests first (TDD): `pytest tests/ -v`
4. Implement the feature
5. Ensure all tests pass: `pytest tests/ --cov=plecost --cov-fail-under=80`
6. Submit a pull request

---

## License

Plecost usa la Functional Source License (FSL-1.1-MIT). Puedes usar, modificar y distribuir la herramienta libremente, incluyendo para auditorías de seguridad corporativas internas. Lo que NO está permitido es ofrecer Plecost como SaaS o servicio de pago. La licencia cambia automáticamente a MIT pasados 4 años.

See [LICENSE](LICENSE) for full details.

**Author:** Dani (cr0hn) — [cr0hn@cr0hn.com](mailto:cr0hn@cr0hn.com)
