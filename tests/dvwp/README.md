# DVWP — Damn Vulnerable WordPress

Local WordPress environment with intentionally vulnerable plugins for plecost security testing.

> **WARNING**: For local/isolated use only. Never expose to the internet.

## Table of Contents

- [Purpose](#purpose)
- [How to Use](#how-to-use)
- [Users](#users)
- [Vulnerable Plugins](#vulnerable-plugins)
- [Vulnerable E-Commerce Plugins](#vulnerable-e-commerce-plugins)
- [Vulnerable Theme](#vulnerable-theme)
- [Webshell Detection Fixtures](#webshell-detection-fixtures)
- [How It Works](#how-it-works)
- [References](#references)

## Purpose

DVWP is a deliberately vulnerable WordPress environment designed to run plecost functional tests (`tests/functional/`) without relying on a real external site.

It includes plugins with known CVEs, users with different roles, and webshell fixtures to cover every detector in the engine. Each element is chosen to exercise a specific part of the scanner.

## How to Use

Start the environment:

```bash
docker compose up -d
```

Once up (takes ~60 s on first run while `wpcli` configures the site), the environment is available at:

- Site: http://localhost:8765
- Admin panel: http://localhost:8765/wp-admin (username `admin`, password `admin`)

Run plecost against it:

```bash
plecost scan http://localhost:8765 -v
plecost scan http://localhost:8765 --deep -v
```

Run the functional test suite:

```bash
PLECOST_FUNCTIONAL_TESTS=1 python3 -m pytest tests/functional/ -v
```

Stop without deleting data:

```bash
docker compose down
```

Full reset — deletes all data and reinstalls from scratch:

```bash
docker compose down -v && docker compose up -d
```

Install an additional plugin at a specific version:

```bash
docker compose run --rm wpcli wp plugin install <slug> --version=<version> --activate --path=/var/www/html --allow-root
```

## Users

| Username | Password | Role |
|---|---|---|
| `admin` | `admin` | Administrator |
| `editor` | `editor123` | Editor |
| `author1` | `author123` | Author |
| `subscriber1` | `sub123` | Subscriber |

## Vulnerable Plugins

| Plugin | Version | CVE | Vulnerability |
|---|---|---|---|
| wpDiscuz | 7.0.4 | CVE-2020-24186 | Unauthenticated RCE via file upload (CVSS 9.8) |
| Contact Form 7 | 5.3.1 | CVE-2020-35489 | Unrestricted file upload |
| WooCommerce | 5.0.0 | CVE-2021-32790 | Multiple vulnerabilities |
| Ninja Forms | 3.4.34.2 | CVE-2021-34648 | Unauthenticated email injection |
| Duplicator | 1.3.26 | CVE-2020-11738 | Unauthenticated path traversal |
| Loginizer | 1.6.3 | CVE-2020-27615 | SQL injection |
| WP Super Cache | 1.7.1 | CVE-2021-33203 | Authenticated XSS |
| Elementor | 3.1.2 | CVE-2022-1329 | Authenticated RCE |
| Wordfence | 7.5.0 | CVE-2021-24875 | Reflected XSS |

## Vulnerable E-Commerce Plugins

| Plugin | Version | CVE | Vulnerability |
|---|---|---|---|
| WooCommerce Payments | 3.9.0 | CVE-2023-28121 | Unauthenticated privilege escalation (CVSS 9.8) |
| Easy Digital Downloads | 2.11.5 | CVE-2021-39351 | Stored XSS |
| Give – Donation Plugin | 2.10.3 | CVE-2021-34634 | SQL injection |
| YITH WooCommerce Wishlist | 2.2.9 | CVE-2021-24987 | Stored XSS |
| WooCommerce Stripe Gateway | 4.3.0 | CVE-2019-15826 | Order information disclosure |

## Vulnerable Theme

| Theme | Version | Notes |
|---|---|---|
| Twenty Twenty | 1.6 | Multiple minor vulnerabilities |

## Webshell Detection Fixtures

Harmless PHP files placed at known webshell paths to exercise each detector in the engine. They have no actual code execution capability.

| Path | Detector | Finding | Fingerprint family |
|---|---|---|---|
| `/wp-content/uploads/shell.php` | KnownPathsDetector | PC-WSH-001 | — (path match only) |
| `/wp-content/uploads/c99.php` | ResponseFingerprintDetector | PC-WSH-200 | `c99shell` |
| `/wp-content/uploads/wso.php` | ResponseFingerprintDetector | PC-WSH-200 | `wso_filesman` |
| `/wp-content/uploads/1.php` | ResponseFingerprintDetector | PC-WSH-200 | `china_chopper` (empty body) |
| `/wp-content/uploads/{year}/04/image.php` | UploadsPhpDetector | PC-WSH-100 | — (PHP in uploads dated subdir) |
| `/wp-content/mu-plugins/cache.php` | MuPluginsDetector | PC-WSH-150 | — (mu-plugins backdoor) |

The uploads `.htaccess` is intentionally overridden to allow PHP execution in this environment. In a production WordPress site the `.htaccess` blocks PHP in uploads — that is the correct hardening.

## How It Works

The setup uses three containers:

| Container | Image | Role |
|---|---|---|
| `dvwp_mysql` | `mysql:8.0` | Database — starts first, healthcheck ensures it's ready |
| `dvwp_wordpress` | `wordpress:6.6` | Apache + PHP + WordPress files — waits for MySQL |
| `dvwp_wpcli` | `wordpress:cli` | Runs `setup.sh` once — installs WP core, users and plugins, then exits |

`setup.sh` is mounted read-only into the `wpcli` container and executed on startup. It uses `wp-cli` to fully configure the environment automatically.

## References

- WPScan Vulnerability Database: https://wpscan.com/plugins
- NVD CVE Search: https://nvd.nist.gov/vuln/search
