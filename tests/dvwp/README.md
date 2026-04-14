# DVWP — Damn Vulnerable WordPress

Local WordPress environment with outdated, intentionally vulnerable plugins for plecost security testing.

> **WARNING**: For local/isolated use only. Never expose to the internet.

---

## Quick Start

```bash
docker compose up -d
docker compose logs wpcli -f   # watch setup progress (~60s)
```

Once the `wpcli` container prints the plugin table and exits, the environment is ready.

**Access:**
- Site: http://localhost:8765
- Admin panel: http://localhost:8765/wp-admin
  - Username: `admin`
  - Password: `admin`

---

## What Gets Installed

### WordPress
- Version: **6.6** (official `wordpress:6.6` image)
- Database: MySQL 8.0

### Users

| Username | Password | Role |
|---|---|---|
| `admin` | `admin` | Administrator |
| `editor` | `editor123` | Editor |
| `author1` | `author123` | Author |
| `subscriber1` | `sub123` | Subscriber |

### Vulnerable Plugins

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

### Vulnerable E-Commerce Plugins

| Plugin | Version | CVE | Vulnerability |
|---|---|---|---|
| WooCommerce Payments | 3.9.0 | CVE-2023-28121 | Unauthenticated privilege escalation (CVSS 9.8) |
| Easy Digital Downloads | 2.11.5 | CVE-2021-39351 | Stored XSS |
| Give – Donation Plugin | 2.10.3 | CVE-2021-34634 | SQL injection |
| YITH WooCommerce Wishlist | 2.2.9 | CVE-2021-24987 | Stored XSS |
| WooCommerce Stripe Gateway | 4.3.0 | CVE-2019-15826 | Order information disclosure |

### Vulnerable Theme

| Theme | Version | Notes |
|---|---|---|
| Twenty Twenty | 1.6 | Multiple minor vulnerabilities |

### Webshell Detection Fixtures

Harmless PHP files are placed at known webshell paths to exercise each detector in the engine.
They output minimal safe content — no actual code execution capability.

| Path | Detector triggered | Finding | Fingerprint family |
|---|---|---|---|
| `/wp-content/uploads/shell.php` | KnownPathsDetector | PC-WSH-001 | — (path match only) |
| `/wp-content/uploads/c99.php` | ResponseFingerprintDetector | PC-WSH-200 | `c99shell` |
| `/wp-content/uploads/wso.php` | ResponseFingerprintDetector | PC-WSH-200 | `wso_filesman` |
| `/wp-content/uploads/1.php` | ResponseFingerprintDetector | PC-WSH-200 | `china_chopper` (empty body) |
| `/wp-content/uploads/{year}/04/image.php` | UploadsPhpDetector | PC-WSH-100 | — (PHP in uploads dated subdir) |
| `/wp-content/mu-plugins/cache.php` | MuPluginsDetector | PC-WSH-150 | — (mu-plugins backdoor) |

> The uploads `.htaccess` is intentionally overridden to allow PHP execution in this environment.
> In a production WordPress site the `.htaccess` blocks PHP in uploads — that is the correct hardening.

---

## How It Works

The setup uses three containers:

| Container | Image | Role |
|---|---|---|
| `dvwp_mysql` | `mysql:8.0` | Database — starts first, healthcheck ensures it's ready |
| `dvwp_wordpress` | `wordpress:6.6` | Apache + PHP + WordPress files — waits for MySQL |
| `dvwp_wpcli` | `wordpress:cli` | Runs `setup.sh` once — installs WP core, users and plugins, then exits |

`setup.sh` is mounted read-only into the `wpcli` container and executed on startup. It uses `wp-cli` to fully configure the environment automatically.

---

## Stop / Reset

```bash
# Stop without deleting data (volumes preserved)
docker compose down

# Full reset — deletes all data and reinstalls from scratch
docker compose down -v && docker compose up -d
```

---

## Installing Additional Plugins at Specific Versions

```bash
docker compose run --rm wpcli wp plugin install <slug> --version=<version> --activate --path=/var/www/html --allow-root
```

Example:
```bash
docker compose run --rm wpcli wp plugin install classic-editor --version=1.6 --activate --path=/var/www/html --allow-root
```

All historical plugin versions are available at:
```
https://downloads.wordpress.org/plugin/<slug>.<version>.zip
```

---

## Running plecost Against This Environment

```bash
plecost scan http://localhost:8765 -v
plecost scan http://localhost:8765 --deep -v
```

---

## References

- WPScan Vulnerability Database: https://wpscan.com/plugins
- NVD CVE Search: https://nvd.nist.gov/vuln/search
