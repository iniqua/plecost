# Webshell Detector Module — Design Spec

**Date:** 2026-04-14  
**Status:** Approved  
**Module name:** `webshells`  
**Finding prefix:** `PC-WSH`

---

## 1. Overview

The `webshells` module is a remote-only WordPress webshell detection system. It operates in two modes:

- **Black box** — no credentials required; uses HTTP probing, path enumeration, and response fingerprinting
- **Grey box** — WordPress admin credentials (`--user` / `--password`); adds core integrity checks and REST API plugin enumeration

The module is designed for **low false positives**: only findings with high confidence are reported. A finding requires at least two independent signals, or one signal against a known high-confidence fingerprint.

---

## 2. Background: Webshell Landscape

Based on threat intelligence research (Sucuri, Recorded Future, NSA/CISA, Mandiant, Talos):

- Webshells represent **35% of cyberattack incidents Q4 2024**
- Most active families: **China Chopper**, **WSO/FilesMan**, **b374k**, **P.A.S.**, **Alfa Shell**, **Godzilla**, **Behinder**
- Emerging vector (2024–2025): **wp-content/mu-plugins/** — Must-Use plugins load automatically and are invisible in the WP admin panel
- Common evasion: fake 404 pages (WSO), blank 200 responses (China Chopper), polyglot image/PHP files, whitespace steganography, remote loaders

---

## 3. Architecture

### 3.1 File Structure

```
plecost/modules/webshells/
├── __init__.py              # exports WebshellsModule
├── module.py                # WebshellsModule(ScanModule)
├── base.py                  # BaseDetector ABC
├── wordlists.py             # embedded wordlists (known paths, filenames)
└── detectors/
    ├── __init__.py
    ├── known_paths.py        # KnownPathsDetector      [no auth]
    ├── uploads_php.py        # UploadsPhpDetector       [no auth]
    ├── mu_plugins.py         # MuPluginsDetector        [no auth]
    ├── response_fp.py        # ResponseFingerprintDetector [no auth]
    ├── checksums.py          # ChecksumsDetector        [auth required]
    └── fake_plugins.py       # FakePluginRestDetector   [auth required]
```

### 3.2 Scheduler Integration

```
fingerprint (no deps)
plugins     (no deps)
    └── webshells  (depends_on: ["fingerprint", "plugins"])
```

`webshells` waits for `fingerprint` to obtain `ctx.wordpress_version` and `ctx.wordpress_locale`, and for `plugins` to populate `ctx.plugins` for correlation in `FakePluginRestDetector`.

### 3.3 BaseDetector Interface

```python
class BaseDetector(ABC):
    name: str
    requires_auth: bool = False

    @abstractmethod
    async def detect(
        self, ctx: ScanContext, http: PlecostHTTPClient
    ) -> list[Finding]: ...
```

### 3.4 WebshellsModule Flow

```python
async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
    active = [d for d in self._detectors if not d.requires_auth or ctx.opts.user]
    results = await asyncio.gather(*[d.detect(ctx, http) for d in active], return_exceptions=True)
    for findings in results:
        if isinstance(findings, list):
            for f in findings:
                ctx.add_finding(f)
        # exceptions are silently ignored (project convention)
```

---

## 4. Detectors

### 4.1 KnownPathsDetector `[no auth]`

**Finding range:** `PC-WSH-001` – `PC-WSH-099`  
**Severity:** CRITICAL

Probes ~300 known webshell paths compiled from real-world attacks (c99, r57, WSO, b374k, P.A.S., Alfa Shell, IndoXploit, China Chopper, Godzilla variants) across typical WordPress locations:

```
/wp-content/uploads/
/wp-content/plugins/[random_slug]/
/wp-content/mu-plugins/
/wp-includes/css/
/wp-includes/images/
/wp-admin/css/
/ (root)
```

**High-confidence conditions (both required to report):**
1. HTTP response is `200 OK`
2. `Content-Type` is `text/html`, `text/plain`, or `application/x-httpd-php`

**False-positive guard:** Before probing, the module performs a preflight check: requests a random non-existent `.php` path. If it returns 200, the WordPress install uses catch-all routing for all paths — in that case, `KnownPathsDetector` and `UploadsPhpDetector` are skipped entirely to avoid mass false positives. (`ResponseFingerprintDetector` still runs because it relies on body content, not just status code.)

**Wordlist:** Embedded in `wordlists.py`. Two tiers:
- `WEBSHELL_PATHS_CORE` (~100 paths) — default scan
- `WEBSHELL_PATHS_EXTENDED` (~300 paths) — activated with `--module-option webshells:wordlist=extended`

---

### 4.2 UploadsPhpDetector `[no auth]`

**Finding:** `PC-WSH-100`  
**Severity:** CRITICAL

`wp-content/uploads/` must never execute PHP. Any `.php` file returning 200 indicates either a webshell or a misconfigured `.htaccess` (which itself enables webshell execution).

**Strategy:** Generates paths for years 2020–current, all months:
```
/wp-content/uploads/{year}/{month}/{name}.php
/wp-content/uploads/{name}.php
```
With a wordlist of ~50 common webshell filenames observed in uploads.

A 200 OK on any of these paths is reported as CRITICAL regardless of body content.

---

### 4.3 MuPluginsDetector `[no auth]`

**Finding:** `PC-WSH-150`  
**Severity:** CRITICAL

Must-Use plugins in `wp-content/mu-plugins/` load automatically on every request and are hidden from the WP admin plugin list. Any PHP file here not matching a known legitimate mu-plugin is a red flag.

**Probes:** ~25 filenames observed in real attacks (Sucuri research 2024–2025):
```
index.php, redirect.php, custom-js-loader.php, loader.php,
wp-plugin.php, cache.php, update.php, maintenance.php, ...
```

A 200 OK here is CRITICAL.

---

### 4.4 ResponseFingerprintDetector `[no auth]`

**Finding range:** `PC-WSH-200` – `PC-WSH-249`  
**Severity:** CRITICAL

Runs independently (in parallel with other detectors) against the same wordlist as `KnownPathsDetector`. Its primary signal is response body fingerprinting rather than path existence — it probes each path and analyzes the body against known webshell family signatures:

| Family | Fingerprint condition |
|--------|-----------------------|
| **China Chopper** | 200 OK + body is exactly empty (0 bytes) |
| **WSO/FilesMan** | HTML body contains `name="a"` AND `name="charset"` form fields |
| **b374k** | Body contains `b374k` string OR MD5 `0de664ecd2be02cdd54234a0d1229b43` |
| **c99shell** | Body contains `c99shell` in title or body |
| **Generic loader** | 200 OK + `Content-Length: 0` + `Content-Type: text/html` |
| **Godzilla/Behinder** | Body contains `->|` or `|<-` markers |
| **Polyglot image/PHP** | Response starts with GIF89a / FFD8FF / PNG magic bytes AND body contains `<?php` |

Reports the identified family in `evidence.family`.

---

### 4.5 ChecksumsDetector `[auth required]`

**Finding range:** `PC-WSH-250` – `PC-WSH-299`  
**Severity:** HIGH

Uses the public WordPress checksums API to verify core file integrity:

```
GET https://api.wordpress.org/core/checksums/1.0/?version={ver}&locale={locale}
```

Downloads each of the ~20 highest-risk core files via HTTP and compares MD5 hashes against the official values.

**Monitored files (highest attack surface):**
```
wp-login.php, wp-includes/functions.php, wp-includes/class-wp-hook.php,
wp-includes/plugin.php, wp-includes/load.php, wp-admin/includes/plugin.php,
wp-settings.php, wp-config-sample.php, index.php, wp-blog-header.php,
xmlrpc.php, wp-cron.php, wp-includes/ms-functions.php
```

**False-positive guard:** Only reports if the size difference between the downloaded file and expected size exceeds 100 bytes (avoids FP from minor customizations or encoding differences).

**Requires:** `ctx.wordpress_version` from `fingerprint` module. Skips silently if version unknown.

---

### 4.6 FakePluginRestDetector `[auth required]`

**Finding range:** `PC-WSH-300` – `PC-WSH-349`  
**Severity:** HIGH

Calls `/wp-json/wp/v2/plugins` with Basic Auth and cross-references each installed plugin against:
1. The known-plugins wordlist already in `ctx.plugins` (populated by the `plugins` module)
2. Whether the plugin's directory contains only `index.php` (no `readme.txt`, no proper plugin header)
3. Whether the plugin slug appears in the site's HTML (is it actually enqueued?)

Reports a fake plugin if **at least 2 of 3 signals** are positive.

---

## 5. Finding IDs

| ID | Detector | Severity | Description |
|----|----------|----------|-------------|
| `PC-WSH-001` | KnownPathsDetector | CRITICAL | Known webshell path accessible |
| `PC-WSH-100` | UploadsPhpDetector | CRITICAL | PHP file executable in wp-content/uploads |
| `PC-WSH-150` | MuPluginsDetector | CRITICAL | Suspicious PHP file in mu-plugins |
| `PC-WSH-200` | ResponseFingerprintDetector | CRITICAL | Webshell family fingerprint matched |
| `PC-WSH-250` | ChecksumsDetector | HIGH | WordPress core file modified |
| `PC-WSH-300` | FakePluginRestDetector | HIGH | Fake/unauthorized plugin detected |

---

## 6. Module Options

Configurable via `--module-option webshells:KEY=VALUE`:

| Key | Values | Default | Effect |
|-----|--------|---------|--------|
| `wordlist` | `core`, `extended` | `core` | Path wordlist size (~100 vs ~300) |
| `detectors` | comma-separated names | all | Run only specified detectors |
| `checksums_files` | `minimal`, `full` | `minimal` | 20 vs all core files |

---

## 7. Concurrency

Detectors run in parallel via `asyncio.gather`. Within each detector, path probing uses the same concurrency limit as the rest of the scanner (`ctx.opts.concurrency`, default 10). No separate concurrency control needed.

---

## 8. False Positive Strategy

The module follows a **two-signal minimum** philosophy:

- A path returning 200 alone is not enough — it must also match a content-type or fingerprint check
- The one exception is `UploadsPhpDetector` and `MuPluginsDetector`: a 200 OK from these locations is inherently CRITICAL because legitimate WordPress installations never execute PHP there
- `ChecksumsDetector` adds a 100-byte size delta guard to avoid flagging minor customizations

---

## 9. Testing Strategy

| Layer | Coverage |
|-------|----------|
| **Unit** (respx mock) | Each detector independently: 200/403/404 responses, family fingerprints, FP scenarios |
| **Contract** | All `PC-WSH-*` IDs registered in `KNOWN_FINDING_IDS` |
| **Property** (hypothesis) | Random paths without 200 responses never produce findings |
| **Functional** (docker) | Real WordPress with a planted webshell in uploads and mu-plugins |

---

## 10. Registration Checklist

To integrate the module into plecost:

1. `plecost/modules/webshells/__init__.py` — export `WebshellsModule`
2. `plecost/scanner.py` — instantiate and add to module list
3. `plecost/cli.py` — add `"webshells"` to `_ALL_MODULE_NAMES` and `PC-WSH-*` IDs to `_FINDINGS_REGISTRY`
4. `tests/contract/test_finding_ids.py` — add all `PC-WSH-*` IDs to `KNOWN_FINDING_IDS`

---

## 11. References

- [NSA/CISA — Detect and Prevent Web Shell Malware](https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF)
- [NSACyber/Mitigating-Web-Shells YARA rules](https://github.com/nsacyber/Mitigating-Web-Shells)
- [Sucuri — Hidden Malware in MU-Plugins (2025)](https://blog.sucuri.net/2025/03/hidden-malware-strikes-again-mu-plugins-under-attack.html)
- [Recorded Future — Web Shell Analysis](https://www.recordedfuture.com/blog/web-shell-analysis-part-1)
- [php-malware-finder YARA rules](https://github.com/jvoisin/php-malware-finder)
- [WordPress Checksums API](https://api.wordpress.org/core/checksums/1.0/)
- [Mandiant — China Chopper Analysis](https://cloud.google.com/blog/topics/threat-intelligence/breaking-down-the-china-chopper-web-shell-part-ii/)
