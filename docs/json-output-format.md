# Plecost JSON Output Format

This document is the authoritative reference for the JSON object produced by `plecost scan --output <file>` (or via the public API `ScanResult.to_json()`). It is written for programmatic consumption — by code, agents, or AI systems that need to parse or reason about scan results.

---

## Top-level object

```
ScanResult {
  scan_id:                string          -- UUID v4. Unique identifier for this scan run.
  url:                    string          -- Canonical target URL (trailing slash stripped).
  timestamp:              string          -- ISO 8601 UTC datetime when the scan started.
  duration_seconds:       number          -- Wall-clock seconds the scan took (float).
  is_wordpress:           boolean         -- true if WordPress was positively identified.
  wordpress_version:      string | null   -- Detected WP version (e.g. "6.6.2"), or null.
  blocked:                boolean         -- true if the target returned 403 on pre-flight probe.
  waf_detected:           string | null   -- WAF product name (e.g. "Cloudflare"), or null.
  summary:                ScanSummary     -- Finding counts by severity.
  findings:               Finding[]       -- Security findings (ordered by insertion, not severity).
  findings_by_category:   object          -- Same findings grouped by category string (see Category taxonomy).
                                          --   Keys are category strings; values are Finding[] arrays.
                                          --   Only present when using JSONReporter (CLI --output flag or
                                          --   JSONReporter.to_string()). NOT included by ScanResult.to_json().
  plugins:                Plugin[]        -- Detected WordPress plugins.
  themes:                 Theme[]         -- Detected WordPress themes.
  users:                  User[]          -- Detected WordPress user accounts.
  woocommerce:            WooCommerceInfo | null  -- WooCommerce details, or null if not detected.
  wp_ecommerce:           WPECommerceInfo | null  -- WP eCommerce details, or null if not detected.
  magecart:               MagecartInfo | null     -- Magecart scan results, or null if not run.
}
```

> **`findings_by_category` availability**: this key is injected by `JSONReporter` (used by `plecost scan --output`). If you call `ScanResult.to_json()` directly (library usage), this key is absent. Always prefer the CLI output or `JSONReporter` when building integrations.

### Blocked scan

When `blocked == true`, the scanner could not reach the target (pre-flight probe returned 403). In this state: `is_wordpress` is `false`, `wordpress_version` is `null`, `plugins` / `themes` / `users` are empty arrays, and `findings` contains at most one finding with `id == "PC-PRE-001"`.

---

## ScanSummary

```
ScanSummary {
  critical: integer   -- Number of CRITICAL findings.
  high:     integer   -- Number of HIGH findings.
  medium:   integer   -- Number of MEDIUM findings.
  low:      integer   -- Number of LOW findings.
  info:     integer   -- Number of INFO findings.
}
```

---

## Finding

Each object in `findings[]` represents a distinct security issue discovered during the scan.

```
Finding {
  id:               string        -- Permanent finding ID. Format: "PC-{MODULE}-{NNN}".
  remediation_id:   string        -- Paired remediation ID. Format: "REM-{MODULE}-{NNN}".
  title:            string        -- Short human-readable title.
  severity:         Severity      -- One of: "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO".
  description:      string        -- Full description of the issue.
  evidence:         object        -- Key-value pairs of evidence (schema varies by module, see below).
  remediation:      string        -- Actionable remediation guidance.
  references:       string[]      -- List of URLs with additional context (may be empty).
  cvss_score:       number | null -- CVSS v3 base score (0.0–10.0), or null if not applicable.
  module:           string        -- Module that emitted this finding (see Module names below).
  category:         string        -- Semantic category (see Category taxonomy below).
                                  --   Auto-derived from `id`; stable across releases.
}
```

### Severity enum

| Value      | Meaning                                              |
|------------|------------------------------------------------------|
| `CRITICAL` | Immediate exploitation risk; update or mitigate now. |
| `HIGH`     | Significant risk; remediate urgently.                |
| `MEDIUM`   | Moderate risk; remediate in near term.               |
| `LOW`      | Minor risk or informational with slight risk.        |
| `INFO`     | Informational only; no direct exploit risk.          |

### Finding ID format

- Pattern: `PC-{MODULE}-{NNN}` where `{MODULE}` is 2–8 uppercase letters and `{NNN}` is a zero-padded integer or a CVE ID.
- CVE findings use: `PC-CVE-CVE-YYYY-NNNNN` (e.g. `PC-CVE-CVE-2023-28121`).
- Each `id` has a corresponding `remediation_id` with the same suffix but `REM-` prefix.

### Module names

| `module` value     | Description                                    |
|--------------------|------------------------------------------------|
| `pre-flight`       | Pre-flight access check                        |
| `fingerprint`      | WordPress version and technology fingerprint   |
| `waf`              | Web Application Firewall detection             |
| `plugins`          | Plugin detection (passive + brute-force)       |
| `themes`           | Theme detection (passive + brute-force)        |
| `users`            | User enumeration                               |
| `xmlrpc`           | XML-RPC exposure checks                        |
| `rest_api`         | REST API exposure and user leaks               |
| `misconfigs`       | WordPress misconfiguration checks              |
| `directory_listing`| Open directory listings                        |
| `http_headers`     | Missing/misconfigured security headers         |
| `ssl_tls`          | SSL/TLS configuration issues                   |
| `debug_exposure`   | Debug endpoints and WP_DEBUG exposure          |
| `content_analysis` | Sensitive content (emails, keys) in HTML       |
| `auth`             | Authentication and login page exposure         |
| `woocommerce`      | WooCommerce-specific checks                    |
| `wp_ecommerce`     | WP eCommerce-specific checks                   |
| `magecart`         | Magecart/skimmer script detection              |
| `webshells`        | Uploaded PHP webshell detection                |
| `cves`             | CVE matching against detected component versions|

### Category taxonomy

`category` is a fine-grained semantic label, independent of `module`. Multiple modules can produce the same category.

| `category`                | Meaning / examples                                              |
|---------------------------|-----------------------------------------------------------------|
| `ssl_certificate`         | Invalid or expired SSL certificate                              |
| `ssl_redirect`            | HTTP→HTTPS redirect missing                                     |
| `hsts`                    | HSTS not configured (HDR or SSL module)                         |
| `clickjacking`            | X-Frame-Options header absent                                   |
| `content_security_policy` | Content-Security-Policy header absent                           |
| `http_headers`            | Other missing security headers (nosniff, Referrer-Policy, etc.) |
| `version_disclosure`      | WP/PHP/server version exposed in headers, meta tags or files    |
| `credentials_exposed`     | wp-config.php, .env or backup with credentials accessible       |
| `source_code_exposed`     | .git directory publicly accessible                              |
| `debug_exposure`          | WP_DEBUG active, debug.log accessible                           |
| `backup_files`            | SQL backup or archive files accessible                          |
| `admin_scripts`           | install.php / upgrade.php accessible                            |
| `directory_listing`       | Open directory listing in wp-content or subdirectories          |
| `user_enumeration`        | WordPress usernames leaked via REST API or author archives       |
| `xmlrpc`                  | XML-RPC endpoint enabled (brute-force / DoS amplification risk) |
| `rest_api_exposure`       | REST API leaking data or users without authentication           |
| `attack_surface`          | Unnecessary attack surface enabled (e.g. wp-cron external)     |
| `cve`                     | CVE matched against a detected plugin/theme version             |
| `open_registration`       | User registration open to the public                            |
| `authentication`          | Authentication result (successful login with supplied creds)    |
| `woocommerce_detection`   | WooCommerce presence, version or API namespace disclosed        |
| `woocommerce_api_exposure`| WooCommerce REST API endpoints returning data unauthenticated   |
| `woocommerce_cve`         | CVE in WooCommerce or its official extensions                   |
| `wp_ecommerce`            | WP eCommerce plugin detected or misconfigured                   |
| `wp_ecommerce_cve`        | CVE in WP eCommerce plugin                                      |
| `card_skimmer`            | Magecart-style skimmer script or known malicious domain         |
| `suspicious_content`      | Unexpected iframe or hardcoded API key in page source           |
| `webshell`                | Uploaded PHP webshell detected in uploads directory             |
| `waf_detected`            | WAF or CDN identified                                           |
| `infrastructure`          | Infrastructure-level findings (pre-flight block)                |
| `other`                   | Finding ID not matched by any rule (should not occur normally)  |

### Evidence object schemas (by module)

Evidence keys vary by finding. Common patterns:

```
# fingerprint
{ "url": string, "match": string }

# cves
{ "cve_id": string, "software": string, "version_range": string }

# misconfigs / debug_exposure / directory_listing
{ "url": string }
{ "url": string, "status_code": integer }

# http_headers
{ "header": string, "value": string | "missing" }

# users (rest_api / xmlrpc)
{ "source": string, "users": string }   -- users is a formatted multi-line string

# webshells
{ "url": string, "matched_pattern": string, "response_size": integer }

# woocommerce
{ "endpoint": string, "record_count": integer }
```

---

## Plugin

Each object in `plugins[]` represents a detected WordPress plugin.

```
Plugin {
  slug:           string        -- WordPress.org plugin slug (e.g. "woocommerce").
  version:        string | null -- Detected installed version, or null if unknown.
  latest_version: string | null -- Latest available version (always null in current release).
  url:            string        -- Direct URL to the plugin directory on the target.
  outdated:       boolean       -- Always false in current release (reserved).
  abandoned:      boolean       -- Always false in current release (reserved).
  vulns:          PluginVuln[]  -- All known CVEs for this plugin (regardless of installed version).
}
```

### PluginVuln

```
PluginVuln {
  cve_id:        string        -- CVE identifier (e.g. "CVE-2023-28121").
  title:         string        -- Short CVE title.
  severity:      string        -- One of: "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO".
  cvss_score:    number | null -- CVSS v3 base score, or null.
  has_exploit:   boolean       -- true if a public exploit is known to exist.
  version_range: string        -- Affected version range, formatted as "start–end".
                               --   "*" means unbounded (e.g. "*–4.9.2" = all up to 4.9.2).
                               --   Format uses en-dash (U+2013), not hyphen.
  description:   string        -- Full CVE description.
  remediation:   string        -- Remediation guidance (typically "Update to latest version").
  references:    string[]      -- URLs to CVE advisories, changelogs, PoC repos, etc.
}
```

#### Relationship between `plugins[].vulns` and `findings[]`

- `plugins[].vulns` — **all CVEs** for the plugin slug, regardless of whether the installed version is affected. Use this to show the full vulnerability history of a component.
- `findings[]` (module `cves`) — **only CVEs that affect the detected installed version**. Use this to identify what needs immediate remediation.

If `version == null`, no CVE findings are emitted for that plugin (version matching is not possible), but `vulns` is still populated with all known CVEs.

---

## Theme

```
Theme {
  slug:           string        -- WordPress.org theme slug (e.g. "twentytwenty").
  version:        string | null -- Detected installed version, or null if unknown.
  latest_version: string | null -- Always null in current release (reserved).
  url:            string        -- Direct URL to the theme directory on the target.
  outdated:       boolean       -- Always false in current release (reserved).
  active:         boolean       -- Always true in current release (reserved for multi-theme detection).
}
```

> Themes do **not** have a `vulns` array. CVE findings for themes appear only in `findings[]` with `module == "cves"` and evidence `software` matching the theme slug.

---

## User

```
User {
  id:           integer | null  -- WordPress user ID, or null if not determinable.
  username:     string          -- WordPress login username.
  display_name: string | null   -- Public display name, or null.
  source:       string          -- How the user was discovered (see values below).
}
```

### Source values

| `source`         | Discovery method                                    |
|------------------|-----------------------------------------------------|
| `rest_api`       | `/wp-json/wp/v2/users` endpoint                     |
| `author_archive` | Author archive URL enumeration (`/?author=N`)       |
| `rss`            | RSS feed `<dc:creator>` or `<author>` tags          |
| `oEmbed`         | oEmbed endpoint author field                        |

---

## WooCommerceInfo

Present (non-null) only when WooCommerce is detected.

```
WooCommerceInfo {
  detected:       boolean   -- Always true when this object is present.
  version:        string | null  -- WooCommerce version, or null.
  active_plugins: string[]  -- Which WooCommerce sub-plugins are active.
                            --   Possible values: "core", "payments", "blocks", "stripe-gateway"
  api_namespaces: string[]  -- REST API namespaces exposed (e.g. ["wc/v3", "wc/store/v1"]).
}
```

---

## WPECommerceInfo

Present (non-null) only when WP eCommerce is detected.

```
WPECommerceInfo {
  detected:      boolean   -- Always true when this object is present.
  version:       string | null  -- WP eCommerce version, or null.
  active_gateways: string[] -- Detected payment gateways (e.g. ["chronopay"]).
  checks_run:    string[]  -- Checks that were executed during the scan.
                           --   Possible values: "readme", "directories", "sensitive_files",
                           --   "chronopay_endpoint"
}
```

---

## MagecartInfo

Present (non-null) when the Magecart module ran (always included when DB is available).

```
MagecartInfo {
  detected:          boolean   -- true if a Magecart skimmer was found.
  pages_scanned:     string[]  -- URLs of checkout/cart pages that were analyzed.
  scripts_analyzed:  integer   -- Number of external scripts inspected.
  malicious_domains: string[]  -- Domains flagged as known Magecart infrastructure.
}
```

---

## Null vs absent fields

All fields are always present in the JSON (no field is omitted). Nullable fields use JSON `null`. Empty collections use `[]`. Boolean flags default to `false`.

---

## Complete minimal example (blocked scan)

```json
{
  "scan_id": "a1b2c3d4-0000-0000-0000-000000000000",
  "url": "https://target.example.com",
  "timestamp": "2026-04-14T12:00:00.000000",
  "duration_seconds": 0.42,
  "is_wordpress": false,
  "wordpress_version": null,
  "blocked": true,
  "waf_detected": null,
  "summary": { "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0 },
  "findings": [
    {
      "id": "PC-PRE-001",
      "remediation_id": "REM-PRE-001",
      "title": "Target returned 403 Forbidden",
      "severity": "CRITICAL",
      "description": "The target URL returned HTTP 403 on the pre-flight probe. The site may be behind a WAF or IP block.",
      "evidence": { "url": "https://target.example.com/", "status_code": 403 },
      "remediation": "Verify the target is accessible from your IP. Consider using --proxy or contacting the site owner.",
      "references": [],
      "cvss_score": null,
      "module": "pre-flight",
      "category": "infrastructure"
    }
  ],
  "findings_by_category": {
    "infrastructure": [
      {
        "id": "PC-PRE-001",
        "category": "infrastructure",
        "severity": "CRITICAL",
        "..."
      }
    ]
  },
  "plugins": [],
  "themes": [],
  "users": [],
  "woocommerce": null,
  "wp_ecommerce": null,
  "magecart": null
}
```

## Complete example (successful WordPress scan excerpt)

```json
{
  "scan_id": "91f23f04-4111-4c6a-8028-69fd984497c5",
  "url": "http://target.example.com",
  "timestamp": "2026-04-14T16:20:47.961672",
  "duration_seconds": 5.67,
  "is_wordpress": true,
  "wordpress_version": "6.6.2",
  "blocked": false,
  "waf_detected": null,
  "summary": { "critical": 5, "high": 2, "medium": 8, "low": 3, "info": 2 },
  "findings": [
    {
      "id": "PC-FP-001",
      "remediation_id": "REM-FP-001",
      "title": "WordPress version disclosed via meta generator tag",
      "severity": "LOW",
      "description": "WordPress version 6.6.2 found in meta generator tag.",
      "evidence": {
        "url": "http://target.example.com/",
        "match": "<meta name=\"generator\" content=\"WordPress 6.6.2"
      },
      "remediation": "Remove the generator meta tag. Add to functions.php: remove_action('wp_head', 'wp_generator');",
      "references": ["https://wordpress.org/support/article/hardening-wordpress/"],
      "cvss_score": null,
      "module": "fingerprint",
      "category": "version_disclosure"
    },
    {
      "id": "PC-CVE-CVE-2023-28121",
      "remediation_id": "REM-CVE-CVE-2023-28121",
      "title": "woocommerce-payments: CVE-2023-28121 (CVE-2023-28121)",
      "severity": "CRITICAL",
      "description": "An authentication bypass vulnerability in WooCommerce Payments allows unauthenticated attackers to impersonate arbitrary users and gain administrator access.",
      "evidence": {
        "cve_id": "CVE-2023-28121",
        "software": "woocommerce-payments",
        "version_range": "*–5.6.1"
      },
      "remediation": "Update the plugin/theme to the latest version.",
      "references": [
        "https://developer.woocommerce.com/2023/07/12/critical-vulnerability-in-woocommerce-payments/"
      ],
      "cvss_score": 9.8,
      "module": "cves",
      "category": "cve"
    }
  ],
  "findings_by_category": {
    "cve": [
      {
        "id": "PC-CVE-CVE-2023-28121",
        "category": "cve",
        "severity": "CRITICAL",
        "..."
      }
    ],
    "version_disclosure": [
      {
        "id": "PC-FP-001",
        "category": "version_disclosure",
        "severity": "LOW",
        "..."
      }
    ]
  },
  "plugins": [
    {
      "slug": "woocommerce-payments",
      "version": "3.9.0",
      "latest_version": null,
      "url": "http://target.example.com/wp-content/plugins/woocommerce-payments/",
      "outdated": false,
      "abandoned": false,
      "vulns": [
        {
          "cve_id": "CVE-2023-28121",
          "title": "woocommerce-payments: CVE-2023-28121",
          "severity": "CRITICAL",
          "cvss_score": 9.8,
          "has_exploit": true,
          "version_range": "*–5.6.1",
          "description": "An authentication bypass vulnerability in WooCommerce Payments allows unauthenticated attackers to impersonate arbitrary users.",
          "remediation": "Update the plugin/theme to the latest version.",
          "references": [
            "https://developer.woocommerce.com/2023/07/12/critical-vulnerability-in-woocommerce-payments/"
          ]
        }
      ]
    }
  ],
  "themes": [
    {
      "slug": "twentytwenty",
      "version": "1.6",
      "latest_version": null,
      "url": "http://target.example.com/wp-content/themes/twentytwenty/",
      "outdated": false,
      "active": true
    }
  ],
  "users": [
    {
      "id": 1,
      "username": "admin",
      "display_name": "Site Admin",
      "source": "rest_api"
    }
  ],
  "woocommerce": {
    "detected": true,
    "version": "5.0.0",
    "active_plugins": ["core", "payments", "stripe-gateway"],
    "api_namespaces": ["wc/v3"]
  },
  "wp_ecommerce": {
    "detected": false,
    "version": null,
    "active_gateways": [],
    "checks_run": ["readme"]
  },
  "magecart": {
    "detected": false,
    "pages_scanned": [
      "http://target.example.com/checkout",
      "http://target.example.com/cart"
    ],
    "scripts_analyzed": 3,
    "malicious_domains": []
  }
}
```

---

## Querying the JSON (usage patterns for AI agents)

**"Is this site vulnerable to a specific CVE?"**
Search `findings[].evidence.cve_id` for the CVE ID. If present, the installed version is confirmed affected.

**"What is the highest-severity issue on this site?"**
Check `summary.critical > 0`, then `summary.high > 0`, etc. For details, filter `findings[]` by `severity == "CRITICAL"`.

**"Does this plugin have any known exploits?"**
Check `plugins[slug].vulns[].has_exploit == true`.

**"Which findings need immediate action?"**
Filter `findings[]` where `severity` is `"CRITICAL"` or `"HIGH"`.

**"Is WooCommerce present and what payment plugins are active?"**
Check `woocommerce != null && woocommerce.detected == true`, then read `woocommerce.active_plugins`.

**"Were any user accounts leaked?"**
Check `users.length > 0`. Each entry has `username`, `id`, `display_name`, and `source`.

**"Was the scan blocked by a WAF?"**
Check `blocked == true` or `waf_detected != null`.

**"What version of WordPress is running?"**
Read `wordpress_version`. May be `null` if version could not be determined even though `is_wordpress == true`.

**"Show me all SSL/TLS issues grouped together."**
Use `findings_by_category["ssl_certificate"]`, `findings_by_category["ssl_redirect"]`, and `findings_by_category["hsts"]`. Or filter `findings[]` where `category` starts with `"ssl_"` or equals `"hsts"`.

**"Show me all findings in a specific dashboard section."**
Read directly from `findings_by_category["<category>"]`. Keys are only present when at least one finding exists for that category — always guard with a null/key check.

**"Group all credential and secret exposure issues."**
Check `findings_by_category["credentials_exposed"]` and `findings_by_category["source_code_exposed"]`.

**"Are there any signs of compromise (webshells, skimmers)?"**
Check `findings_by_category["webshell"]`, `findings_by_category["card_skimmer"]`, and `findings_by_category["suspicious_content"]`.

**"What outdated or vulnerable software is installed?"**
Check `findings_by_category["cve"]` for version-matched CVEs, plus `findings_by_category["woocommerce_cve"]` and `findings_by_category["wp_ecommerce_cve"]`.

**"Enumerate all category keys present in this scan."**
Read `Object.keys(findings_by_category)` — only categories with at least one finding appear as keys.
