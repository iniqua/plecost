from __future__ import annotations
import asyncio
import re
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule

# PHP source code patterns — if found, wp-config.php is truly exposed
_PHP_SOURCE_RE = re.compile(r'(define\s*\(|DB_PASSWORD|DB_HOST|DB_NAME|\$table_prefix)', re.I)

_CHECKS = [
    ("/wp-config.php",         "PC-MCFG-001", "REM-MCFG-001", Severity.CRITICAL,
     "wp-config.php is publicly accessible",
     "wp-config.php is accessible and may expose database credentials.",
     "Restrict access via .htaccess or move wp-config.php one level above webroot.",
     True),   # True = check for PHP source content, not just HTTP 200
    ("/wp-config.php.bak",     "PC-MCFG-002", "REM-MCFG-002", Severity.CRITICAL,
     "wp-config.php backup is publicly accessible",
     "A backup of wp-config.php is accessible and may expose database credentials.",
     "Delete backup files from the server.",
     False),
    ("/.env",                  "PC-MCFG-003", "REM-MCFG-003", Severity.CRITICAL,
     ".env file is publicly accessible",
     ".env file is accessible and may expose application secrets.",
     "Restrict access to .env files via web server configuration.",
     False),
    ("/.git/HEAD",             "PC-MCFG-004", "REM-MCFG-004", Severity.HIGH,
     ".git directory is publicly accessible",
     "The .git directory is accessible, potentially exposing source code.",
     "Deny access to .git directory in web server configuration.",
     False),
    ("/debug.log",             "PC-MCFG-005", "REM-MCFG-005", Severity.HIGH,
     "debug.log is publicly accessible",
     "WordPress debug log is accessible and may expose sensitive information.",
     "Delete debug.log and disable WP_DEBUG_LOG in wp-config.php.",
     False),
    ("/backup.sql",            "PC-MCFG-006", "REM-MCFG-006", Severity.HIGH,
     "SQL backup file is publicly accessible",
     "A database backup file is accessible and may expose all data.",
     "Remove backup files from the webroot.",
     False),
    ("/wp-admin/install.php",  "PC-MCFG-007", "REM-MCFG-007", Severity.MEDIUM,
     "wp-admin/install.php is accessible",
     "WordPress installation script is accessible.",
     "WordPress should already be installed. Restrict access to install.php.",
     False),
    ("/wp-admin/upgrade.php",  "PC-MCFG-008", "REM-MCFG-008", Severity.MEDIUM,
     "wp-admin/upgrade.php is accessible",
     "WordPress upgrade script is accessible.",
     "Restrict access to upgrade.php after updates.",
     False),
    ("/readme.html",           "PC-MCFG-009", "REM-MCFG-009", Severity.LOW,
     "readme.html discloses WordPress version",
     "readme.html is accessible and may disclose the WordPress version.",
     "Delete /readme.html from the server.",
     False),
    ("/license.txt",           "PC-MCFG-010", "REM-MCFG-010", Severity.LOW,
     "license.txt is publicly accessible",
     "license.txt is accessible, confirming WordPress installation.",
     "Delete /license.txt from the server.",
     False),
    ("/wlwmanifest.xml",       "PC-MCFG-011", "REM-MCFG-011", Severity.LOW,
     "wlwmanifest.xml exposes Windows Live Writer endpoint",
     "wlwmanifest.xml is accessible, exposing the blog endpoint for Windows Live Writer.",
     "Remove wlwmanifest link: remove_action('wp_head', 'wlwmanifest_link');",
     False),
    ("/wp-cron.php",           "PC-MCFG-012", "REM-MCFG-012", Severity.MEDIUM,
     "wp-cron.php is externally accessible",
     "wp-cron.php is publicly accessible, allowing external triggering of scheduled tasks.",
     "Disable wp-cron and use a real cron job: define('DISABLE_WP_CRON', true);",
     False),
]


class MisconfigsModule(ScanModule):
    name = "misconfigs"
    depends_on = ["fingerprint"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress:
            return

        # Fetch baseline 404 to detect WordPress catch-all redirect pattern
        baseline_size = await self._get_baseline_size(ctx, http)

        await asyncio.gather(*[
            self._check(ctx, http, baseline_size, *args) for args in _CHECKS
        ])

    async def _get_baseline_size(self, ctx: ScanContext, http: PlecostHTTPClient) -> int:
        """Request a guaranteed non-existent path to get the 404 page size."""
        try:
            r = await http.get(ctx.url + "/plecost-canary-404-xyz-nonexistent-12345")
            return len(r.content)
        except Exception:
            return -1

    async def _check(
        self, ctx: ScanContext, http: PlecostHTTPClient, baseline_size: int,
        path: str, finding_id: str, rem_id: str, severity: Severity,
        title: str, description: str, remediation: str, php_source_check: bool
    ) -> None:
        url = ctx.url + path
        try:
            r = await http.get(url)

            if r.status_code != 200:
                return

            body = r.content
            body_size = len(body)

            # Skip if response is identical size to baseline 404 (WordPress catch-all)
            if baseline_size > 0 and body_size == baseline_size:
                return

            # Skip if body is empty (PHP file executed server-side, no output leaked)
            if body_size == 0:
                return

            # For wp-config.php: only flag if PHP source code is visible
            if php_source_check and not _PHP_SOURCE_RE.search(r.text):
                return

            ctx.add_finding(Finding(
                id=finding_id, remediation_id=rem_id,
                title=title, severity=severity,
                description=description,
                evidence={"url": url, "status_code": r.status_code, "body_size": body_size},
                remediation=remediation,
                references=["https://wordpress.org/support/article/hardening-wordpress/"],
                cvss_score=None, module=self.name
            ))
        except Exception:
            pass
