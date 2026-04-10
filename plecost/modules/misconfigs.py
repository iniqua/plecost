from __future__ import annotations
import asyncio
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule

_CHECKS = [
    ("/wp-config.php",         "PC-MCFG-001", "REM-MCFG-001", Severity.CRITICAL,
     "wp-config.php is publicly accessible",
     "wp-config.php is accessible and may expose database credentials.",
     "Restrict access via .htaccess or move wp-config.php one level above webroot."),
    ("/wp-config.php.bak",     "PC-MCFG-002", "REM-MCFG-002", Severity.CRITICAL,
     "wp-config.php backup is publicly accessible",
     "A backup of wp-config.php is accessible and may expose database credentials.",
     "Delete backup files from the server."),
    ("/.env",                  "PC-MCFG-003", "REM-MCFG-003", Severity.CRITICAL,
     ".env file is publicly accessible",
     ".env file is accessible and may expose application secrets.",
     "Restrict access to .env files via web server configuration."),
    ("/.git/HEAD",             "PC-MCFG-004", "REM-MCFG-004", Severity.HIGH,
     ".git directory is publicly accessible",
     "The .git directory is accessible, potentially exposing source code.",
     "Deny access to .git directory in web server configuration."),
    ("/debug.log",             "PC-MCFG-005", "REM-MCFG-005", Severity.HIGH,
     "debug.log is publicly accessible",
     "WordPress debug log is accessible and may expose sensitive information.",
     "Delete debug.log and disable WP_DEBUG_LOG in wp-config.php."),
    ("/backup.sql",            "PC-MCFG-006", "REM-MCFG-006", Severity.HIGH,
     "SQL backup file is publicly accessible",
     "A database backup file is accessible and may expose all data.",
     "Remove backup files from the webroot."),
    ("/wp-admin/install.php",  "PC-MCFG-007", "REM-MCFG-007", Severity.MEDIUM,
     "wp-admin/install.php is accessible",
     "WordPress installation script is accessible.",
     "WordPress should already be installed. Restrict access to install.php."),
    ("/wp-admin/upgrade.php",  "PC-MCFG-008", "REM-MCFG-008", Severity.MEDIUM,
     "wp-admin/upgrade.php is accessible",
     "WordPress upgrade script is accessible.",
     "Restrict access to upgrade.php after updates."),
    ("/readme.html",           "PC-MCFG-009", "REM-MCFG-009", Severity.LOW,
     "readme.html discloses WordPress version",
     "readme.html is accessible and may disclose the WordPress version.",
     "Delete /readme.html from the server."),
    ("/license.txt",           "PC-MCFG-010", "REM-MCFG-010", Severity.LOW,
     "license.txt is publicly accessible",
     "license.txt is accessible, confirming WordPress installation.",
     "Delete /license.txt from the server."),
    ("/wlwmanifest.xml",       "PC-MCFG-011", "REM-MCFG-011", Severity.LOW,
     "wlwmanifest.xml exposes Windows Live Writer endpoint",
     "wlwmanifest.xml is accessible, exposing the blog endpoint for Windows Live Writer.",
     "Remove wlwmanifest link: remove_action('wp_head', 'wlwmanifest_link');"),
    ("/wp-cron.php",           "PC-MCFG-012", "REM-MCFG-012", Severity.MEDIUM,
     "wp-cron.php is externally accessible",
     "wp-cron.php is publicly accessible, allowing external triggering of scheduled tasks.",
     "Disable wp-cron and use a real cron job: define('DISABLE_WP_CRON', true);"),
]


class MisconfigsModule(ScanModule):
    name = "misconfigs"
    depends_on = ["fingerprint"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress:
            return
        await asyncio.gather(*[self._check(ctx, http, *args) for args in _CHECKS])

    async def _check(
        self, ctx: ScanContext, http: PlecostHTTPClient,
        path: str, finding_id: str, rem_id: str, severity: Severity,
        title: str, description: str, remediation: str
    ) -> None:
        url = ctx.url + path
        try:
            r = await http.get(url)
            if r.status_code == 200:
                ctx.add_finding(Finding(
                    id=finding_id, remediation_id=rem_id,
                    title=title, severity=severity,
                    description=description,
                    evidence={"url": url, "status_code": r.status_code},
                    remediation=remediation,
                    references=["https://wordpress.org/support/article/hardening-wordpress/"],
                    cvss_score=None, module=self.name
                ))
        except Exception:
            pass
