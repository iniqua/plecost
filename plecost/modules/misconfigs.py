from __future__ import annotations
import asyncio
import re
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule
from plecost.i18n import t

# PHP source code patterns — if found, wp-config.php is truly exposed
_PHP_SOURCE_RE = re.compile(r'(define\s*\(|DB_PASSWORD|DB_HOST|DB_NAME|\$table_prefix)', re.I)

_CHECKS = [
    ("/wp-config.php",         "PC-MCFG-001", "REM-MCFG-001", Severity.CRITICAL,
     "findings.pc_mcfg_001.title",
     "findings.pc_mcfg_001.description",
     "findings.pc_mcfg_001.remediation",
     True),
    ("/wp-config.php.bak",     "PC-MCFG-002", "REM-MCFG-002", Severity.CRITICAL,
     "findings.pc_mcfg_002.title",
     "findings.pc_mcfg_002.description",
     "findings.pc_mcfg_002.remediation",
     False),
    ("/.env",                  "PC-MCFG-003", "REM-MCFG-003", Severity.CRITICAL,
     "findings.pc_mcfg_003.title",
     "findings.pc_mcfg_003.description",
     "findings.pc_mcfg_003.remediation",
     False),
    ("/.git/HEAD",             "PC-MCFG-004", "REM-MCFG-004", Severity.HIGH,
     "findings.pc_mcfg_004.title",
     "findings.pc_mcfg_004.description",
     "findings.pc_mcfg_004.remediation",
     False),
    ("/debug.log",             "PC-MCFG-005", "REM-MCFG-005", Severity.HIGH,
     "findings.pc_mcfg_005.title",
     "findings.pc_mcfg_005.description",
     "findings.pc_mcfg_005.remediation",
     False),
    ("/backup.sql",            "PC-MCFG-006", "REM-MCFG-006", Severity.HIGH,
     "findings.pc_mcfg_006.title",
     "findings.pc_mcfg_006.description",
     "findings.pc_mcfg_006.remediation",
     False),
    ("/wp-admin/install.php",  "PC-MCFG-007", "REM-MCFG-007", Severity.MEDIUM,
     "findings.pc_mcfg_007.title",
     "findings.pc_mcfg_007.description",
     "findings.pc_mcfg_007.remediation",
     False),
    ("/wp-admin/upgrade.php",  "PC-MCFG-008", "REM-MCFG-008", Severity.MEDIUM,
     "findings.pc_mcfg_008.title",
     "findings.pc_mcfg_008.description",
     "findings.pc_mcfg_008.remediation",
     False),
    ("/readme.html",           "PC-MCFG-009", "REM-MCFG-009", Severity.LOW,
     "findings.pc_mcfg_009.title",
     "findings.pc_mcfg_009.description",
     "findings.pc_mcfg_009.remediation",
     False),
    ("/license.txt",           "PC-MCFG-010", "REM-MCFG-010", Severity.LOW,
     "findings.pc_mcfg_010.title",
     "findings.pc_mcfg_010.description",
     "findings.pc_mcfg_010.remediation",
     False),
    ("/wlwmanifest.xml",       "PC-MCFG-011", "REM-MCFG-011", Severity.LOW,
     "findings.pc_mcfg_011.title",
     "findings.pc_mcfg_011.description",
     "findings.pc_mcfg_011.remediation",
     False),
    ("/wp-cron.php",           "PC-MCFG-012", "REM-MCFG-012", Severity.MEDIUM,
     "findings.pc_mcfg_012.title",
     "findings.pc_mcfg_012.description",
     "findings.pc_mcfg_012.remediation",
     False),
]


class MisconfigsModule(ScanModule):
    name = "misconfigs"
    depends_on = ["fingerprint"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress and not ctx.opts.force:
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
        title_key: str, description_key: str, remediation_key: str, php_source_check: bool
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
                title=t(title_key), severity=severity,
                description=t(description_key),
                evidence={"url": url, "status_code": r.status_code, "body_size": body_size},
                remediation=t(remediation_key),
                references=["https://wordpress.org/support/article/hardening-wordpress/"],
                cvss_score=None, module=self.name
            ))
        except Exception:
            pass
