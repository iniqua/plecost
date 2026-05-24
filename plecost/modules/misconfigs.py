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

# Adminer signature: body must contain "class Adminer" to avoid FPs
_ADMINER_SIGNATURE_RE = re.compile(r'class Adminer', re.I)

# install.php: only flag if the active installation form is present (language-independent HTML)
# A healthy "Already installed" page has no such input field.
_INSTALL_ACTIVE_RE = re.compile(r'<input[^>]+name=["\']weblog_title', re.IGNORECASE)

# upgrade.php: only flag if the upgrade form/link is present (language-independent HTML)
# A "No upgrade required" page has no such form or upgrade link.
_UPGRADE_ACTIVE_RE = re.compile(r'<(?:form|a)[^>]+(?:upgrade\.php|do_upgrade)', re.IGNORECASE)

_CHECKS = [
    # (path, finding_id, rem_id, severity, title_key, description_key, remediation_key,
    #  php_source_check, plaintext_check, content_signature)
    # plaintext_check=True → skip if Content-Type contains "text/html" (soft-404 FP prevention)
    # content_signature=regex → body[:4096] must match; None = no body check (positive gate)
    ("/wp-config.php",         "PC-MCFG-001", "REM-MCFG-001", Severity.CRITICAL,
     "findings.pc_mcfg_001.title",
     "findings.pc_mcfg_001.description",
     "findings.pc_mcfg_001.remediation",
     True,  False, None),
    ("/wp-config.php.bak",     "PC-MCFG-002", "REM-MCFG-002", Severity.CRITICAL,
     "findings.pc_mcfg_002.title",
     "findings.pc_mcfg_002.description",
     "findings.pc_mcfg_002.remediation",
     False, True, None),
    ("/.env",                  "PC-MCFG-003", "REM-MCFG-003", Severity.CRITICAL,
     "findings.pc_mcfg_003.title",
     "findings.pc_mcfg_003.description",
     "findings.pc_mcfg_003.remediation",
     False, True, None),
    ("/.git/HEAD",             "PC-MCFG-004", "REM-MCFG-004", Severity.HIGH,
     "findings.pc_mcfg_004.title",
     "findings.pc_mcfg_004.description",
     "findings.pc_mcfg_004.remediation",
     False, True, None),
    ("/debug.log",             "PC-MCFG-005", "REM-MCFG-005", Severity.HIGH,
     "findings.pc_mcfg_005.title",
     "findings.pc_mcfg_005.description",
     "findings.pc_mcfg_005.remediation",
     False, True, None),
    ("/backup.sql",            "PC-MCFG-006", "REM-MCFG-006", Severity.HIGH,
     "findings.pc_mcfg_006.title",
     "findings.pc_mcfg_006.description",
     "findings.pc_mcfg_006.remediation",
     False, True, None),
    # install.php: only flag if the active installation form (weblog_title input) is present.
    # A healthy "Already installed" page lacks this field — no phrase matching needed.
    ("/wp-admin/install.php",  "PC-MCFG-007", "REM-MCFG-007", Severity.MEDIUM,
     "findings.pc_mcfg_007.title",
     "findings.pc_mcfg_007.description",
     "findings.pc_mcfg_007.remediation",
     False, False, _INSTALL_ACTIVE_RE),
    # upgrade.php: only flag if the upgrade form or link is present in the HTML.
    # A "No upgrade required" page has neither — no phrase matching needed.
    ("/wp-admin/upgrade.php",  "PC-MCFG-008", "REM-MCFG-008", Severity.MEDIUM,
     "findings.pc_mcfg_008.title",
     "findings.pc_mcfg_008.description",
     "findings.pc_mcfg_008.remediation",
     False, False, _UPGRADE_ACTIVE_RE),
    ("/readme.html",           "PC-MCFG-009", "REM-MCFG-009", Severity.LOW,
     "findings.pc_mcfg_009.title",
     "findings.pc_mcfg_009.description",
     "findings.pc_mcfg_009.remediation",
     False, False, None),
    ("/license.txt",           "PC-MCFG-010", "REM-MCFG-010", Severity.LOW,
     "findings.pc_mcfg_010.title",
     "findings.pc_mcfg_010.description",
     "findings.pc_mcfg_010.remediation",
     False, False, None),
    ("/wlwmanifest.xml",       "PC-MCFG-011", "REM-MCFG-011", Severity.LOW,
     "findings.pc_mcfg_011.title",
     "findings.pc_mcfg_011.description",
     "findings.pc_mcfg_011.remediation",
     False, False, None),
    ("/wp-cron.php",           "PC-MCFG-012", "REM-MCFG-012", Severity.MEDIUM,
     "findings.pc_mcfg_012.title",
     "findings.pc_mcfg_012.description",
     "findings.pc_mcfg_012.remediation",
     False, False, None),
    # AC-1: debug.log in wp-content (HIGH)
    ("/wp-content/debug.log",  "PC-MCFG-013", "REM-MCFG-013", Severity.HIGH,
     "findings.pc_mcfg_013.title",
     "findings.pc_mcfg_013.description",
     "findings.pc_mcfg_013.remediation",
     False, True, None),
    # AC-2: adminer.php (CRITICAL) — requires "class Adminer" in body[:4096]
    ("/adminer.php",           "PC-MCFG-014", "REM-MCFG-014", Severity.CRITICAL,
     "findings.pc_mcfg_014.title",
     "findings.pc_mcfg_014.description",
     "findings.pc_mcfg_014.remediation",
     False, False, _ADMINER_SIGNATURE_RE),
    # AC-3: wp-config.php backup variants (all CRITICAL)
    ("/wp-config.php~",        "PC-MCFG-015", "REM-MCFG-015", Severity.CRITICAL,
     "findings.pc_mcfg_015.title",
     "findings.pc_mcfg_015.description",
     "findings.pc_mcfg_015.remediation",
     False, True, None),
    ("/wp-config.php.old",     "PC-MCFG-016", "REM-MCFG-016", Severity.CRITICAL,
     "findings.pc_mcfg_016.title",
     "findings.pc_mcfg_016.description",
     "findings.pc_mcfg_016.remediation",
     False, True, None),
    ("/wp-config.php_bak",     "PC-MCFG-017", "REM-MCFG-017", Severity.CRITICAL,
     "findings.pc_mcfg_017.title",
     "findings.pc_mcfg_017.description",
     "findings.pc_mcfg_017.remediation",
     False, True, None),
    ("/wp-config.php.orig",    "PC-MCFG-018", "REM-MCFG-018", Severity.CRITICAL,
     "findings.pc_mcfg_018.title",
     "findings.pc_mcfg_018.description",
     "findings.pc_mcfg_018.remediation",
     False, True, None),
    ("/wp-config.php.save",    "PC-MCFG-019", "REM-MCFG-019", Severity.CRITICAL,
     "findings.pc_mcfg_019.title",
     "findings.pc_mcfg_019.description",
     "findings.pc_mcfg_019.remediation",
     False, True, None),
    # AC-4: database.sql (HIGH)
    ("/database.sql",          "PC-MCFG-020", "REM-MCFG-020", Severity.HIGH,
     "findings.pc_mcfg_020.title",
     "findings.pc_mcfg_020.description",
     "findings.pc_mcfg_020.remediation",
     False, True, None),
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
        title_key: str, description_key: str, remediation_key: str,
        php_source_check: bool, plaintext_check: bool,
        content_signature: "re.Pattern[str] | None" = None,
    ) -> None:
        url = ctx.url + path
        try:
            r = await http.get(url)

            if r.status_code != 200:
                return

            # Skip if the final URL after following redirects differs from the requested URL.
            # WordPress soft-404: non-existent paths redirect to a real page (e.g. the homepage)
            # which returns HTTP 200. Detecting the redirect reveals it is not a real exposure.
            if str(r.url) != url:
                return

            body = r.content
            body_size = len(body)

            # Skip if response is identical size to baseline 404 (WordPress catch-all)
            if baseline_size > 0 and body_size == baseline_size:
                return

            # Skip if body is empty (PHP file executed server-side, no output leaked)
            if body_size == 0:
                return

            # For plaintext files (.env, .git/HEAD, debug.log, backup.sql, wp-config.php.bak):
            # skip if server returned HTML — the file is not truly exposed; WordPress served
            # a catch-all HTML page (soft-404) with a 200 status code.
            if plaintext_check:
                content_type = r.headers.get("content-type", "")
                if "text/html" in content_type:
                    return

            # For wp-config.php: only flag if PHP source code is visible
            if php_source_check and not _PHP_SOURCE_RE.search(r.text):
                return

            # For files requiring a body signature (e.g. adminer.php, install.php, upgrade.php):
            # report ONLY if the signature is present — acts as a positive gate.
            if content_signature is not None and not content_signature.search(r.text[:4096]):
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
