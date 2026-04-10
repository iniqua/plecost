from __future__ import annotations
import re
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule

_PHP_ERROR_RE = re.compile(r'<b>(Notice|Warning|Fatal error|Parse error)</b>:', re.I)
_PHP_VER_RE = re.compile(r'PHP/(\d+\.\d+\.\d+)', re.I)


class DebugExposureModule(ScanModule):
    name = "debug_exposure"
    depends_on = ["fingerprint"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress:
            return
        try:
            r = await http.get(ctx.url + "/")
        except Exception:
            return

        # PC-DBG-001: WP_DEBUG active
        if _PHP_ERROR_RE.search(r.text):
            ctx.add_finding(Finding(
                id="PC-DBG-001", remediation_id="REM-DBG-001",
                title="WP_DEBUG is active — PHP errors exposed in response",
                severity=Severity.HIGH,
                description="PHP error messages are visible in the page response, indicating WP_DEBUG=true.",
                evidence={"url": ctx.url + "/", "match": _PHP_ERROR_RE.search(r.text).group(0)},
                remediation="Set WP_DEBUG to false in wp-config.php for production.",
                references=["https://wordpress.org/support/article/debugging-in-wordpress/"],
                cvss_score=5.3, module=self.name
            ))

        # PC-DBG-003: PHP version in X-Powered-By
        powered_by = r.headers.get("x-powered-by", "")
        if powered_by and "php" in powered_by.lower():
            ctx.add_finding(Finding(
                id="PC-DBG-003", remediation_id="REM-DBG-003",
                title="PHP version exposed via X-Powered-By header",
                severity=Severity.MEDIUM,
                description=f"PHP version is disclosed in X-Powered-By header: {powered_by}",
                evidence={"header": "X-Powered-By", "value": powered_by},
                remediation="Set expose_php = Off in php.ini.",
                references=[], cvss_score=None, module=self.name
            ))
