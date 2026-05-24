from __future__ import annotations
import re
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule

_PHP_ERROR_RE = re.compile(r'<b>(Notice|Warning|Fatal error|Parse error)</b>:', re.I)

# AC-5: Full Path Disclosure via REST API — matches absolute server paths in response body
_SERVER_PATH_RE = re.compile(r'/(?:var|home|srv|www|opt|usr)/[^"<\s]{3,}')


class DebugExposureModule(ScanModule):
    name = "debug_exposure"
    depends_on = ["fingerprint"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress and not ctx.opts.force:
            return
        try:
            r = await http.get(ctx.url + "/")
        except Exception:
            return

        # PC-DBG-001: WP_DEBUG active
        if debug_match := _PHP_ERROR_RE.search(r.text):
            ctx.add_finding(Finding(
                id="PC-DBG-001", remediation_id="REM-DBG-001",
                title="WP_DEBUG is active — PHP errors exposed in response",
                severity=Severity.HIGH,
                description="PHP error messages are visible in the page response, indicating WP_DEBUG=true.",
                evidence={"url": ctx.url + "/", "match": debug_match.group(0)},
                remediation="Set WP_DEBUG to false in wp-config.php for production.",
                references=["https://wordpress.org/support/article/debugging-in-wordpress/"],
                cvss_score=5.3, module=self.name
            ))

        # AC-5: PC-DBG-002 — Full Path Disclosure via REST API invalid query
        await self._check_fpd_rest_api(ctx, http)

    async def _check_fpd_rest_api(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        """AC-5: Probe REST API with invalid param to trigger Full Path Disclosure."""
        try:
            rest_url = ctx.url + "/wp-json/wp/v2/"
            r = await http.get(rest_url + "?invalid_param=__plecost_fpd_probe__")
            if r.status_code not in (200, 400, 500):
                return
            body = r.text[:4096] if r.text else ""
            if path_match := _SERVER_PATH_RE.search(body):
                ctx.add_finding(Finding(
                    id="PC-DBG-002", remediation_id="REM-DBG-002",
                    title="Full Path Disclosure via REST API",
                    severity=Severity.MEDIUM,
                    description=(
                        "The WordPress REST API leaks the absolute server file-system path "
                        "in its response body when queried with an invalid parameter, "
                        "aiding attackers in mapping server layout."
                    ),
                    evidence={"url": rest_url, "path_found": path_match.group(0)},
                    remediation=(
                        "Set WP_DEBUG to false in wp-config.php and ensure PHP error "
                        "display is off in production: display_errors = Off in php.ini."
                    ),
                    references=["https://owasp.org/www-community/attacks/Full_Path_Disclosure"],
                    cvss_score=5.3, module=self.name
                ))
        except Exception:
            pass
