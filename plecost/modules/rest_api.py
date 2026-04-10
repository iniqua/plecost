from __future__ import annotations
import re
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule

_REST_LINK_RE = re.compile(r'rel=["\']https://api\.w\.org/["\']', re.I)


class RESTAPIModule(ScanModule):
    name = "rest_api"
    depends_on = ["fingerprint"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress:
            return

        await self._check_rest_link(ctx, http)
        await self._check_oembed(ctx, http)
        await self._check_cors(ctx, http)

    async def _check_rest_link(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        try:
            r = await http.get(ctx.url + "/")
            if _REST_LINK_RE.search(r.text):
                ctx.add_finding(Finding(
                    id="PC-REST-001", remediation_id="REM-REST-001",
                    title="REST API link exposed in HTML head",
                    severity=Severity.INFO,
                    description="The REST API link rel='https://api.w.org/' is exposed in the page HTML head.",
                    evidence={"url": ctx.url + "/"},
                    remediation="Remove REST API link: remove_action('wp_head', 'rest_output_link_wp_head');",
                    references=[], cvss_score=None, module=self.name
                ))
        except Exception:
            pass

    async def _check_oembed(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        try:
            r = await http.get(f"{ctx.url}/wp-json/oembed/1.0/embed?url={ctx.url}")
            if r.status_code == 200 and "author_name" in r.text:
                ctx.add_finding(Finding(
                    id="PC-REST-002", remediation_id="REM-REST-002",
                    title="oEmbed endpoint exposes author information",
                    severity=Severity.LOW,
                    description="The oEmbed endpoint reveals author username/display name.",
                    evidence={"url": f"{ctx.url}/wp-json/oembed/1.0/embed"},
                    remediation="Disable oEmbed or filter author_name from response.",
                    references=[], cvss_score=None, module=self.name
                ))
        except Exception:
            pass

    async def _check_cors(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        try:
            r = await http.get(f"{ctx.url}/wp-json/wp/v2/")
            cors = r.headers.get("access-control-allow-origin", "")
            if cors == "*":
                ctx.add_finding(Finding(
                    id="PC-REST-003", remediation_id="REM-REST-003",
                    title="REST API CORS misconfiguration (Allow-Origin: *)",
                    severity=Severity.MEDIUM,
                    description="The REST API allows cross-origin requests from any domain.",
                    evidence={"url": f"{ctx.url}/wp-json/wp/v2/", "header": cors},
                    remediation="Restrict CORS origins. Use the rest_pre_serve_request filter.",
                    references=[], cvss_score=5.3, module=self.name
                ))
        except Exception:
            pass
