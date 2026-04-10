from __future__ import annotations
import asyncio
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule

_DIRS = [
    ("/wp-content/",           "PC-DIR-001", "REM-DIR-001", "Directory listing enabled in /wp-content/"),
    ("/wp-content/plugins/",   "PC-DIR-002", "REM-DIR-002", "Directory listing enabled in /wp-content/plugins/"),
    ("/wp-content/themes/",    "PC-DIR-003", "REM-DIR-003", "Directory listing enabled in /wp-content/themes/"),
    ("/wp-content/uploads/",   "PC-DIR-004", "REM-DIR-004", "Directory listing enabled in /wp-content/uploads/"),
]


class DirectoryListingModule(ScanModule):
    name = "directory_listing"
    depends_on = ["fingerprint"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress:
            return
        await asyncio.gather(*[self._check(ctx, http, *args) for args in _DIRS])

    async def _check(
        self, ctx: ScanContext, http: PlecostHTTPClient,
        path: str, finding_id: str, rem_id: str, title: str
    ) -> None:
        url = ctx.url + path
        try:
            r = await http.get(url)
            body_lower = r.text.lower()
            if r.status_code == 200 and ("index of" in body_lower or "<title>index of" in body_lower):
                ctx.add_finding(Finding(
                    id=finding_id, remediation_id=rem_id,
                    title=title, severity=Severity.HIGH,
                    description=f"Directory listing is enabled at {url}, exposing all files.",
                    evidence={"url": url},
                    remediation="Add 'Options -Indexes' to .htaccess or disable autoindex in nginx.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                    cvss_score=5.3, module=self.name
                ))
        except Exception:
            pass
