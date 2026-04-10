from __future__ import annotations
import re
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule

_REQUIRED_HEADERS = [
    ("strict-transport-security", "PC-HDR-001", "REM-HDR-001", Severity.MEDIUM,
     "Missing Strict-Transport-Security (HSTS) header",
     "HSTS header is not set, allowing downgrade attacks.",
     "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("x-frame-options", "PC-HDR-002", "REM-HDR-002", Severity.MEDIUM,
     "Missing X-Frame-Options header",
     "X-Frame-Options is not set, allowing clickjacking attacks.",
     "Add header: X-Frame-Options: SAMEORIGIN"),
    ("x-content-type-options", "PC-HDR-003", "REM-HDR-003", Severity.LOW,
     "Missing X-Content-Type-Options header",
     "X-Content-Type-Options is not set, allowing MIME sniffing.",
     "Add header: X-Content-Type-Options: nosniff"),
    ("content-security-policy", "PC-HDR-004", "REM-HDR-004", Severity.MEDIUM,
     "Missing Content-Security-Policy header",
     "CSP header is not set, increasing XSS risk.",
     "Add a Content-Security-Policy header appropriate for your site."),
    ("referrer-policy", "PC-HDR-005", "REM-HDR-005", Severity.LOW,
     "Missing Referrer-Policy header",
     "Referrer-Policy is not set.",
     "Add header: Referrer-Policy: strict-origin-when-cross-origin"),
    ("permissions-policy", "PC-HDR-006", "REM-HDR-006", Severity.LOW,
     "Missing Permissions-Policy header",
     "Permissions-Policy is not set.",
     "Add a Permissions-Policy header to restrict browser features."),
]


class HTTPHeadersModule(ScanModule):
    name = "http_headers"
    depends_on = ["fingerprint"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress:
            return
        try:
            r = await http.get(ctx.url + "/")
        except Exception:
            return

        headers = {k.lower(): v for k, v in r.headers.items()}

        for header, fid, rid, sev, title, desc, rem in _REQUIRED_HEADERS:
            if header not in headers:
                ctx.add_finding(Finding(
                    id=fid, remediation_id=rid, title=title, severity=sev,
                    description=desc, evidence={"url": ctx.url + "/"},
                    remediation=rem, references=["https://securityheaders.com/"],
                    cvss_score=None, module=self.name
                ))

        # Server version disclosure
        server = headers.get("server", "")
        if server and re.search(r'\d+\.\d+', server):
            ctx.add_finding(Finding(
                id="PC-HDR-007", remediation_id="REM-HDR-007",
                title="Server header discloses version",
                severity=Severity.LOW,
                description=f"Server header reveals version: {server}",
                evidence={"server": server},
                remediation="Configure web server to hide version number.",
                references=[], cvss_score=None, module=self.name
            ))

        # X-Powered-By PHP disclosure
        powered_by = headers.get("x-powered-by", "")
        if powered_by and "php" in powered_by.lower():
            ctx.add_finding(Finding(
                id="PC-HDR-008", remediation_id="REM-HDR-008",
                title="X-Powered-By header discloses PHP version",
                severity=Severity.LOW,
                description=f"X-Powered-By reveals: {powered_by}",
                evidence={"x-powered-by": powered_by},
                remediation="Set expose_php = Off in php.ini.",
                references=[], cvss_score=None, module=self.name
            ))
