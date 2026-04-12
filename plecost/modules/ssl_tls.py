from __future__ import annotations
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule
import httpx


class SSLTLSModule(ScanModule):
    name = "ssl_tls"
    depends_on = ["fingerprint"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress:
            return
        await self._check_http_redirect(ctx, http)
        await self._check_ssl_cert(ctx, http)

    async def _check_http_redirect(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        """Check that HTTP redirects to HTTPS."""
        if not ctx.url.startswith("https://"):
            return
        http_url = ctx.url.replace("https://", "http://", 1)
        try:
            # Use a fresh client without follow_redirects to check redirect
            async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
                r = await client.get(http_url + "/")
                if r.status_code not in (301, 302, 308):
                    ctx.add_finding(Finding(
                        id="PC-SSL-001", remediation_id="REM-SSL-001",
                        title="HTTP to HTTPS redirect is missing",
                        severity=Severity.HIGH,
                        description="The site does not redirect HTTP traffic to HTTPS.",
                        evidence={"url": http_url, "status_code": r.status_code},
                        remediation="Configure web server to redirect all HTTP traffic to HTTPS.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                        cvss_score=None, module=self.name
                    ))
        except Exception:
            pass

    async def _check_ssl_cert(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        """Check for SSL certificate issues."""
        if not ctx.url.startswith("https://"):
            return
        try:
            async with httpx.AsyncClient(timeout=10, verify=True) as client:
                await client.get(ctx.url + "/")
        except (httpx.ConnectError, httpx.TransportError) as e:
            if "ssl" in str(e).lower() or "certificate" in str(e).lower() or "tls" in str(e).lower():
                ctx.add_finding(Finding(
                    id="PC-SSL-002", remediation_id="REM-SSL-002",
                    title="SSL certificate is invalid or expired",
                    severity=Severity.HIGH,
                    description=f"SSL certificate validation failed: {e}",
                    evidence={"url": ctx.url, "error": str(e)},
                    remediation="Renew or replace the SSL certificate. Use Let's Encrypt for free certificates.",
                    references=["https://letsencrypt.org/"],
                    cvss_score=None, module=self.name
                ))
        except Exception:
            pass

        # Check HSTS
        try:
            r = await http.get(ctx.url + "/")
            if "strict-transport-security" not in {k.lower() for k in r.headers.keys()}:
                ctx.add_finding(Finding(
                    id="PC-SSL-003", remediation_id="REM-SSL-003",
                    title="HSTS (Strict-Transport-Security) header not set",
                    severity=Severity.LOW,
                    description="HSTS header is missing from HTTPS response.",
                    evidence={"url": ctx.url + "/"},
                    remediation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    references=[], cvss_score=None, module=self.name
                ))
        except Exception:
            pass
