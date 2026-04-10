from __future__ import annotations
import re
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule

_META_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]+)', re.I)
_VER_RE = re.compile(r'[Vv]ersion[:\s]+([\d.]+)')
_QVER_RE = re.compile(r'\?ver=([\d.]+)')


class FingerprintModule(ScanModule):
    name = "fingerprint"
    depends_on: list[str] = []

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        version = await self._detect_version(ctx, http)
        if version or await self._check_wp_login(ctx, http):
            ctx.is_wordpress = True
        if version:
            ctx.wordpress_version = version

    async def _detect_version(self, ctx: ScanContext, http: PlecostHTTPClient) -> str | None:
        # Method 1: meta generator tag on homepage
        try:
            r = await http.get(ctx.url + "/")
            if m := _META_RE.search(r.text):
                ctx.add_finding(Finding(
                    id="PC-FP-001", remediation_id="REM-FP-001",
                    title="WordPress version disclosed via meta generator tag",
                    severity=Severity.LOW,
                    description=f"WordPress version {m.group(1)} found in meta generator tag.",
                    evidence={"url": ctx.url + "/", "match": m.group(0)},
                    remediation="Remove the generator meta tag. Add to functions.php: remove_action('wp_head', 'wp_generator');",
                    references=["https://wordpress.org/support/article/hardening-wordpress/"],
                    cvss_score=None, module=self.name
                ))
                return m.group(1)
        except Exception:
            pass

        # Method 2: /readme.html
        try:
            r = await http.get(ctx.url + "/readme.html")
            if r.status_code == 200:
                if m := _VER_RE.search(r.text):
                    ctx.add_finding(Finding(
                        id="PC-FP-002", remediation_id="REM-FP-002",
                        title="WordPress version disclosed via readme.html",
                        severity=Severity.LOW,
                        description=f"WordPress version {m.group(1)} found in /readme.html.",
                        evidence={"url": ctx.url + "/readme.html"},
                        remediation="Delete /readme.html from the server.",
                        references=[], cvss_score=None, module=self.name
                    ))
                    return m.group(1)
        except Exception:
            pass

        # Method 3: RSS feed generator tag
        try:
            r = await http.get(ctx.url + "/feed/")
            if r.status_code == 200 and "generator" in r.text:
                if m := re.search(r'<generator>.*?/([\d.]+)</generator>', r.text):
                    return m.group(1)
        except Exception:
            pass

        return None

    async def _check_wp_login(self, ctx: ScanContext, http: PlecostHTTPClient) -> bool:
        try:
            r = await http.get(ctx.url + "/wp-login.php")
            return r.status_code == 200 and "wp-login" in r.text.lower()
        except Exception:
            return False
