from __future__ import annotations
import re
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule

_META_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]+)', re.I)
_VER_RE = re.compile(r'[Vv]ersion[:\s]+([\d.]+)')
_GENERATOR_FEED_RE = re.compile(r'<generator>.*?/([\d.]+)</generator>')
_LINK_API_RE = re.compile(r'rel=["\']https://api\.w\.org/["\']', re.I)

# WordPress-specific paths: a non-404 response on any of these indicates WordPress.
# We use these ONLY when the baseline probe confirms that the server returns 404
# for genuinely nonexistent paths (i.e. 403 is meaningful, not a blanket WAF block).
_WP_EXISTENCE_PATHS = [
    "/wp-login.php",
    "/wp-admin/",
    "/xmlrpc.php",
    "/wp-cron.php",
]


class FingerprintModule(ScanModule):
    name = "fingerprint"
    depends_on: list[str] = []

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        # Try each detection method in order. The first successful one wins.
        if await self._try_meta_generator(ctx, http):
            return
        if await self._try_readme(ctx, http):
            return
        if await self._try_feed(ctx, http):
            return
        if await self._try_rest_api(ctx, http):
            return
        # No version found — try to confirm WordPress presence without version
        if await self._try_wp_paths(ctx, http):
            return
        # All methods failed — WordPress not detected

    async def _try_meta_generator(self, ctx: ScanContext, http: PlecostHTTPClient) -> bool:
        """Detect WordPress version via meta generator tag on homepage."""
        try:
            r = await http.get(ctx.url + "/")
            if r.status_code != 200:
                return False
            if m := _META_RE.search(r.text):
                ctx.is_wordpress = True
                ctx.wordpress_version = m.group(1)
                ctx.add_finding(Finding(
                    id="PC-FP-001", remediation_id="REM-FP-001",
                    title="WordPress version disclosed via meta generator tag",
                    severity=Severity.LOW,
                    description=f"WordPress version {m.group(1)} found in meta generator tag.",
                    evidence={"url": ctx.url + "/", "match": m.group(0)},
                    remediation="Remove the generator meta tag. Add to functions.php: "
                                "remove_action('wp_head', 'wp_generator');",
                    references=["https://wordpress.org/support/article/hardening-wordpress/"],
                    cvss_score=None, module=self.name
                ))
                return True
            # Homepage accessible but no generator tag — still check for WP indicators
            if "wp-content" in r.text or _LINK_API_RE.search(r.text):
                ctx.is_wordpress = True
                return True
        except Exception:
            pass
        return False

    async def _try_readme(self, ctx: ScanContext, http: PlecostHTTPClient) -> bool:
        """Detect WordPress version via /readme.html."""
        try:
            r = await http.get(ctx.url + "/readme.html")
            if r.status_code == 200:
                if m := _VER_RE.search(r.text):
                    ctx.is_wordpress = True
                    ctx.wordpress_version = m.group(1)
                    ctx.add_finding(Finding(
                        id="PC-FP-002", remediation_id="REM-FP-002",
                        title="WordPress version disclosed via readme.html",
                        severity=Severity.LOW,
                        description=f"WordPress version {m.group(1)} found in /readme.html.",
                        evidence={"url": ctx.url + "/readme.html"},
                        remediation="Delete /readme.html from the server.",
                        references=[], cvss_score=None, module=self.name
                    ))
                    return True
        except Exception:
            pass
        return False

    async def _try_feed(self, ctx: ScanContext, http: PlecostHTTPClient) -> bool:
        """Detect WordPress version via RSS feed generator tag."""
        try:
            r = await http.get(ctx.url + "/feed/")
            if r.status_code == 200 and "generator" in r.text:
                if m := _GENERATOR_FEED_RE.search(r.text):
                    ctx.is_wordpress = True
                    ctx.wordpress_version = m.group(1)
                    return True
        except Exception:
            pass
        return False

    async def _try_rest_api(self, ctx: ScanContext, http: PlecostHTTPClient) -> bool:
        """Detect WordPress via REST API root endpoint."""
        try:
            r = await http.get(ctx.url + "/wp-json/")
            if r.status_code == 200 and "application/json" in r.headers.get("content-type", ""):
                data = r.json()
                if "namespaces" in data or "name" in data:
                    ctx.is_wordpress = True
                    ver = data.get("version")
                    if ver:
                        ctx.wordpress_version = ver
                    return True
        except Exception:
            pass
        return False

    async def _try_wp_paths(self, ctx: ScanContext, http: PlecostHTTPClient) -> bool:
        """
        Confirm WordPress by checking well-known WP-specific paths.

        Strategy: first probe a nonexistent path to establish the server's 404 behavior.
        - If the server returns 404 for nonexistent paths (normal), then a non-404
          response on WP-specific paths means those paths exist → WordPress confirmed.
        - If the server returns non-404 for nonexistent paths (blanket WAF block),
          we can't rely on status codes — fall back to body/header content inspection.
        """
        baseline_is_404 = True
        try:
            probe = await http.get(ctx.url + "/__plecost_probe_nonexistent__/")
            baseline_is_404 = probe.status_code == 404
        except Exception:
            pass

        for path in _WP_EXISTENCE_PATHS:
            try:
                r = await http.get(ctx.url + path)
                if baseline_is_404:
                    # Normal server: any non-404 on a WP-specific path confirms WP
                    if r.status_code != 404:
                        ctx.is_wordpress = True
                        return True
                else:
                    # WAF blanket block: look for WP-specific content in the response
                    body = r.text.lower()
                    if any(kw in body for kw in ("wp-login", "wordpress", "wp-admin", "xmlrpc")):
                        ctx.is_wordpress = True
                        return True
                    if "api.w.org" in r.headers.get("link", ""):
                        ctx.is_wordpress = True
                        return True
            except Exception:
                pass

        return False
