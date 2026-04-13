from __future__ import annotations
import asyncio
import re
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Theme, Finding, Severity
from plecost.modules.base import ScanModule

_THEME_PATH_RE = re.compile(r'/wp-content/themes/([a-z0-9_-]+)/', re.I)
_CSS_VER_RE = re.compile(r'Version:\s*([\d.]+)', re.I)
_QVER_RE = re.compile(r'\?ver=([\d.]+)')


class ThemesModule(ScanModule):
    name = "themes"
    depends_on = ["fingerprint"]

    def __init__(self, wordlist: list[str] | None = None) -> None:
        self._wordlist = wordlist or []

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress and not ctx.opts.force:
            return

        # Passive: scan homepage for theme paths
        found: dict[str, str | None] = {}  # slug -> version
        active_theme: str | None = None
        try:
            r = await http.get(ctx.url + "/")
            for m in _THEME_PATH_RE.finditer(r.text):
                slug = m.group(1)
                surrounding = r.text[max(0, m.start()-5):m.end()+100]
                ver_m = _QVER_RE.search(surrounding)
                if slug not in found:
                    found[slug] = ver_m.group(1) if ver_m else None
                if active_theme is None:
                    active_theme = slug
        except Exception:
            pass

        # Active: brute-force wordlist via style.css
        # Probe a nonexistent theme first to establish the 404 baseline.
        # If the server returns non-404 for nonexistent paths (WAF blanket block),
        # then 403 is not a reliable "theme exists" signal — only accept 200.
        baseline_is_404 = True
        try:
            probe = await http.get(f"{ctx.url}/wp-content/themes/__plecost_probe__/style.css")
            baseline_is_404 = probe.status_code == 404
        except Exception:
            pass

        sem = asyncio.Semaphore(ctx.opts.concurrency)
        total = len(self._wordlist)
        checked = 0

        async def check_theme(slug: str) -> None:
            nonlocal checked
            async with sem:
                url = f"{ctx.url}/wp-content/themes/{slug}/style.css"
                try:
                    r = await http.get(url)
                    exists = r.status_code == 200 or (baseline_is_404 and r.status_code == 403)
                    if exists:
                        ver = None
                        if r.status_code == 200:
                            if m := _CSS_VER_RE.search(r.text):
                                ver = m.group(1)
                        if slug not in found:
                            found[slug] = ver
                        elif ver and found[slug] is None:
                            found[slug] = ver
                except Exception:
                    pass
                finally:
                    checked += 1
                    ctx.report_progress("themes", checked, total)

        await asyncio.gather(*[check_theme(s) for s in self._wordlist])

        for i, (slug, version) in enumerate(found.items()):
            is_active = (slug == active_theme) or (active_theme is None and i == 0)
            ctx.add_theme(Theme(
                slug=slug, version=version, latest_version=None,
                url=f"{ctx.url}/wp-content/themes/{slug}/",
                outdated=False, active=is_active
            ))
            if version:
                ctx.add_finding(Finding(
                    id="PC-THM-001", remediation_id="REM-THM-001",
                    title=f"Theme version disclosed: {slug} v{version}",
                    severity=Severity.INFO,
                    description=f"Theme '{slug}' version {version} found via style.css.",
                    evidence={"slug": slug, "version": version},
                    remediation="Keep themes updated. Remove unused themes.",
                    references=[], cvss_score=None, module=self.name
                ))
