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
# Patterns that only appear in a real WordPress theme style.css
_STYLE_VALID_RE = re.compile(r'(Theme\s+Name:|Version:|Author:|Text\s+Domain:)', re.I)


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
                surrounding = r.text[max(0, m.start()-5):m.end()+200]
                ver_m = _QVER_RE.search(surrounding)
                ver = ver_m.group(1) if ver_m else None
                # Keep the best version seen: don't overwrite a known version with None
                if slug not in found or (ver and found[slug] is None):
                    found[slug] = ver
                if active_theme is None:
                    active_theme = slug
        except Exception:
            pass

        # Active: brute-force wordlist via style.css
        # Probe a nonexistent theme first to establish the 404 baseline.
        # Some servers return non-404 for nonexistent paths (WAF blanket block or WordPress
        # routing through index.php). In those cases we validate response content instead.
        baseline_is_404 = True
        baseline_is_soft_200 = False  # server returns 200 for non-existent paths
        try:
            probe = await http.get(f"{ctx.url}/wp-content/themes/__plecost_probe__/style.css")
            baseline_is_404 = probe.status_code == 404
            if not baseline_is_404 and probe.status_code == 200:
                # Server returns 200 for everything (e.g. WordPress routing to index.php).
                # A real style.css must pass content validation; fake ones won't.
                baseline_is_soft_200 = True
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
                    if baseline_is_soft_200:
                        # Server returns 200 for everything; only trust a real style.css
                        exists = r.status_code == 200 and bool(_STYLE_VALID_RE.search(r.text[:2000]))
                    else:
                        exists = r.status_code == 200 or (baseline_is_404 and r.status_code == 403)
                    if exists:
                        ver = None
                        if r.status_code == 200:
                            if m := _CSS_VER_RE.search(r.text):
                                ver = m.group(1)
                        if slug not in found:
                            found[slug] = ver
                        elif ver:
                            # style.css "Version:" is authoritative; always prefer it
                            # over the ?ver= picked up from passive HTML scanning
                            found[slug] = ver
                except Exception:
                    pass
                finally:
                    checked += 1
                    ctx.report_progress("themes", checked, total)

        await asyncio.gather(*[check_theme(s) for s in self._wordlist])

        # Active check for themes found passively but not in the wordlist:
        # they have no version yet, so try to fetch their style.css directly.
        wordlist_set = set(self._wordlist)
        passive_only = [slug for slug, ver in found.items() if ver is None and slug not in wordlist_set]
        if passive_only:
            sem2 = asyncio.Semaphore(ctx.opts.concurrency)

            async def fetch_passive_version(slug: str) -> None:
                async with sem2:
                    url = f"{ctx.url}/wp-content/themes/{slug}/style.css"
                    try:
                        r = await http.get(url)
                        if r.status_code == 200:
                            if baseline_is_soft_200 and not _STYLE_VALID_RE.search(r.text[:2000]):
                                # Fake 200 — theme doesn't really exist; remove it
                                found.pop(slug, None)
                                return
                            if m := _CSS_VER_RE.search(r.text):
                                found[slug] = m.group(1)
                    except Exception:
                        pass

            await asyncio.gather(*[fetch_passive_version(s) for s in passive_only])

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
