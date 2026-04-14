from __future__ import annotations
import asyncio
import re
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Plugin
from plecost.modules.base import ScanModule

_PLUGIN_PATH_RE = re.compile(r'/wp-content/plugins/([a-z0-9_-]+)/', re.I)
_VER_RE = re.compile(r'[Ss]table\s+tag:\s*([\d.]+)')
_QVER_RE = re.compile(r'\?ver=([\d.]+)')


class PluginsModule(ScanModule):
    name = "plugins"
    depends_on = ["fingerprint"]

    def __init__(self, wordlist: list[str] | None = None) -> None:
        self._wordlist = wordlist or []

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress and not ctx.opts.force:
            return

        # Passive: scan homepage for plugin paths
        found: dict[str, str | None] = {}  # slug -> version
        try:
            r = await http.get(ctx.url + "/")
            for m in _PLUGIN_PATH_RE.finditer(r.text):
                slug = m.group(1)
                # Try to get version from ?ver= near this path
                surrounding = r.text[max(0, m.start()-5):m.end()+200]
                ver_m = _QVER_RE.search(surrounding)
                ver = ver_m.group(1) if ver_m else None
                # Keep the best version seen: don't overwrite a known version with None
                if slug not in found or (ver and found[slug] is None):
                    found[slug] = ver
        except Exception:
            pass

        # Active: brute-force wordlist
        # First probe a nonexistent slug to establish the 404 baseline.
        # If the server returns non-404 for nonexistent paths (WAF blanket block),
        # then 403 is not a reliable "plugin exists" signal — only accept 200.
        baseline_is_404 = True
        try:
            probe = await http.get(f"{ctx.url}/wp-content/plugins/__plecost_probe__/readme.txt")
            baseline_is_404 = probe.status_code == 404
        except Exception:
            pass

        sem = asyncio.Semaphore(ctx.opts.concurrency)
        total = len(self._wordlist)
        checked = 0

        async def check_plugin(slug: str) -> None:
            nonlocal checked
            async with sem:
                url = f"{ctx.url}/wp-content/plugins/{slug}/readme.txt"
                try:
                    r = await http.get(url)
                    exists = r.status_code == 200 or (baseline_is_404 and r.status_code == 403)
                    if exists:
                        ver = None
                        if r.status_code == 200:
                            if m := _VER_RE.search(r.text):
                                ver = m.group(1)
                        if slug not in found:
                            found[slug] = ver
                        elif ver and found[slug] is None:
                            found[slug] = ver
                except Exception:
                    pass
                finally:
                    checked += 1
                    ctx.report_progress("plugins", checked, total)

        await asyncio.gather(*[check_plugin(s) for s in self._wordlist])

        # Active check for plugins found passively but not in the wordlist:
        # they have no version yet, so try to fetch their readme.txt directly.
        wordlist_set = set(self._wordlist)
        passive_only = [slug for slug, ver in found.items() if ver is None and slug not in wordlist_set]
        if passive_only:
            sem2 = asyncio.Semaphore(ctx.opts.concurrency)

            async def fetch_passive_version(slug: str) -> None:
                async with sem2:
                    url = f"{ctx.url}/wp-content/plugins/{slug}/readme.txt"
                    try:
                        r = await http.get(url)
                        if r.status_code == 200:
                            if m := _VER_RE.search(r.text):
                                found[slug] = m.group(1)
                    except Exception:
                        pass

            await asyncio.gather(*[fetch_passive_version(s) for s in passive_only])

        for slug, version in found.items():
            ctx.add_plugin(Plugin(
                slug=slug, version=version, latest_version=None,
                url=f"{ctx.url}/wp-content/plugins/{slug}/",
                outdated=False, abandoned=False
            ))
