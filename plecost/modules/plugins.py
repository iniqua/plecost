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
        if not ctx.is_wordpress:
            return

        # Passive: scan homepage for plugin paths
        found: dict[str, str | None] = {}  # slug -> version
        try:
            r = await http.get(ctx.url + "/")
            for m in _PLUGIN_PATH_RE.finditer(r.text):
                slug = m.group(1)
                # Try to get version from ?ver= near this path
                surrounding = r.text[max(0, m.start()-5):m.end()+100]
                ver_m = _QVER_RE.search(surrounding)
                found[slug] = ver_m.group(1) if ver_m else None
        except Exception:
            pass

        # Active: brute-force wordlist
        sem = asyncio.Semaphore(ctx.opts.concurrency)

        async def check_plugin(slug: str) -> None:
            async with sem:
                url = f"{ctx.url}/wp-content/plugins/{slug}/readme.txt"
                try:
                    r = await http.get(url)
                    if r.status_code in (200, 403):
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

        await asyncio.gather(*[check_plugin(s) for s in self._wordlist])

        for slug, version in found.items():
            ctx.add_plugin(Plugin(
                slug=slug, version=version, latest_version=None,
                url=f"{ctx.url}/wp-content/plugins/{slug}/",
                outdated=False, abandoned=False
            ))
