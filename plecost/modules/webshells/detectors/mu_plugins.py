from __future__ import annotations
import asyncio
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.webshells.base import BaseDetector
from plecost.modules.webshells.wordlists import MU_PLUGINS_NAMES

_MU_PLUGINS_BASE = "/wp-content/mu-plugins/"
_PROBE_A = "/wp-content/mu-plugins/__plecost_probe_a__.php"
_PROBE_B = "/wp-content/mu-plugins/__plecost_probe_b__.php"
_TOLERANCE = 0.05


class MuPluginsDetector(BaseDetector):
    """
    Detects PHP files in wp-content/mu-plugins/ returning HTTP 200.
    Must-Use plugins load automatically and are invisible in the WP admin panel.
    This is a primary vector for persistent WordPress backdoors (Sucuri 2024-2025).
    """

    name = "mu_plugins"
    requires_auth = False

    async def detect(
        self, ctx: ScanContext, http: PlecostHTTPClient
    ) -> list[Finding]:
        findings: list[Finding] = []
        sem = asyncio.Semaphore(ctx.opts.concurrency)

        catch_all_size = await self._detect_catch_all(
            http,
            ctx.url + _PROBE_A,
            ctx.url + _PROBE_B,
            tolerance=_TOLERANCE,
        )

        async def _probe(name: str) -> None:
            async with sem:
                try:
                    url = ctx.url + _MU_PLUGINS_BASE + name
                    r = await http.get(url)
                    if r.status_code != 200:
                        return
                    if catch_all_size is not None:
                        hit_size = len(r.content)
                        max_s = max(hit_size, catch_all_size)
                        if max_s == 0 or abs(hit_size - catch_all_size) / max_s < _TOLERANCE:
                            return
                    findings.append(Finding(
                        id="PC-WSH-150",
                        remediation_id="REM-WSH-150",
                        title="Suspicious PHP file in wp-content/mu-plugins",
                        severity=Severity.CRITICAL,
                        description=(
                            f"A PHP file was found at `{url}`. "
                            "Must-Use plugins load automatically on every WordPress request "
                            "and are hidden from the admin plugin list — making them a preferred "
                            "location for persistent backdoors."
                        ),
                        evidence={"url": url, "status_code": "200"},
                        remediation=(
                            "Review and remove any unexpected files in wp-content/mu-plugins/. "
                            "Legitimate must-use plugins are intentionally installed by developers "
                            "and should be documented."
                        ),
                        references=[
                            "https://blog.sucuri.net/2025/03/hidden-malware-strikes-again-mu-plugins-under-attack.html",
                            "https://www.bleepingcomputer.com/news/security/hackers-abuse-wordpress-mu-plugins-to-hide-malicious-code/",
                        ],
                        cvss_score=9.8,
                        module="webshells",
                    ))
                except Exception:
                    pass

        await asyncio.gather(*[_probe(name) for name in MU_PLUGINS_NAMES])
        return findings
