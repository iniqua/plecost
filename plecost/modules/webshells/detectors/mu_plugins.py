from __future__ import annotations
import asyncio
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.webshells.base import BaseDetector
from plecost.modules.webshells.wordlists import MU_PLUGINS_NAMES

_MU_PLUGINS_BASE = "/wp-content/mu-plugins/"
_BASELINE_NAME = "__plecost_probe_xyz__.php"


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

        # Baseline probe: detect soft-200 environments where the server returns
        # HTTP 200 for any path (including non-existent files).
        baseline_body: str | None = None
        try:
            probe = await http.get(ctx.url + _MU_PLUGINS_BASE + _BASELINE_NAME)
            if probe.status_code == 200:
                baseline_body = probe.text
        except Exception:
            pass

        async def _probe(name: str) -> None:
            async with sem:
                try:
                    url = ctx.url + _MU_PLUGINS_BASE + name
                    r = await http.get(url)
                    if r.status_code != 200:
                        return
                    # In a soft-200 environment, skip if the response body is
                    # identical to the baseline (false positive).
                    if baseline_body is not None and r.text == baseline_body:
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
