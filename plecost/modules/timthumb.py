"""
TimThumb detector — AC-7

Checks for accessible timthumb.php files in common locations:
  - /timthumb.php
  - /wp-content/timthumb.php
  - /wp-content/plugins/{slug}/timthumb.php (per detected plugin)

Findings:
  - PC-TTH-001 (HIGH): timthumb.php is accessible
  - PC-TTH-002 (CRITICAL): timthumb version < 2.8.14 (last secure release)
  - PC-TTH-003 (HIGH): timthumb.php found inside a plugin directory
"""
from __future__ import annotations

import asyncio
import re

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule
from plecost.i18n import t

# Signature: response body must contain one of these to confirm it is timthumb
_SIGNATURE_RE = re.compile(r'TimThumb|Not a valid src', re.I)

# Extract version from response body
_VERSION_RE = re.compile(r'TimThumb\s+v?([\d.]+)', re.I)

# Last patched version
_LAST_SECURE_VERSION = "2.8.14"


def _version_lt(ver: str, reference: str) -> bool:
    """Return True if ver < reference using simple tuple comparison."""
    try:
        v1 = tuple(int(x) for x in ver.split("."))
        v2 = tuple(int(x) for x in reference.split("."))
        # Pad to same length
        length = max(len(v1), len(v2))
        v1 = v1 + (0,) * (length - len(v1))
        v2 = v2 + (0,) * (length - len(v2))
        return v1 < v2
    except ValueError:
        return False


class TimThumbModule(ScanModule):
    name = "timthumb"
    depends_on = ["fingerprint", "plugins"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress and not ctx.opts.force:
            return

        # Build list of (path, is_plugin_dir) tuples to check
        paths: list[tuple[str, bool]] = [
            ("/timthumb.php", False),
            ("/wp-content/timthumb.php", False),
        ]
        for plugin in ctx.plugins:
            plugin_path = f"/wp-content/plugins/{plugin.slug}/timthumb.php"
            paths.append((plugin_path, True))

        await asyncio.gather(*[
            self._check_path(ctx, http, path, is_plugin_dir)
            for path, is_plugin_dir in paths
        ], return_exceptions=True)

    async def _check_path(
        self,
        ctx: ScanContext,
        http: PlecostHTTPClient,
        path: str,
        is_plugin_dir: bool,
    ) -> None:
        url = ctx.url + path
        try:
            r = await http.get(url)
            if r.status_code != 200:
                return

            body = r.text[:4096]

            # Must match timthumb signature
            if not _SIGNATURE_RE.search(body):
                return

            # PC-TTH-001: accessible
            ctx.add_finding(Finding(
                id="PC-TTH-001", remediation_id="REM-TTH-001",
                title=t("findings.pc_tth_001.title"),
                severity=Severity.HIGH,
                description=t("findings.pc_tth_001.description"),
                evidence={"url": url, "status_code": r.status_code},
                remediation=t("findings.pc_tth_001.remediation"),
                references=[
                    "https://blog.sucuri.net/2014/06/timthumb-zero-day-exploit-found-vulnerability-in-webshot.html"
                ],
                cvss_score=7.5, module=self.name
            ))

            # PC-TTH-002: vulnerable version
            ver_match = _VERSION_RE.search(body)
            if ver_match:
                version = ver_match.group(1)
                if _version_lt(version, _LAST_SECURE_VERSION):
                    ctx.add_finding(Finding(
                        id="PC-TTH-002", remediation_id="REM-TTH-002",
                        title=t("findings.pc_tth_002.title"),
                        severity=Severity.CRITICAL,
                        description=t("findings.pc_tth_002.description"),
                        evidence={
                            "url": url,
                            "detected_version": version,
                            "last_secure_version": _LAST_SECURE_VERSION,
                        },
                        remediation=t("findings.pc_tth_002.remediation"),
                        references=[
                            "https://nvd.nist.gov/vuln/search/results?query=timthumb"
                        ],
                        cvss_score=9.8, module=self.name
                    ))

            # PC-TTH-003: found inside plugin directory
            if is_plugin_dir:
                ctx.add_finding(Finding(
                    id="PC-TTH-003", remediation_id="REM-TTH-003",
                    title=t("findings.pc_tth_003.title"),
                    severity=Severity.HIGH,
                    description=t("findings.pc_tth_003.description"),
                    evidence={"url": url, "plugin_path": path},
                    remediation=t("findings.pc_tth_003.remediation"),
                    references=[
                        "https://blog.sucuri.net/2014/06/timthumb-zero-day-exploit-found-vulnerability-in-webshot.html"
                    ],
                    cvss_score=7.5, module=self.name
                ))
        except Exception:
            pass
