"""
WordPress Hardening module — AC-10

Checks if the detected WordPress version is older than the known latest version.

KNOWN_LATEST_VERSION: "7.0" (hardcoded; last verified: 2026-05-24)
Overridable via: ctx.opts.module_options.get("hardening", {}).get("latest_version")

Finding:
  - PC-WPH-001 (MEDIUM): WordPress version is outdated
"""
from __future__ import annotations

from packaging.version import InvalidVersion, Version

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.i18n import t
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule

KNOWN_LATEST_VERSION = "7.0"  # Last verified: 2026-05-24


class WPHardeningModule(ScanModule):
    name = "wp_hardening"
    depends_on = ["fingerprint"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress and not ctx.opts.force:
            return

        if not ctx.wordpress_version:
            return

        # Allow override via module_options
        latest_str = (
            ctx.opts.module_options.get("hardening", {}).get("latest_version")
            or KNOWN_LATEST_VERSION
        )

        try:
            detected = Version(ctx.wordpress_version)
            latest = Version(latest_str)
        except InvalidVersion:
            return

        if detected < latest:
            ctx.add_finding(Finding(
                id="PC-WPH-001", remediation_id="REM-WPH-001",
                title=t("findings.pc_wph_001.title"),
                severity=Severity.MEDIUM,
                description=t("findings.pc_wph_001.description"),
                evidence={
                    "detected_version": ctx.wordpress_version,
                    "latest_known_version": latest_str,
                },
                remediation=t("findings.pc_wph_001.remediation"),
                references=[
                    "https://wordpress.org/news/category/releases/",
                    "https://wordpress.org/support/article/updating-wordpress/",
                ],
                cvss_score=5.3, module=self.name
            ))
