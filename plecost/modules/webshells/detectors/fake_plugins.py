from __future__ import annotations
import base64
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.webshells.base import BaseDetector


class FakePluginRestDetector(BaseDetector):
    """
    Uses the WordPress REST API (/wp-json/wp/v2/plugins) with Basic Auth to list all
    installed plugins, then flags any plugin that is not in the plugins detected by
    the passive/brute-force plugins module (ctx.plugins).

    Requires WordPress admin credentials.
    """

    name = "fake_plugins"
    requires_auth = True

    async def detect(
        self, ctx: ScanContext, http: PlecostHTTPClient
    ) -> list[Finding]:
        if not ctx.opts.credentials:
            return []

        username, password = ctx.opts.credentials
        auth_header = base64.b64encode(f"{username}:{password}".encode()).decode()

        try:
            r = await http.get(
                f"{ctx.url}/wp-json/wp/v2/plugins",
                headers={"Authorization": f"Basic {auth_header}"},
            )
            if r.status_code not in (200,):
                return []
            plugins_data: list[dict] = r.json()
        except Exception:
            return []

        # Build set of known-legitimate slugs from passive/brute-force scan
        known_slugs = {p.slug.lower() for p in ctx.plugins}

        findings: list[Finding] = []
        for plugin in plugins_data:
            plugin_file: str = plugin.get("plugin", "")
            # plugin_file is "slug/main-file.php" — extract slug
            slug = plugin_file.split("/")[0].lower() if "/" in plugin_file else plugin_file.lower()
            if not slug:
                continue
            if slug in known_slugs:
                continue  # legitimate plugin, already detected by plugins module

            findings.append(Finding(
                id="PC-WSH-300",
                remediation_id="REM-WSH-300",
                title=f"Unrecognized plugin found via REST API: {slug}",
                severity=Severity.HIGH,
                description=(
                    f"The WordPress REST API reports a plugin with slug `{slug}` "
                    f"(file: `{plugin_file}`) is installed and active. "
                    "This plugin was not detected during passive scanning, which can indicate "
                    "a fake or hidden plugin used as a backdoor."
                ),
                evidence={
                    "slug": slug,
                    "plugin_file": plugin_file,
                    "plugin_name": plugin.get("name", ""),
                },
                remediation=(
                    "Verify whether this plugin is intentionally installed. "
                    "If unknown, deactivate and delete it immediately. "
                    "Inspect its source code for malicious content."
                ),
                references=[
                    "https://blog.sucuri.net/2020/01/webshell-in-fake-plugin-blnmrpb-directory.html",
                ],
                cvss_score=7.5,
                module="webshells",
            ))

        return findings
