from __future__ import annotations
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule
from plecost.database.store import CVEStore, VulnerabilityRecord

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class CVEsModule(ScanModule):
    name = "cves"
    depends_on = ["plugins", "themes"]

    def __init__(self, store: CVEStore) -> None:
        self._store = store

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient | None) -> None:
        if not ctx.is_wordpress:
            return
        # Check core
        if ctx.wordpress_version:
            for vuln in self._store.find("core", "wordpress", ctx.wordpress_version):
                ctx.add_finding(self._make_finding(vuln))
        # Check plugins
        for plugin in ctx.plugins:
            if plugin.version:
                for vuln in self._store.find("plugin", plugin.slug, plugin.version):
                    ctx.add_finding(self._make_finding(vuln))
        # Check themes
        for theme in ctx.themes:
            if theme.version:
                for vuln in self._store.find("theme", theme.slug, theme.version):
                    ctx.add_finding(self._make_finding(vuln))

    def _make_finding(self, vuln: VulnerabilityRecord) -> Finding:
        sev = _SEVERITY_MAP.get(vuln.severity, Severity.MEDIUM)
        exploit_note = " **Public exploit available.**" if vuln.has_exploit else ""
        return Finding(
            id=f"PC-CVE-{vuln.cve_id}",
            remediation_id=f"REM-CVE-{vuln.cve_id}",
            title=f"{vuln.title} ({vuln.cve_id})",
            severity=sev,
            description=f"{vuln.description}.{exploit_note} Affects versions {vuln.version_from}–{vuln.version_to}.",
            evidence={"cve_id": vuln.cve_id, "software": vuln.software_slug, "installed_version": vuln.version_from},
            remediation=vuln.remediation,
            references=vuln.references,
            cvss_score=vuln.cvss_score,
            module=self.name
        )
