from __future__ import annotations
import time
import uuid
from datetime import datetime
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.engine.scheduler import Scheduler
from plecost.models import ScanOptions, ScanResult, ScanSummary, Severity
from plecost.modules.fingerprint import FingerprintModule
from plecost.modules.waf import WAFModule
from plecost.modules.plugins import PluginsModule
from plecost.modules.themes import ThemesModule
from plecost.modules.users import UsersModule
from plecost.modules.xmlrpc import XMLRPCModule
from plecost.modules.rest_api import RESTAPIModule
from plecost.modules.misconfigs import MisconfigsModule
from plecost.modules.directory_listing import DirectoryListingModule
from plecost.modules.http_headers import HTTPHeadersModule
from plecost.modules.ssl_tls import SSLTLSModule
from plecost.modules.debug_exposure import DebugExposureModule
from plecost.modules.content_analysis import ContentAnalysisModule
from plecost.modules.auth import AuthModule
from plecost.modules.cves import CVEsModule
from plecost.modules.base import ScanModule
from plecost.models import Finding


def _build_summary(findings: list[Finding]) -> ScanSummary:
    s = ScanSummary()
    for f in findings:
        if f.severity == Severity.CRITICAL:
            s.critical += 1
        elif f.severity == Severity.HIGH:
            s.high += 1
        elif f.severity == Severity.MEDIUM:
            s.medium += 1
        elif f.severity == Severity.LOW:
            s.low += 1
        else:
            s.info += 1
    return s


class Scanner:
    def __init__(self, opts: ScanOptions) -> None:
        self._opts = opts

    def _build_modules(self) -> list[ScanModule]:
        try:
            from plecost.database.store import CVEStore
            from pathlib import Path
            db_path = str(Path.home() / ".plecost" / "db" / "plecost.db")
            store = CVEStore(db_path)
            cve_mod: CVEsModule | None = CVEsModule(store)
            plugin_wl = store.get_plugins_wordlist()
            theme_wl = store.get_themes_wordlist()
        except Exception:
            cve_mod = None
            plugin_wl = []
            theme_wl = []

        modules = [
            FingerprintModule(), WAFModule(),
            PluginsModule(wordlist=plugin_wl),
            ThemesModule(wordlist=theme_wl),
            UsersModule(), XMLRPCModule(), RESTAPIModule(),
            MisconfigsModule(), DirectoryListingModule(),
            HTTPHeadersModule(), SSLTLSModule(),
            DebugExposureModule(), ContentAnalysisModule(), AuthModule(),
        ]
        if cve_mod:
            modules.append(cve_mod)
        return modules

    async def run(self) -> ScanResult:
        start = time.monotonic()
        ctx = ScanContext(self._opts)
        modules = self._build_modules()
        scheduler = Scheduler(modules)
        async with PlecostHTTPClient(self._opts) as http:
            await scheduler.run(ctx, http)
        duration = time.monotonic() - start
        return ScanResult(
            scan_id=str(uuid.uuid4()), url=self._opts.url,
            timestamp=datetime.now(), duration_seconds=round(duration, 2),
            is_wordpress=ctx.is_wordpress, wordpress_version=ctx.wordpress_version,
            plugins=ctx.plugins, themes=ctx.themes, users=ctx.users,
            waf_detected=ctx.waf_detected, findings=ctx.findings,
            summary=_build_summary(ctx.findings)
        )
