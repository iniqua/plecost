from __future__ import annotations
import time
import uuid
from collections.abc import Callable
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
    def __init__(
        self,
        opts: ScanOptions,
        on_module_start: Callable[[str], None] | None = None,
        on_module_done: Callable[[str], None] | None = None,
        on_finding: Callable[[Finding], None] | None = None,
        on_module_progress: Callable[[str, int, int], None] | None = None,
    ) -> None:
        self._opts = opts
        self._on_module_start = on_module_start
        self._on_module_done = on_module_done
        self._on_finding = on_finding
        self._on_progress = on_module_progress

    async def run_many(self, urls: list[str]) -> list[ScanResult]:
        """Scan multiple targets sequentially and return a list of ScanResults."""
        results: list[ScanResult] = []
        for target_url in urls:
            opts = ScanOptions(
                url=target_url,
                concurrency=self._opts.concurrency,
                timeout=self._opts.timeout,
                proxy=self._opts.proxy,
                modules=self._opts.modules,
                skip_modules=self._opts.skip_modules,
                credentials=self._opts.credentials,
                stealth=self._opts.stealth,
                aggressive=self._opts.aggressive,
                user_agent=self._opts.user_agent,
                random_user_agent=self._opts.random_user_agent,
                verify_ssl=self._opts.verify_ssl,
                force=self._opts.force,
                output=self._opts.output,
            )
            scanner = Scanner(opts)
            result = await scanner.run()
            results.append(result)
        return results

    async def run(self) -> ScanResult:
        start = time.monotonic()
        ctx = ScanContext(self._opts, on_finding=self._on_finding, on_progress=self._on_progress)

        # Initialize CVE store and wordlists asynchronously
        cve_mod: CVEsModule | None = None
        plugin_wl: list[str] = []
        theme_wl: list[str] = []
        store = None
        try:
            from plecost.database.store import CVEStore
            from pathlib import Path
            db_url = self._opts.db_url or f"sqlite+aiosqlite:///{Path.home() / '.plecost' / 'db' / 'plecost.db'}"
            store = CVEStore.from_url(db_url)
            cve_mod = CVEsModule(store)
            plugin_wl = await store.get_plugins_wordlist()
            theme_wl = await store.get_themes_wordlist()
        except Exception as e:
            import sys
            print(
                f"[plecost] Warning: CVE database unavailable ({e}). "
                "Run 'plecost update-db' to download it.",
                file=sys.stderr,
            )

        modules: list[ScanModule] = [
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

        try:
            scheduler = Scheduler(modules, on_module_start=self._on_module_start, on_module_done=self._on_module_done)
            async with PlecostHTTPClient(self._opts) as http:
                blocked = await self._check_access(ctx, http)
                if not blocked:
                    await scheduler.run(ctx, http)
        finally:
            if store is not None:
                await store.dispose()
        duration = time.monotonic() - start
        return ScanResult(
            scan_id=str(uuid.uuid4()), url=self._opts.url, blocked=ctx.blocked,
            timestamp=datetime.now(), duration_seconds=round(duration, 2),
            is_wordpress=ctx.is_wordpress, wordpress_version=ctx.wordpress_version,
            plugins=ctx.plugins, themes=ctx.themes, users=ctx.users,
            waf_detected=ctx.waf_detected, findings=ctx.findings,
            summary=_build_summary(ctx.findings)
        )

    async def _check_access(self, ctx: ScanContext, http: PlecostHTTPClient) -> bool:
        """Pre-flight: probe the target URL. Returns True (blocked) if access is denied."""
        try:
            r = await http.get(ctx.url + "/")
            if r.status_code == 403:
                ctx.blocked = True
                ctx.add_finding(Finding(
                    id="PC-PRE-001", remediation_id="REM-PRE-001",
                    title="Target host blocked this scanner (HTTP 403)",
                    severity=Severity.INFO,
                    description=(
                        f"The target {ctx.url} returned HTTP 403 Forbidden on the initial "
                        "probe request. The server is actively blocking this scanner's IP or "
                        "User-Agent. No further analysis was performed."
                    ),
                    evidence={"url": ctx.url + "/", "status_code": "403"},
                    remediation=(
                        "Try scanning from a different IP, use --proxy to route through a "
                        "different exit node, or use --user-agent to change the User-Agent string."
                    ),
                    references=[],
                    cvss_score=None,
                    module="pre-flight",
                ))
                return True
        except Exception:
            pass
        return False
