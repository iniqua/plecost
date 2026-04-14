from __future__ import annotations

import asyncio
import re

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity, WPECommerceInfo
from plecost.modules.base import ScanModule
from plecost.i18n import t

_VERSION_RE = re.compile(r'Stable tag:\s*([\d.]+)', re.I)
_DIR_LISTING_RE = re.compile(r'<title>\s*index of', re.I)
_SQL_ERROR_RE = re.compile(
    r'(you have an error in your sql syntax|mysql_fetch|wpdb error|warning.*mysql)',
    re.I,
)
_INJECT_RE = re.compile(
    r'(__wakeup|unserialize\(\)|class.*evil|fatal error.*unserialized)',
    re.I,
)


class WPECommerceModule(ScanModule):
    name = "wp_ecommerce"
    depends_on = ["fingerprint"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress and not ctx.opts.force:
            return

        wpec_opts = ctx.opts.module_options.get("wpec", {})
        mode = wpec_opts.get("mode", "passive")
        checks_run: list[str] = []

        # Phase 1: Fingerprint (parallel internally)
        detected, version, active_gateways = await self._fingerprint(ctx, http, checks_run)
        if not detected:
            return

        ctx.wp_ecommerce = WPECommerceInfo(
            detected=True,
            version=version,
            active_gateways=active_gateways,
            checks_run=checks_run,
        )

        # Phase 2: Abandoned plugin finding (always when detected)
        ctx.add_finding(Finding(
            id="PC-WPEC-003",
            remediation_id="REM-WPEC-003",
            title=t("findings.pc_wpec_003.title"),
            severity=Severity.HIGH,
            description=t("findings.pc_wpec_003.description"),
            evidence={"version": version, "last_update": "2020", "last_version": "3.15.1"},
            remediation=t("findings.pc_wpec_003.remediation"),
            references=[
                "https://wordpress.org/plugins/wp-e-commerce/",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-1514",
            ],
            cvss_score=8.1,
            module=self.name,
        ))

        # Phase 3: Passive checks (parallel)
        await asyncio.gather(
            self._check_sensitive_files(ctx, http, checks_run),
            self._check_directories(ctx, http, checks_run, active_gateways),
        )

        # Phase 4: Semi-active checks (only if mode=semi-active)
        if mode == "semi-active":
            await asyncio.gather(
                self._check_cve_2024_1514(ctx, http, checks_run, active_gateways),
                self._check_cve_2026_1235(ctx, http, checks_run),
            )

        # Phase 5: Summary
        self._emit_summary(ctx, mode)

    # ── Fingerprint ───────────────────────────────────────────────────────────

    async def _fingerprint(
        self,
        ctx: ScanContext,
        http: PlecostHTTPClient,
        checks_run: list[str],
    ) -> tuple[bool, str | None, list[str]]:
        detected_flags: list[bool] = [False, False]
        version_holder: list[str | None] = [None]
        active_gateways: list[str] = []

        async def _probe_readme() -> None:
            url = ctx.url + "/wp-content/plugins/wp-e-commerce/readme.txt"
            try:
                r = await http.get(url)
                if r.status_code == 200:
                    detected_flags[0] = True
                    checks_run.append("readme")
                    m = _VERSION_RE.search(r.text)
                    if m:
                        version_holder[0] = m.group(1)
                    ctx.add_finding(Finding(
                        id="PC-WPEC-001",
                        remediation_id="REM-WPEC-001",
                        title=t("findings.pc_wpec_001.title"),
                        severity=Severity.INFO,
                        description=t("findings.pc_wpec_001.description"),
                        evidence={"url": url},
                        remediation=t("findings.pc_wpec_001.remediation"),
                        references=["https://wordpress.org/plugins/wp-e-commerce/"],
                        cvss_score=None,
                        module=self.name,
                    ))
                    if version_holder[0]:
                        ctx.add_finding(Finding(
                            id="PC-WPEC-002",
                            remediation_id="REM-WPEC-002",
                            title=t("findings.pc_wpec_002.title"),
                            severity=Severity.LOW,
                            description=t("findings.pc_wpec_002.description"),
                            evidence={"url": url, "version": version_holder[0]},
                            remediation=t("findings.pc_wpec_002.remediation"),
                            references=[],
                            cvss_score=5.3,
                            module=self.name,
                        ))
            except Exception:
                pass

        async def _probe_main_php() -> None:
            url = ctx.url + "/wp-content/plugins/wp-e-commerce/wp-shopping-cart.php"
            try:
                r = await http.get(url)
                if r.status_code == 200:
                    detected_flags[1] = True
            except Exception:
                pass

        async def _probe_wp_json() -> None:
            url = ctx.url + "/wp-json/"
            try:
                r = await http.get(url)
                if r.status_code == 200 and "wpsc_db_version" in r.text[:4096]:
                    detected_flags[1] = True
            except Exception:
                pass

        async def _probe_homepage() -> None:
            url = ctx.url + "/"
            try:
                r = await http.get(url)
                if r.status_code == 200 and "wp-e-commerce" in r.text[:4096]:
                    detected_flags[1] = True
            except Exception:
                pass

        async def _probe_chronopay() -> None:
            url = ctx.url + "/wp-content/plugins/wp-e-commerce/wpsc-merchants/chronopay.php"
            try:
                r = await http.get(url)
                if r.status_code == 200:
                    if "chronopay" not in active_gateways:
                        active_gateways.append("chronopay")
                    ctx.add_finding(Finding(
                        id="PC-WPEC-004",
                        remediation_id="REM-WPEC-004",
                        title=t("findings.pc_wpec_004.title"),
                        severity=Severity.INFO,
                        description=t("findings.pc_wpec_004.description"),
                        evidence={"url": url},
                        remediation=t("findings.pc_wpec_004.remediation"),
                        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-1514"],
                        cvss_score=None,
                        module=self.name,
                    ))
            except Exception:
                pass

        await asyncio.gather(
            _probe_readme(),
            _probe_main_php(),
            _probe_wp_json(),
            _probe_homepage(),
            _probe_chronopay(),
        )

        detected = detected_flags[0] or detected_flags[1]
        return detected, version_holder[0], active_gateways

    # ── Sensitive file checks ─────────────────────────────────────────────────

    async def _check_sensitive_files(
        self,
        ctx: ScanContext,
        http: PlecostHTTPClient,
        checks_run: list[str],
    ) -> None:
        async def _probe_db_backup() -> None:
            url = ctx.url + "/wp-content/plugins/wp-e-commerce/wpsc-admin/db-backup.php"
            try:
                r = await http.get(url)
                if r.status_code == 200:
                    checks_run.append("sensitive_files")
                    ctx.add_finding(Finding(
                        id="PC-WPEC-008",
                        remediation_id="REM-WPEC-008",
                        title=t("findings.pc_wpec_008.title"),
                        severity=Severity.HIGH,
                        description=t("findings.pc_wpec_008.description"),
                        evidence={"url": url},
                        remediation=t("findings.pc_wpec_008.remediation"),
                        references=[],
                        cvss_score=7.5,
                        module=self.name,
                    ))
            except Exception:
                pass

        async def _probe_display_log() -> None:
            url = ctx.url + "/wp-content/plugins/wp-e-commerce/wpsc-admin/display-log.php"
            try:
                r = await http.get(url)
                if r.status_code == 200:
                    ctx.add_finding(Finding(
                        id="PC-WPEC-009",
                        remediation_id="REM-WPEC-009",
                        title=t("findings.pc_wpec_009.title"),
                        severity=Severity.MEDIUM,
                        description=t("findings.pc_wpec_009.description"),
                        evidence={"url": url},
                        remediation=t("findings.pc_wpec_009.remediation"),
                        references=[],
                        cvss_score=5.3,
                        module=self.name,
                    ))
            except Exception:
                pass

        await asyncio.gather(
            _probe_db_backup(),
            _probe_display_log(),
        )

    # ── Directory checks ──────────────────────────────────────────────────────

    async def _check_directories(
        self,
        ctx: ScanContext,
        http: PlecostHTTPClient,
        checks_run: list[str],
        active_gateways: list[str],
    ) -> None:
        async def _probe_plugin_dir() -> None:
            url = ctx.url + "/wp-content/plugins/wp-e-commerce/"
            try:
                r = await http.get(url)
                if r.status_code == 200 and _DIR_LISTING_RE.search(r.text[:4096]):
                    ctx.add_finding(Finding(
                        id="PC-WPEC-005",
                        remediation_id="REM-WPEC-005",
                        title=t("findings.pc_wpec_005.title"),
                        severity=Severity.HIGH,
                        description=t("findings.pc_wpec_005.description"),
                        evidence={"url": url},
                        remediation=t("findings.pc_wpec_005.remediation"),
                        references=[],
                        cvss_score=7.5,
                        module=self.name,
                    ))
            except Exception:
                pass

        async def _probe_uploads_wpsc() -> None:
            url = ctx.url + "/wp-content/uploads/wpsc/"
            try:
                r = await http.get(url)
                if r.status_code == 200:
                    ctx.add_finding(Finding(
                        id="PC-WPEC-006",
                        remediation_id="REM-WPEC-006",
                        title=t("findings.pc_wpec_006.title"),
                        severity=Severity.HIGH,
                        description=t("findings.pc_wpec_006.description"),
                        evidence={"url": url},
                        remediation=t("findings.pc_wpec_006.remediation"),
                        references=[],
                        cvss_score=7.5,
                        module=self.name,
                    ))
            except Exception:
                pass

        async def _probe_digital_downloads() -> None:
            url = ctx.url + "/wp-content/uploads/wpsc/digital/"
            try:
                r = await http.get(url)
                if r.status_code == 200:
                    ctx.add_finding(Finding(
                        id="PC-WPEC-007",
                        remediation_id="REM-WPEC-007",
                        title=t("findings.pc_wpec_007.title"),
                        severity=Severity.CRITICAL,
                        description=t("findings.pc_wpec_007.description"),
                        evidence={"url": url},
                        remediation=t("findings.pc_wpec_007.remediation"),
                        references=[],
                        cvss_score=9.1,
                        module=self.name,
                    ))
            except Exception:
                pass

        async def _probe_chronopay_endpoint() -> None:
            if "chronopay" not in active_gateways:
                return
            url = ctx.url + "/?chronopay_return=1"
            try:
                r = await http.get(url)
                if r.status_code == 200 and not r.is_redirect:
                    checks_run.append("chronopay_endpoint")
                    ctx.add_finding(Finding(
                        id="PC-WPEC-010",
                        remediation_id="REM-WPEC-010",
                        title=t("findings.pc_wpec_010.title"),
                        severity=Severity.MEDIUM,
                        description=t("findings.pc_wpec_010.description"),
                        evidence={"url": url},
                        remediation=t("findings.pc_wpec_010.remediation"),
                        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-1514"],
                        cvss_score=5.3,
                        module=self.name,
                    ))
            except Exception:
                pass

        checks_run.append("directories")

        await asyncio.gather(
            _probe_plugin_dir(),
            _probe_uploads_wpsc(),
            _probe_digital_downloads(),
            _probe_chronopay_endpoint(),
        )

    # ── Semi-active CVE checks ────────────────────────────────────────────────

    async def _check_cve_2024_1514(
        self,
        ctx: ScanContext,
        http: PlecostHTTPClient,
        checks_run: list[str],
        active_gateways: list[str],
    ) -> None:
        """CVE-2024-1514: WP eCommerce ChronoPay SQL Injection (CVSS 9.8).
        Only runs in semi-active mode when ChronoPay gateway is active.
        Boolean detection only — never time-based to avoid blocking the event loop.
        """
        if "chronopay" not in active_gateways:
            return
        url = ctx.url + "/?chronopay=process"
        try:
            r = await http.post(url, data={"order_id": "1'", "merchant_id": "test"})
            checks_run.append("cve_2024_1514")
            if _SQL_ERROR_RE.search(r.text[:4096]):
                ctx.add_finding(Finding(
                    id="PC-WPEC-020",
                    remediation_id="REM-WPEC-020",
                    title=t("findings.pc_wpec_020.title"),
                    severity=Severity.CRITICAL,
                    description=t("findings.pc_wpec_020.description"),
                    evidence={"url": url, "pattern": "SQL error detected in response"},
                    remediation=t("findings.pc_wpec_020.remediation"),
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2024-1514"],
                    cvss_score=9.8,
                    module=self.name,
                ))
        except Exception:
            pass

    async def _check_cve_2026_1235(
        self,
        ctx: ScanContext,
        http: PlecostHTTPClient,
        checks_run: list[str],
    ) -> None:
        """CVE-2026-1235: WP eCommerce PHP Object Injection (CVSS 8.1).
        Only runs in semi-active mode. Sends a serialized PHP object payload and checks
        whether the server triggers unserialization errors.
        """
        url = ctx.url + "/wp-admin/admin-ajax.php?action=wpsc_add_to_cart"
        payload = b"product_id=O%3A4%3A%22Evil%22%3A0%3A%7B%7D"
        try:
            r = await http.post(
                url,
                content=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            checks_run.append("cve_2026_1235")
            if r.status_code in (200, 500) and _INJECT_RE.search(r.text[:4096]):
                ctx.add_finding(Finding(
                    id="PC-WPEC-021",
                    remediation_id="REM-WPEC-021",
                    title=t("findings.pc_wpec_021.title"),
                    severity=Severity.HIGH,
                    description=t("findings.pc_wpec_021.description"),
                    evidence={"url": url, "pattern": "Unserialization pattern detected"},
                    remediation=t("findings.pc_wpec_021.remediation"),
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2026-1235"],
                    cvss_score=8.1,
                    module=self.name,
                ))
        except Exception:
            pass

    # ── Summary finding ───────────────────────────────────────────────────────

    def _emit_summary(self, ctx: ScanContext, mode: str) -> None:
        if ctx.wp_ecommerce is None:
            return
        wpe = ctx.wp_ecommerce
        ctx.add_finding(Finding(
            id="PC-WPEC-000",
            remediation_id="REM-WPEC-000",
            title=t("findings.pc_wpec_000.title"),
            severity=Severity.INFO,
            description=t("findings.pc_wpec_000.description"),
            evidence={
                "version": wpe.version,
                "active_gateways": wpe.active_gateways,
                "checks_run": wpe.checks_run,
                "mode": mode,
            },
            remediation=t("findings.pc_wpec_000.remediation"),
            references=[],
            cvss_score=None,
            module=self.name,
        ))
