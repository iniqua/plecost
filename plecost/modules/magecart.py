from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, MagecartInfo, Severity
from plecost.modules.base import ScanModule

if TYPE_CHECKING:
    from plecost.database.store import CVEStore

# Matches <script src="https://EXTERNAL_DOMAIN/...">
_SCRIPT_SRC_RE = re.compile(
    r'<script[^>]+\bsrc=["\']?(https?://[^"\'\s>]+)["\']?',
    re.IGNORECASE,
)

# Severity mapping: (category, is_checkout) -> (finding_id, severity, cvss)
_SEVERITY_MAP: dict[tuple[str, bool], tuple[str, Severity, float | None]] = {
    ("magecart", True):    ("PC-MGC-001", Severity.CRITICAL, 9.8),
    ("dropper", True):     ("PC-MGC-002", Severity.CRITICAL, 9.8),
    ("exfiltrator", True): ("PC-MGC-003", Severity.HIGH,     8.1),
    ("magecart", False):   ("PC-MGC-004", Severity.MEDIUM,   5.3),
    ("dropper", False):    ("PC-MGC-004", Severity.MEDIUM,   5.3),
    ("exfiltrator", False):("PC-MGC-004", Severity.MEDIUM,   5.3),
}

_CHECKOUT_PATHS = {"/checkout", "/cart", "/?pagename=checkout", "/?pagename=cart"}


class MagecartModule(ScanModule):
    """
    Detect Magecart / card-skimming JavaScript on eCommerce checkout pages.

    Runs only when WooCommerce or WP eCommerce is detected. Performs a passive
    GET-only scan of checkout and cart pages, extracting external script sources
    and checking them against the blocklist in the local CVE database.

    No module_options required — always runs in blocklist-only mode.
    """

    name = "magecart"
    depends_on = ["fingerprint", "woocommerce", "wp_ecommerce"]

    def __init__(self, store: CVEStore | None = None) -> None:
        # store is a CVEStore instance or None (when DB is unavailable)
        self._store = store

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not self._should_run(ctx):
            return

        urls = self._get_checkout_urls(ctx)

        pages_scanned: list[str] = []
        scripts_counter: list[int] = [0]
        malicious_domains: list[str] = []

        await asyncio.gather(
            *[
                self._scan_page(ctx, http, url, pages_scanned, scripts_counter, malicious_domains)
                for url in urls
            ]
        )

        ctx.magecart = MagecartInfo(
            detected=len(malicious_domains) > 0,
            pages_scanned=pages_scanned,
            scripts_analyzed=scripts_counter[0],
            malicious_domains=list(dict.fromkeys(malicious_domains)),
        )
        self._emit_summary(ctx, pages_scanned, malicious_domains)

    def _should_run(self, ctx: ScanContext) -> bool:
        return bool(ctx.woocommerce or ctx.wp_ecommerce)

    def _get_checkout_urls(self, ctx: ScanContext) -> list[str]:
        base = ctx.url.rstrip("/")
        urls: list[str] = []
        if ctx.woocommerce:
            urls.extend([base + "/checkout", base + "/cart"])
        if ctx.wp_ecommerce:
            urls.extend([base + "/?pagename=checkout", base + "/?pagename=cart"])
        # Deduplicate preserving order
        return list(dict.fromkeys(urls))

    async def _scan_page(
        self,
        ctx: ScanContext,
        http: PlecostHTTPClient,
        url: str,
        pages_scanned: list[str],
        scripts_counter: list[int],
        malicious_domains: list[str],
    ) -> None:
        try:
            r = await http.get(url)
        except Exception:
            return
        if r.status_code != 200:
            return

        pages_scanned.append(url)
        base_domain = urlparse(ctx.url).netloc

        # Extract all external script src attributes
        external_domains: list[str] = []
        for match in _SCRIPT_SRC_RE.finditer(r.text):
            src = match.group(1)
            parsed = urlparse(src)
            domain = parsed.netloc
            if domain and domain != base_domain:
                external_domains.append(domain)
                scripts_counter[0] += 1

        if not external_domains or self._store is None:
            return

        # DB lookup
        try:
            hits = await self._store.get_magecart_domains(external_domains)
        except Exception:
            return

        is_checkout = (
            "/checkout" in url or "/cart" in url
            or "pagename=checkout" in url or "pagename=cart" in url
        )

        for domain_row in hits:
            category = domain_row.category
            key = (category, is_checkout)
            if key not in _SEVERITY_MAP:
                # Unknown category on non-checkout: treat as medium
                key = ("magecart", False)
            finding_id, severity, cvss = _SEVERITY_MAP[key]

            malicious_domains.append(domain_row.domain)

            title_map = {
                "PC-MGC-001": "Known Magecart domain script on checkout page",
                "PC-MGC-002": "Known dropper domain script on checkout page",
                "PC-MGC-003": "Known exfiltrator domain script on checkout page",
                "PC-MGC-004": "Known Magecart domain script on non-checkout page",
            }
            desc_map = {
                "PC-MGC-001": (
                    f"A script from the known Magecart domain '{domain_row.domain}' "
                    f"(source: {domain_row.source}) was found loading on the checkout page {url}. "
                    "This is a strong indicator of a supply-chain attack targeting payment card data."
                ),
                "PC-MGC-002": (
                    f"A script from the known dropper domain '{domain_row.domain}' "
                    f"(source: {domain_row.source}) was found on the checkout page {url}. "
                    "Dropper scripts typically load secondary card-skimming payloads."
                ),
                "PC-MGC-003": (
                    f"A script from the known exfiltrator domain '{domain_row.domain}' "
                    f"(source: {domain_row.source}) was found on the checkout page {url}. "
                    "Exfiltrator scripts send captured data to attacker-controlled servers."
                ),
                "PC-MGC-004": (
                    f"A script from the known Magecart-related domain '{domain_row.domain}' "
                    f"(source: {domain_row.source}) was found on {url}. "
                    "While on a non-checkout page, this may indicate site compromise."
                ),
            }

            ctx.add_finding(Finding(
                id=finding_id,
                remediation_id=finding_id.replace("PC-", "REM-"),
                title=title_map[finding_id],
                severity=severity,
                description=desc_map[finding_id],
                evidence={
                    "url": url,
                    "malicious_domain": domain_row.domain,
                    "category": category,
                    "source": domain_row.source,
                },
                remediation=(
                    "Immediately remove the malicious script. Audit your theme and plugin files "
                    "for injected code. Reset all WordPress credentials and rotate payment API keys. "
                    "Notify your payment processor and consider filing a PCI DSS incident report."
                ),
                references=[
                    "https://www.riskiq.com/what-is-magecart/",
                    "https://owasp.org/www-project-top-ten/",
                ],
                cvss_score=cvss,
                module=self.name,
            ))

    def _emit_summary(
        self,
        ctx: ScanContext,
        pages_scanned: list[str],
        malicious_domains: list[str],
    ) -> None:
        ctx.add_finding(Finding(
            id="PC-MGC-000",
            remediation_id="REM-MGC-000",
            title="Magecart scan summary",
            severity=Severity.INFO,
            description=(
                f"Magecart scan completed. Pages scanned: {len(pages_scanned)}. "
                f"Malicious domains found: {len(malicious_domains)}."
            ),
            evidence={
                "pages_scanned": pages_scanned,
                "malicious_domains": list(dict.fromkeys(malicious_domains)),
            },
            remediation="No action required for this informational finding.",
            references=["https://www.riskiq.com/what-is-magecart/"],
            cvss_score=None,
            module=self.name,
        ))
