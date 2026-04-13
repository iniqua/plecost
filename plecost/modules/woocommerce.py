from __future__ import annotations

import asyncio
import re
from typing import Any

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity, WooCommerceInfo
from plecost.modules.base import ScanModule

_VERSION_RE = re.compile(r"Stable tag:\s*([\d.]+)", re.I)
_DIR_LISTING_RE = re.compile(r"<title>\s*index of", re.I)


class WooCommerceModule(ScanModule):
    name = "woocommerce"
    depends_on = ["fingerprint"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress and not ctx.opts.force:
            return

        wc_opts = ctx.opts.module_options.get("woocommerce", {})
        mode = wc_opts.get("mode", "passive")

        detected, version, active_plugins, api_namespaces = await self._fingerprint(ctx, http)
        if not detected:
            return

        ctx.woocommerce = WooCommerceInfo(
            detected=True,
            version=version,
            active_plugins=active_plugins,
            api_namespaces=api_namespaces,
        )

        await asyncio.gather(
            self._check_rest_endpoint(
                ctx, http, "/wp-json/wc/v3/customers",
                "PC-WC-004", "REM-WC-004", Severity.CRITICAL,
                "WooCommerce REST API: customer list exposed without authentication",
                "The /wp-json/wc/v3/customers endpoint returns customer PII (name, email, address) "
                "without requiring any authentication credentials.",
                "Restrict the WooCommerce REST API. Ensure consumer keys are required for all "
                "sensitive endpoints via WooCommerce > Settings > Advanced > REST API.",
                ["https://woocommerce.com/document/woocommerce-rest-api/",
                 "https://owasp.org/www-project-top-ten/"],
                9.1,
            ),
            self._check_rest_endpoint(
                ctx, http, "/wp-json/wc/v3/orders",
                "PC-WC-005", "REM-WC-005", Severity.CRITICAL,
                "WooCommerce REST API: order list exposed without authentication",
                "The /wp-json/wc/v3/orders endpoint returns all customer orders with PII "
                "without requiring authentication.",
                "Restrict the WooCommerce REST API to authenticated users only.",
                ["https://woocommerce.com/document/woocommerce-rest-api/"],
                9.1,
            ),
            self._check_rest_endpoint(
                ctx, http, "/wp-json/wc/v3/coupons",
                "PC-WC-006", "REM-WC-006", Severity.HIGH,
                "WooCommerce REST API: coupon list exposed without authentication",
                "The /wp-json/wc/v3/coupons endpoint exposes all active discount codes "
                "without authentication, allowing coupon abuse.",
                "Restrict the WooCommerce REST API to authenticated users only.",
                ["https://woocommerce.com/document/woocommerce-rest-api/"],
                7.5,
            ),
            self._check_rest_endpoint(
                ctx, http, "/wp-json/wc/v3/system-status",
                "PC-WC-007", "REM-WC-007", Severity.HIGH,
                "WooCommerce REST API: system status exposed without authentication",
                "The /wp-json/wc/v3/system-status endpoint reveals server configuration, "
                "PHP/MySQL versions, plugin list, and debug settings without authentication.",
                "Restrict the WooCommerce REST API to authenticated users only.",
                ["https://woocommerce.com/document/woocommerce-rest-api/"],
                7.5,
            ),
            self._check_wc_logs(ctx, http),
            self._check_wc_uploads(ctx, http),
        )

        consumer_key = wc_opts.get("wc_consumer_key")
        consumer_secret = wc_opts.get("wc_consumer_secret")
        if consumer_key and consumer_secret:
            await asyncio.gather(
                self._check_authenticated_system_status(ctx, http, consumer_key, consumer_secret),
                self._check_payment_gateways(ctx, http, consumer_key, consumer_secret),
            )

        if mode == "semi-active":
            await asyncio.gather(
                self._check_cve_2023_28121(ctx, http),
                self._check_cve_2023_34000(ctx, http),
            )

        self._emit_summary(ctx, mode, bool(consumer_key))

    # ── Fingerprint ──────────────────────────────────────────────────────────

    async def _fingerprint(
        self,
        ctx: ScanContext,
        http: PlecostHTTPClient,
    ) -> tuple[bool, str | None, list[str], list[str]]:
        detected_flags: list[bool] = [False, False]
        version_holder: list[str | None] = [None]
        active_plugins: list[str] = []
        api_namespaces: list[str] = []

        async def _probe_store_api() -> None:
            url = ctx.url + "/wp-json/wc/store/v1/"
            try:
                r = await http.get(url)
                if r.status_code == 200:
                    detected_flags[0] = True
                    if "core" not in active_plugins:
                        active_plugins.append("core")
                    try:
                        data = r.json()
                        ns = data.get("namespace", "")
                        if ns and ns not in api_namespaces:
                            api_namespaces.append(ns)
                        if "wc/store/v1" in (ns or ""):
                            if "blocks" not in active_plugins:
                                active_plugins.append("blocks")
                    except (ValueError, KeyError):
                        pass
                    ctx.add_finding(Finding(
                        id="PC-WC-001",
                        remediation_id="REM-WC-001",
                        title="WooCommerce detected via Store API",
                        severity=Severity.INFO,
                        description="WooCommerce was detected via the /wp-json/wc/store/v1/ endpoint.",
                        evidence={"url": url, "status_code": r.status_code},
                        remediation="No action required. This is an informational finding.",
                        references=["https://woocommerce.com/"],
                        cvss_score=None,
                        module=self.name,
                    ))
            except Exception:
                pass

        async def _probe_readme() -> None:
            url = ctx.url + "/wp-content/plugins/woocommerce/readme.txt"
            try:
                r = await http.get(url)
                if r.status_code == 200:
                    detected_flags[1] = True
                    if "core" not in active_plugins:
                        active_plugins.append("core")
                    m = _VERSION_RE.search(r.text)
                    if m:
                        version_holder[0] = m.group(1)
                    ctx.add_finding(Finding(
                        id="PC-WC-002",
                        remediation_id="REM-WC-002",
                        title="WooCommerce version disclosed via readme.txt",
                        severity=Severity.LOW,
                        description=(
                            f"WooCommerce version {version_holder[0] or 'unknown'} is disclosed "
                            "via the publicly accessible readme.txt file."
                        ),
                        evidence={"url": url, "version": version_holder[0]},
                        remediation=(
                            "Remove or restrict access to readme.txt via .htaccess or Nginx config. "
                            "Add: <Files readme.txt> Require all denied </Files>"
                        ),
                        references=["https://wordpress.org/support/article/hardening-wordpress/"],
                        cvss_score=5.3,
                        module=self.name,
                    ))
            except Exception:
                pass

        async def _probe_wp_json_namespaces() -> None:
            url = ctx.url + "/wp-json/"
            try:
                r = await http.get(url)
                if r.status_code == 200:
                    try:
                        data = r.json()
                        namespaces = data.get("namespaces", [])
                        wc_ns = [n for n in namespaces if n.startswith("wc/") or n.startswith("wc-")]
                        if wc_ns:
                            for ns in wc_ns:
                                if ns not in api_namespaces:
                                    api_namespaces.append(ns)
                            if "wc/store/v1" in wc_ns and "blocks" not in active_plugins:
                                active_plugins.append("blocks")
                            ctx.add_finding(Finding(
                                id="PC-WC-003",
                                remediation_id="REM-WC-003",
                                title="WooCommerce REST API namespaces exposed",
                                severity=Severity.LOW,
                                description=(
                                    f"WooCommerce API namespaces are visible in /wp-json/: {wc_ns}"
                                ),
                                evidence={"url": url, "namespaces": wc_ns},
                                remediation=(
                                    "Consider restricting the REST API namespace list via a plugin "
                                    "or custom code to avoid revealing installed components."
                                ),
                                references=["https://developer.wordpress.org/rest-api/"],
                                cvss_score=3.7,
                                module=self.name,
                            ))
                    except (ValueError, KeyError):
                        pass
            except Exception:
                pass

        async def _probe_payments_plugin() -> None:
            url = ctx.url + "/wp-content/plugins/woocommerce-payments/readme.txt"
            try:
                r = await http.get(url)
                if r.status_code == 200:
                    if "payments" not in active_plugins:
                        active_plugins.append("payments")
                    ctx.add_finding(Finding(
                        id="PC-WC-010",
                        remediation_id="REM-WC-010",
                        title="WooCommerce Payments plugin detected",
                        severity=Severity.INFO,
                        description="WooCommerce Payments plugin is installed (readme.txt accessible).",
                        evidence={"url": url},
                        remediation="Keep WooCommerce Payments updated to the latest version.",
                        references=[
                            "https://wordpress.org/plugins/woocommerce-payments/",
                            "https://nvd.nist.gov/vuln/detail/CVE-2023-28121",
                        ],
                        cvss_score=None,
                        module=self.name,
                    ))
            except Exception:
                pass

        async def _probe_stripe_plugin() -> None:
            url = ctx.url + "/wp-content/plugins/woocommerce-gateway-stripe/readme.txt"
            try:
                r = await http.get(url)
                if r.status_code == 200:
                    if "stripe-gateway" not in active_plugins:
                        active_plugins.append("stripe-gateway")
                    ctx.add_finding(Finding(
                        id="PC-WC-011",
                        remediation_id="REM-WC-011",
                        title="WooCommerce Stripe Gateway plugin detected",
                        severity=Severity.INFO,
                        description="WooCommerce Stripe Gateway plugin is installed (readme.txt accessible).",
                        evidence={"url": url},
                        remediation="Keep WooCommerce Stripe Gateway updated to the latest version.",
                        references=[
                            "https://wordpress.org/plugins/woocommerce-gateway-stripe/",
                            "https://nvd.nist.gov/vuln/detail/CVE-2023-34000",
                        ],
                        cvss_score=None,
                        module=self.name,
                    ))
            except Exception:
                pass

        await asyncio.gather(
            _probe_store_api(),
            _probe_readme(),
            _probe_wp_json_namespaces(),
            _probe_payments_plugin(),
            _probe_stripe_plugin(),
        )

        detected = detected_flags[0] or detected_flags[1]
        return detected, version_holder[0], active_plugins, api_namespaces

    # ── REST API checks ───────────────────────────────────────────────────────

    async def _check_rest_endpoint(
        self,
        ctx: ScanContext,
        http: PlecostHTTPClient,
        path: str,
        finding_id: str,
        rem_id: str,
        severity: Severity,
        title: str,
        description: str,
        remediation: str,
        references: list[str],
        cvss_score: float | None,
    ) -> None:
        url = ctx.url + path
        try:
            r = await http.get(url)
            if r.status_code == 200:
                ctx.add_finding(Finding(
                    id=finding_id,
                    remediation_id=rem_id,
                    title=title,
                    severity=severity,
                    description=description,
                    evidence={"url": url, "status_code": r.status_code},
                    remediation=remediation,
                    references=references,
                    cvss_score=cvss_score,
                    module=self.name,
                ))
        except Exception:
            pass

    # ── Sensitive file checks ─────────────────────────────────────────────────

    async def _check_wc_logs(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        url = ctx.url + "/wp-content/uploads/wc-logs/"
        try:
            r = await http.get(url)
            if r.status_code == 200 and _DIR_LISTING_RE.search(r.text):
                ctx.add_finding(Finding(
                    id="PC-WC-008",
                    remediation_id="REM-WC-008",
                    title="WooCommerce logs directory listing enabled",
                    severity=Severity.HIGH,
                    description=(
                        "Directory listing is enabled on /wp-content/uploads/wc-logs/. "
                        "Log files may contain transaction data, payment tokens, stack traces, "
                        "and server paths."
                    ),
                    evidence={"url": url, "status_code": r.status_code},
                    remediation=(
                        "Add an .htaccess file to /wp-content/uploads/wc-logs/ with: "
                        "Options -Indexes. For Nginx, add autoindex off; to the location block."
                    ),
                    references=["https://developer.woocommerce.com/docs/best-practices/data-management/logging/"],
                    cvss_score=7.5,
                    module=self.name,
                ))
        except Exception:
            pass

    async def _check_wc_uploads(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        url = ctx.url + "/wp-content/uploads/woocommerce_uploads/"
        try:
            r = await http.get(url)
            if r.status_code == 200:
                ctx.add_finding(Finding(
                    id="PC-WC-009",
                    remediation_id="REM-WC-009",
                    title="WooCommerce uploads directory accessible",
                    severity=Severity.HIGH,
                    description=(
                        "The /wp-content/uploads/woocommerce_uploads/ directory is publicly accessible. "
                        "This directory stores private downloadable product files, invoice PDFs, "
                        "and customer exports. WooCommerce protects it with .htaccess, but Nginx "
                        "servers may not read .htaccess rules."
                    ),
                    evidence={"url": url, "status_code": r.status_code},
                    remediation=(
                        "For Nginx: add 'location /wp-content/uploads/woocommerce_uploads/ { deny all; }' "
                        "For Apache: verify .htaccess is being parsed (AllowOverride All)."
                    ),
                    references=["https://woocommerce.com/document/digital-downloadable-product-handling/"],
                    cvss_score=7.5,
                    module=self.name,
                ))
        except Exception:
            pass

    # ── Authenticated checks ──────────────────────────────────────────────────

    async def _check_authenticated_system_status(
        self,
        ctx: ScanContext,
        http: PlecostHTTPClient,
        consumer_key: str,
        consumer_secret: str,
    ) -> None:
        url = ctx.url + "/wp-json/wc/v3/system-status"
        try:
            r = await http.get(url, auth=(consumer_key, consumer_secret))
            if r.status_code == 200:
                try:
                    data: dict[str, Any] = r.json()
                    env = data.get("environment", {})
                except (ValueError, KeyError):
                    env = {}
                ctx.add_finding(Finding(
                    id="PC-WC-012",
                    remediation_id="REM-WC-012",
                    title="WooCommerce system status retrieved (authenticated)",
                    severity=Severity.INFO,
                    description="WooCommerce system-status endpoint was successfully accessed with API credentials.",
                    evidence={
                        "url": url,
                        "wc_version": env.get("wc_version"),
                        "wp_version": env.get("wp_version"),
                        "php_version": env.get("php_version"),
                        "wp_debug": env.get("wp_debug"),
                    },
                    remediation="Ensure API credentials are stored securely and have minimal required permissions.",
                    references=["https://woocommerce.com/document/woocommerce-rest-api/"],
                    cvss_score=None,
                    module=self.name,
                ))
        except Exception:
            pass

    async def _check_payment_gateways(
        self,
        ctx: ScanContext,
        http: PlecostHTTPClient,
        consumer_key: str,
        consumer_secret: str,
    ) -> None:
        url = ctx.url + "/wp-json/wc/v3/payment-gateways"
        try:
            r = await http.get(url, auth=(consumer_key, consumer_secret))
            if r.status_code == 200:
                try:
                    gateways = r.json()
                    enabled = [g.get("id") for g in gateways if g.get("enabled")]
                except (ValueError, KeyError, TypeError):
                    enabled = []
                ctx.add_finding(Finding(
                    id="PC-WC-013",
                    remediation_id="REM-WC-013",
                    title="WooCommerce payment gateway configuration exposed (authenticated)",
                    severity=Severity.HIGH,
                    description=(
                        "WooCommerce payment gateway configuration was retrieved via the API. "
                        "This may reveal enabled gateways, API keys, and webhook secrets."
                    ),
                    evidence={"url": url, "enabled_gateways": enabled},
                    remediation=(
                        "Restrict WooCommerce API keys to read-only where possible. "
                        "Rotate API credentials if they may have been exposed."
                    ),
                    references=["https://woocommerce.com/document/woocommerce-rest-api/"],
                    cvss_score=7.5,
                    module=self.name,
                ))
        except Exception:
            pass

    # ── Semi-active CVE checks ────────────────────────────────────────────────

    async def _check_cve_2023_28121(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        """CVE-2023-28121: WooCommerce Payments Authentication Bypass (CVSS 9.8).
        Only runs in semi-active mode. Sends a POST with the bypass header and checks
        if the server accepts it (200/201 response). Does NOT create any data — empty body.
        """
        if ctx.woocommerce and "payments" not in ctx.woocommerce.active_plugins:
            return
        url = ctx.url + "/wp-json/wp/v2/users"
        try:
            r = await http.post(
                url,
                headers={"X-WCPAY-PLATFORM-CHECKOUT-USER": "1"},
                content=b"",
            )
            if r.status_code in (200, 201):
                ctx.add_finding(Finding(
                    id="PC-WC-020",
                    remediation_id="REM-WC-020",
                    title="CVE-2023-28121: WooCommerce Payments authentication bypass",
                    severity=Severity.CRITICAL,
                    description=(
                        "The server accepted the X-WCPAY-PLATFORM-CHECKOUT-USER header, "
                        "indicating vulnerability to CVE-2023-28121. This critical flaw allows "
                        "unauthenticated attackers to impersonate any user, including admins, "
                        "and take over the site. Exploited massively in July 2023 (1.3M attacks/day)."
                    ),
                    evidence={"url": url, "status_code": r.status_code, "method": "POST",
                              "header": "X-WCPAY-PLATFORM-CHECKOUT-USER: 1"},
                    remediation=(
                        "Update WooCommerce Payments to version 5.6.2 or later immediately. "
                        "Check for unauthorized admin accounts created after the vulnerability window."
                    ),
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2023-28121",
                        "https://woocommerce.com/posts/critical-vulnerability-detected-july-2023/",
                    ],
                    cvss_score=9.8,
                    module=self.name,
                ))
        except Exception:
            pass

    async def _check_cve_2023_34000(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        """CVE-2023-34000: WooCommerce Stripe Gateway IDOR — unauthenticated PII disclosure (CVSS 7.5).
        Only runs in semi-active mode. Probes the Stripe AJAX endpoint with order_id=1.
        """
        if ctx.woocommerce and "stripe-gateway" not in ctx.woocommerce.active_plugins:
            return
        url = ctx.url + "/?wc-ajax=wc_stripe_payment_request_ajax&order_id=1"
        try:
            r = await http.get(url)
            if r.status_code == 200:
                try:
                    data = r.json()
                    pii_keys = {"email", "billing", "shipping", "customer_email", "customer"}
                    if any(k in data for k in pii_keys):
                        ctx.add_finding(Finding(
                            id="PC-WC-021",
                            remediation_id="REM-WC-021",
                            title="CVE-2023-34000: WooCommerce Stripe Gateway IDOR (PII disclosure)",
                            severity=Severity.HIGH,
                            description=(
                                "The WooCommerce Stripe Gateway AJAX endpoint is vulnerable to "
                                "CVE-2023-34000. Unauthenticated attackers can retrieve PII "
                                "(name, email, billing/shipping address) for any order by ID. "
                                "Affects 900,000+ installations."
                            ),
                            evidence={"url": url, "status_code": r.status_code,
                                      "pii_keys_found": [k for k in pii_keys if k in data]},
                            remediation="Update WooCommerce Stripe Gateway to version 7.4.1 or later.",
                            references=[
                                "https://nvd.nist.gov/vuln/detail/CVE-2023-34000",
                                "https://patchstack.com/articles/unauthenticated-idor-to-pii-disclosure-vulnerability-in-woocommerce-stripe-gateway-plugin/",
                            ],
                            cvss_score=7.5,
                            module=self.name,
                        ))
                except (ValueError, KeyError):
                    pass
        except Exception:
            pass

    # ── Summary finding ───────────────────────────────────────────────────────

    def _emit_summary(self, ctx: ScanContext, mode: str, has_credentials: bool) -> None:
        if not ctx.woocommerce:
            return
        wc = ctx.woocommerce
        checks_run = ["fingerprint", "rest_api_open", "sensitive_files"]
        if has_credentials:
            checks_run.append("authenticated_api")
        if mode == "semi-active":
            checks_run.extend(["cve_2023_28121", "cve_2023_34000"])
        ctx.add_finding(Finding(
            id="PC-WC-000",
            remediation_id="REM-WC-000",
            title="WooCommerce installation summary",
            severity=Severity.INFO,
            description="WooCommerce was detected and scanned for security issues.",
            evidence={
                "version": wc.version,
                "active_plugins": wc.active_plugins,
                "api_namespaces": wc.api_namespaces,
                "checks_run": checks_run,
                "mode": mode,
            },
            remediation="Review all WooCommerce findings and apply the recommended remediations.",
            references=["https://woocommerce.com/document/woocommerce-security/"],
            cvss_score=None,
            module=self.name,
        ))
