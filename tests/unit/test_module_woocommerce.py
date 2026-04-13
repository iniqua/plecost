from __future__ import annotations

import httpx
import pytest
import respx

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.woocommerce import WooCommerceModule

# ── Fixtures ──────────────────────────────────────────────────────────────────

BASE = "https://example.com"

_DEFAULT_404 = httpx.Response(404, text="Not Found")


@pytest.fixture
def ctx() -> ScanContext:
    c = ScanContext(ScanOptions(url=BASE))
    c.is_wordpress = True
    return c


@pytest.fixture
def ctx_semi() -> ScanContext:
    opts = ScanOptions(
        url=BASE,
        module_options={"woocommerce": {"mode": "semi-active"}},
    )
    c = ScanContext(opts)
    c.is_wordpress = True
    return c


def _store_api_200() -> httpx.Response:
    return httpx.Response(200, json={"namespace": "wc/store/v1"})


def _readme_200(version: str = "8.0.0") -> httpx.Response:
    return httpx.Response(200, text=f"Stable tag: {version}\n")


def _wp_json_with_wc() -> httpx.Response:
    return httpx.Response(200, json={"namespaces": ["wp/v2", "wc/v3", "wc/store/v1"]})


# ── Basic detection ───────────────────────────────────────────────────────────

async def test_not_wordpress_skips(ctx: ScanContext) -> None:
    ctx.is_wordpress = False
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert not any(f.id.startswith("PC-WC-") for f in ctx.findings)


async def test_404_everywhere_no_detection(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert not any(f.id.startswith("PC-WC-") for f in ctx.findings)
    assert ctx.woocommerce is None


async def test_detect_via_store_api(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert any(f.id == "PC-WC-001" for f in ctx.findings)
    assert ctx.woocommerce is not None
    assert ctx.woocommerce.detected is True


async def test_detect_via_readme_only(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-content/plugins/woocommerce/readme.txt").mock(
            return_value=_readme_200()
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert ctx.woocommerce is not None
    assert ctx.woocommerce.detected is True


async def test_version_from_readme(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-content/plugins/woocommerce/readme.txt").mock(
            return_value=_readme_200("8.5.2")
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert ctx.woocommerce is not None
    assert ctx.woocommerce.version == "8.5.2"
    finding = next(f for f in ctx.findings if f.id == "PC-WC-002")
    assert finding.evidence["version"] == "8.5.2"


async def test_namespaces_from_wp_json(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.get(f"{BASE}/wp-json/").mock(return_value=_wp_json_with_wc())
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert any(f.id == "PC-WC-003" for f in ctx.findings)


# ── Sub-plugin detection ──────────────────────────────────────────────────────

async def test_detect_payments_plugin(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.get(f"{BASE}/wp-content/plugins/woocommerce-payments/readme.txt").mock(
            return_value=httpx.Response(200, text="Stable tag: 6.0.0\n")
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert any(f.id == "PC-WC-010" for f in ctx.findings)
    assert ctx.woocommerce is not None
    assert "payments" in ctx.woocommerce.active_plugins


async def test_detect_stripe_plugin(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.get(f"{BASE}/wp-content/plugins/woocommerce-gateway-stripe/readme.txt").mock(
            return_value=httpx.Response(200, text="Stable tag: 7.4.1\n")
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert any(f.id == "PC-WC-011" for f in ctx.findings)
    assert ctx.woocommerce is not None
    assert "stripe-gateway" in ctx.woocommerce.active_plugins


async def test_blocks_detected_via_namespace(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert ctx.woocommerce is not None
    assert "blocks" in ctx.woocommerce.active_plugins


# ── REST API open checks ──────────────────────────────────────────────────────

async def test_customers_api_open(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.get(f"{BASE}/wp-json/wc/v3/customers").mock(
            return_value=httpx.Response(200, json=[{"id": 1, "email": "test@test.com"}])
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert any(f.id == "PC-WC-004" for f in ctx.findings)


async def test_orders_api_open(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.get(f"{BASE}/wp-json/wc/v3/orders").mock(
            return_value=httpx.Response(200, json=[])
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert any(f.id == "PC-WC-005" for f in ctx.findings)


async def test_coupons_api_open(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.get(f"{BASE}/wp-json/wc/v3/coupons").mock(
            return_value=httpx.Response(200, json=[])
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert any(f.id == "PC-WC-006" for f in ctx.findings)


async def test_system_status_api_open(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.get(f"{BASE}/wp-json/wc/v3/system-status").mock(
            return_value=httpx.Response(200, json={"environment": {}})
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert any(f.id == "PC-WC-007" for f in ctx.findings)


async def test_api_401_not_flagged(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.get(f"{BASE}/wp-json/wc/v3/customers").mock(
            return_value=httpx.Response(401, json={"code": "woocommerce_rest_authentication_error"})
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert not any(f.id == "PC-WC-004" for f in ctx.findings)


# ── Sensitive file checks ─────────────────────────────────────────────────────

async def test_wc_logs_dir_listing(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.get(f"{BASE}/wp-content/uploads/wc-logs/").mock(
            return_value=httpx.Response(
                200, text="<html><title>Index of /wp-content/uploads/wc-logs/</title></html>"
            )
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert any(f.id == "PC-WC-008" for f in ctx.findings)


async def test_wc_uploads_accessible(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.get(f"{BASE}/wp-content/uploads/woocommerce_uploads/").mock(
            return_value=httpx.Response(200, text="OK")
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert any(f.id == "PC-WC-009" for f in ctx.findings)


# ── Authenticated checks ──────────────────────────────────────────────────────

async def test_authenticated_system_status() -> None:
    opts = ScanOptions(
        url=BASE,
        module_options={
            "woocommerce": {
                "wc_consumer_key": "ck_test123",
                "wc_consumer_secret": "cs_test456",
            }
        },
    )
    c = ScanContext(opts)
    c.is_wordpress = True

    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.get(f"{BASE}/wp-json/wc/v3/system-status").mock(
            return_value=httpx.Response(200, json={"environment": {"wc_version": "8.0.0"}})
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(c.opts) as http:
            await WooCommerceModule().run(c, http)
    assert any(f.id == "PC-WC-012" for f in c.findings)


async def test_authenticated_payment_gateways() -> None:
    opts = ScanOptions(
        url=BASE,
        module_options={
            "woocommerce": {
                "wc_consumer_key": "ck_test123",
                "wc_consumer_secret": "cs_test456",
            }
        },
    )
    c = ScanContext(opts)
    c.is_wordpress = True

    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.get(f"{BASE}/wp-json/wc/v3/payment-gateways").mock(
            return_value=httpx.Response(200, json=[{"id": "stripe", "enabled": True}])
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(c.opts) as http:
            await WooCommerceModule().run(c, http)
    assert any(f.id == "PC-WC-013" for f in c.findings)


# ── Semi-active CVE checks ────────────────────────────────────────────────────

async def test_cve_28121_detected_semi_active(ctx_semi: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.get(f"{BASE}/wp-content/plugins/woocommerce-payments/readme.txt").mock(
            return_value=httpx.Response(200, text="Stable tag: 5.0.0\n")
        )
        respx.post(f"{BASE}/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(200, json={"id": 2, "name": "admin"})
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx_semi.opts) as http:
            await WooCommerceModule().run(ctx_semi, http)
    assert any(f.id == "PC-WC-020" for f in ctx_semi.findings)


async def test_cve_28121_skipped_if_payments_absent(ctx_semi: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.post(f"{BASE}/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(200, json={"id": 2})
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx_semi.opts) as http:
            await WooCommerceModule().run(ctx_semi, http)
    assert not any(f.id == "PC-WC-020" for f in ctx_semi.findings)


async def test_cve_28121_passive_mode_skipped(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.get(f"{BASE}/wp-content/plugins/woocommerce-payments/readme.txt").mock(
            return_value=httpx.Response(200, text="Stable tag: 5.0.0\n")
        )
        respx.post(f"{BASE}/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(200, json={"id": 2})
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert not any(f.id == "PC-WC-020" for f in ctx.findings)


async def test_cve_34000_detected_semi_active(ctx_semi: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.get(f"{BASE}/wp-content/plugins/woocommerce-gateway-stripe/readme.txt").mock(
            return_value=httpx.Response(200, text="Stable tag: 7.0.0\n")
        )
        respx.get(f"{BASE}/?wc-ajax=wc_stripe_payment_request_ajax&order_id=1").mock(
            return_value=httpx.Response(
                200, json={"email": "victim@example.com", "billing": {"city": "Madrid"}}
            )
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx_semi.opts) as http:
            await WooCommerceModule().run(ctx_semi, http)
    assert any(f.id == "PC-WC-021" for f in ctx_semi.findings)


async def test_cve_34000_no_pii_no_finding(ctx_semi: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.get(f"{BASE}/wp-content/plugins/woocommerce-gateway-stripe/readme.txt").mock(
            return_value=httpx.Response(200, text="Stable tag: 7.0.0\n")
        )
        respx.get(f"{BASE}/?wc-ajax=wc_stripe_payment_request_ajax&order_id=1").mock(
            return_value=httpx.Response(200, json={"status": "ok", "result": "success"})
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx_semi.opts) as http:
            await WooCommerceModule().run(ctx_semi, http)
    assert not any(f.id == "PC-WC-021" for f in ctx_semi.findings)


# ── Summary finding ───────────────────────────────────────────────────────────

async def test_summary_finding_always_emitted(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/wc/store/v1/").mock(return_value=_store_api_200())
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert any(f.id == "PC-WC-000" for f in ctx.findings)


async def test_ctx_woocommerce_populated(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(f"{BASE}/wp-content/plugins/woocommerce/readme.txt").mock(
            return_value=_readme_200("8.0.0")
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WooCommerceModule().run(ctx, http)
    assert ctx.woocommerce is not None
    assert ctx.woocommerce.version == "8.0.0"
    assert "core" in ctx.woocommerce.active_plugins
