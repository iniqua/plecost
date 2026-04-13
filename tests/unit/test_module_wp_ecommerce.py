from __future__ import annotations

import httpx
import pytest
import respx

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.wp_ecommerce import WPECommerceModule

# ── Constants & helpers ───────────────────────────────────────────────────────

BASE = "https://example.com"

_DEFAULT_404 = httpx.Response(404, text="Not Found")

_PLUGIN_README_URL = f"{BASE}/wp-content/plugins/wp-e-commerce/readme.txt"
_MAIN_PHP_URL = f"{BASE}/wp-content/plugins/wp-e-commerce/wp-shopping-cart.php"
_CHRONOPAY_URL = f"{BASE}/wp-content/plugins/wp-e-commerce/wpsc-merchants/chronopay.php"
_PLUGIN_DIR_URL = f"{BASE}/wp-content/plugins/wp-e-commerce/"
_UPLOADS_WPSC_URL = f"{BASE}/wp-content/uploads/wpsc/"
_DIGITAL_URL = f"{BASE}/wp-content/uploads/wpsc/digital/"
_DB_BACKUP_URL = f"{BASE}/wp-content/plugins/wp-e-commerce/wpsc-admin/db-backup.php"
_DISPLAY_LOG_URL = f"{BASE}/wp-content/plugins/wp-e-commerce/wpsc-admin/display-log.php"
_CHRONOPAY_RETURN_URL = f"{BASE}/?chronopay_return=1"
_CHRONOPAY_PROCESS_URL = f"{BASE}/?chronopay=process"
_ADMIN_AJAX_URL = f"{BASE}/wp-admin/admin-ajax.php?action=wpsc_add_to_cart"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def ctx() -> ScanContext:
    c = ScanContext(ScanOptions(url=BASE))
    c.is_wordpress = True
    return c


@pytest.fixture
def ctx_semi() -> ScanContext:
    opts = ScanOptions(url=BASE, module_options={"wpec": {"mode": "semi-active"}})
    c = ScanContext(opts)
    c.is_wordpress = True
    return c


def _readme_200(version: str = "3.15.1") -> httpx.Response:
    return httpx.Response(200, text=f"Stable tag: {version}\n")


def _dir_listing_200() -> httpx.Response:
    return httpx.Response(
        200,
        text="<html><title>Index of /wp-content/plugins/wp-e-commerce/</title></html>",
    )


# ── Basic detection ───────────────────────────────────────────────────────────

async def test_not_wordpress_skips(ctx: ScanContext) -> None:
    ctx.is_wordpress = False
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    assert not any(f.id.startswith("PC-WPEC-") for f in ctx.findings)


async def test_404_everywhere_no_detection(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    assert not any(f.id == "PC-WPEC-001" for f in ctx.findings)
    assert not any(f.id == "PC-WPEC-003" for f in ctx.findings)
    assert ctx.wp_ecommerce is None


async def test_detect_via_readme(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    assert any(f.id == "PC-WPEC-001" for f in ctx.findings)


async def test_detect_via_wp_shopping_cart_php(ctx: ScanContext) -> None:
    # wp-shopping-cart.php being accessible sets detected_flags[1]=True which triggers
    # the full passive scan (PC-WPEC-003 abandoned finding, PC-WPEC-000 summary).
    # PC-WPEC-001 is only emitted by _probe_readme() when readme.txt returns 200.
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_DEFAULT_404)
        respx.get(_MAIN_PHP_URL).mock(return_value=httpx.Response(200, text="<?php"))
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    # Plugin detected via wp-shopping-cart.php: abandoned finding and summary must be emitted
    assert any(f.id == "PC-WPEC-003" for f in ctx.findings)
    assert any(f.id == "PC-WPEC-000" for f in ctx.findings)
    assert ctx.wp_ecommerce is not None
    assert ctx.wp_ecommerce.detected is True


async def test_version_from_readme(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200("3.15.1"))
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    version_finding = next((f for f in ctx.findings if f.id == "PC-WPEC-002"), None)
    assert version_finding is not None
    assert version_finding.evidence["version"] == "3.15.1"


async def test_abandoned_finding_always_emitted(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    assert any(f.id == "PC-WPEC-003" for f in ctx.findings)


async def test_chronopay_gateway_detected(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.get(_CHRONOPAY_URL).mock(return_value=httpx.Response(200, text="<?php"))
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    assert any(f.id == "PC-WPEC-004" for f in ctx.findings)


async def test_plugin_dir_listing(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.get(_PLUGIN_DIR_URL).mock(return_value=_dir_listing_200())
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    assert any(f.id == "PC-WPEC-005" for f in ctx.findings)


async def test_uploads_dir_accessible(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.get(_UPLOADS_WPSC_URL).mock(return_value=httpx.Response(200, text="OK"))
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    assert any(f.id == "PC-WPEC-006" for f in ctx.findings)


async def test_digital_downloads_exposed(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.get(_DIGITAL_URL).mock(return_value=httpx.Response(200, text="OK"))
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    assert any(f.id == "PC-WPEC-007" for f in ctx.findings)


async def test_backup_script_accessible(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.get(_DB_BACKUP_URL).mock(return_value=httpx.Response(200, text="<?php"))
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    assert any(f.id == "PC-WPEC-008" for f in ctx.findings)


async def test_log_viewer_accessible(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.get(_DISPLAY_LOG_URL).mock(return_value=httpx.Response(200, text="<?php"))
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    assert any(f.id == "PC-WPEC-009" for f in ctx.findings)


async def test_chronopay_callback_exposed(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.get(_CHRONOPAY_URL).mock(return_value=httpx.Response(200, text="<?php"))
        respx.get(_CHRONOPAY_RETURN_URL).mock(return_value=httpx.Response(200, text="OK"))
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    assert any(f.id == "PC-WPEC-010" for f in ctx.findings)


async def test_dir_401_not_flagged(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.get(_PLUGIN_DIR_URL).mock(return_value=httpx.Response(401, text="Unauthorized"))
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    assert not any(f.id == "PC-WPEC-005" for f in ctx.findings)


# ── Semi-active CVE checks ────────────────────────────────────────────────────

async def test_cve_2024_1514_sqli_detected(ctx_semi: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.get(_CHRONOPAY_URL).mock(return_value=httpx.Response(200, text="<?php"))
        respx.post(_CHRONOPAY_PROCESS_URL).mock(
            return_value=httpx.Response(
                200,
                text="You have an error in your SQL syntax near '1' at line 1",
            )
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx_semi.opts) as http:
            await WPECommerceModule().run(ctx_semi, http)
    assert any(f.id == "PC-WPEC-020" for f in ctx_semi.findings)


async def test_cve_2024_1514_skipped_if_no_chronopay(ctx_semi: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.get(_CHRONOPAY_URL).mock(return_value=_DEFAULT_404)
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx_semi.opts) as http:
            await WPECommerceModule().run(ctx_semi, http)
    assert not any(f.id == "PC-WPEC-020" for f in ctx_semi.findings)


async def test_cve_2024_1514_passive_mode_skipped(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.get(_CHRONOPAY_URL).mock(return_value=httpx.Response(200, text="<?php"))
        respx.post(_CHRONOPAY_PROCESS_URL).mock(
            return_value=httpx.Response(
                200,
                text="You have an error in your SQL syntax",
            )
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    assert not any(f.id == "PC-WPEC-020" for f in ctx.findings)


async def test_cve_2024_1514_no_sql_error_no_finding(ctx_semi: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.get(_CHRONOPAY_URL).mock(return_value=httpx.Response(200, text="<?php"))
        respx.post(_CHRONOPAY_PROCESS_URL).mock(
            return_value=httpx.Response(200, text="OK - no error here")
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx_semi.opts) as http:
            await WPECommerceModule().run(ctx_semi, http)
    assert not any(f.id == "PC-WPEC-020" for f in ctx_semi.findings)


async def test_cve_2026_1235_detected(ctx_semi: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.post(_ADMIN_AJAX_URL).mock(
            return_value=httpx.Response(
                500,
                text="Fatal error: __wakeup() called with incompatible class",
            )
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx_semi.opts) as http:
            await WPECommerceModule().run(ctx_semi, http)
    assert any(f.id == "PC-WPEC-021" for f in ctx_semi.findings)


async def test_cve_2026_1235_passive_skipped(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.post(_ADMIN_AJAX_URL).mock(
            return_value=httpx.Response(
                500,
                text="Fatal error: __wakeup() called",
            )
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    assert not any(f.id == "PC-WPEC-021" for f in ctx.findings)


async def test_cve_2026_1235_no_injection_response(ctx_semi: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.post(_ADMIN_AJAX_URL).mock(
            return_value=httpx.Response(200, text='{"result": "success"}')
        )
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx_semi.opts) as http:
            await WPECommerceModule().run(ctx_semi, http)
    assert not any(f.id == "PC-WPEC-021" for f in ctx_semi.findings)


# ── Summary and context population ───────────────────────────────────────────

async def test_summary_finding_emitted(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    assert any(f.id == "PC-WPEC-000" for f in ctx.findings)


async def test_ctx_wp_ecommerce_populated(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200("3.15.1"))
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    assert ctx.wp_ecommerce is not None
    assert ctx.wp_ecommerce.version == "3.15.1"


async def test_force_scan_without_wordpress() -> None:
    opts = ScanOptions(url=BASE, force=True)
    ctx = ScanContext(opts)
    # is_wordpress is intentionally left as False
    assert ctx.is_wordpress is False

    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    assert any(f.id == "PC-WPEC-001" for f in ctx.findings)


async def test_checks_run_populated(ctx: ScanContext) -> None:
    async with respx.mock:
        respx.get(_PLUGIN_README_URL).mock(return_value=_readme_200())
        respx.route(url__regex=r".*").mock(return_value=_DEFAULT_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPECommerceModule().run(ctx, http)
    assert ctx.wp_ecommerce is not None
    assert len(ctx.wp_ecommerce.checks_run) > 0
