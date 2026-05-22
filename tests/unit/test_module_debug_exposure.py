from __future__ import annotations

import pytest
import respx
import httpx

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.debug_exposure import DebugExposureModule


@pytest.fixture
def ctx():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    return ctx


async def test_debug_skips_non_wordpress():
    """When ctx.is_wordpress is False the module is a no-op."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = False
    async with respx.mock:
        async with PlecostHTTPClient(ctx.opts) as http:
            await DebugExposureModule().run(ctx, http)
    assert ctx.findings == []


async def test_wp_debug_log_accessible(ctx):
    """PC-DBG-001 is added when PHP error messages appear in the homepage HTML."""
    html = (
        "<html><body>"
        "<b>Notice</b>: Undefined variable in /var/www/html/wp-content/themes/foo/functions.php"
        "</body></html>"
    )
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await DebugExposureModule().run(ctx, http)

    assert any(f.id == "PC-DBG-001" for f in ctx.findings)


async def test_wp_debug_log_not_found(ctx):
    """No PC-DBG-001 when the homepage contains no PHP error messages."""
    html = "<html><body><h1>Welcome to WordPress</h1></body></html>"
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await DebugExposureModule().run(ctx, http)

    assert not any(f.id == "PC-DBG-001" for f in ctx.findings)


async def test_php_fatal_error_detected(ctx):
    """PC-DBG-001 is triggered on Fatal error PHP messages too."""
    html = (
        "<html><body>"
        "<b>Fatal error</b>: Call to undefined function do_something()"
        "</body></html>"
    )
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await DebugExposureModule().run(ctx, http)

    assert any(f.id == "PC-DBG-001" for f in ctx.findings)


async def test_x_powered_by_php_not_reported_by_debug_module(ctx):
    """PC-DBG-003 is retired from debug_exposure — PHP header is covered by PC-HDR-008 in http_headers."""
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(
                200,
                headers={"x-powered-by": "PHP/8.1.12"},
                text="<html></html>",
            )
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await DebugExposureModule().run(ctx, http)

    # debug_exposure no longer emits PC-DBG-003; http_headers module emits PC-HDR-008 instead
    assert not any(f.id == "PC-DBG-003" for f in ctx.findings)


async def test_both_debug_and_php_header_only_dbg001(ctx):
    """When PHP errors and X-Powered-By are both present, only PC-DBG-001 is emitted by debug_exposure."""
    html = "<html><body><b>Warning</b>: Division by zero</body></html>"
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(
                200,
                headers={"x-powered-by": "PHP/7.4.3"},
                text=html,
            )
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await DebugExposureModule().run(ctx, http)

    ids = {f.id for f in ctx.findings}
    assert "PC-DBG-001" in ids
    assert "PC-DBG-003" not in ids  # moved to PC-HDR-008 in http_headers module
