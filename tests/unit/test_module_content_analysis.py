from __future__ import annotations

import pytest
import respx
import httpx

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.content_analysis import ContentAnalysisModule


@pytest.fixture
def ctx():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    return ctx


async def test_content_skips_non_wordpress():
    """When ctx.is_wordpress is False the module is a no-op."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = False
    async with respx.mock:
        async with PlecostHTTPClient(ctx.opts) as http:
            await ContentAnalysisModule().run(ctx, http)
    assert ctx.findings == []


async def test_card_skimmer_detected(ctx):
    """PC-CNT-001 is added when a script src matches the skimmer pattern."""
    html = (
        '<html><head>'
        '<script src="https://evil-magecart.com/steal.js"></script>'
        '</head><body></body></html>'
    )
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await ContentAnalysisModule().run(ctx, http)

    assert any(f.id == "PC-CNT-001" for f in ctx.findings)


async def test_card_skimmer_cc_number_pattern(ctx):
    """PC-CNT-001 is also triggered by 'cc-number' in script src."""
    html = (
        '<html><head>'
        '<script src="https://cdn.example.net/cc-number-collector.js"></script>'
        '</head><body></body></html>'
    )
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await ContentAnalysisModule().run(ctx, http)

    assert any(f.id == "PC-CNT-001" for f in ctx.findings)


async def test_suspicious_iframe_detected(ctx):
    """PC-CNT-002 is added when an iframe points to an external domain."""
    html = (
        '<html><body>'
        '<iframe src="https://totally-external-bad.com/payload"></iframe>'
        '</body></html>'
    )
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await ContentAnalysisModule().run(ctx, http)

    assert any(f.id == "PC-CNT-002" for f in ctx.findings)


async def test_same_domain_iframe_not_flagged(ctx):
    """No PC-CNT-002 when an iframe points to the same domain."""
    html = (
        '<html><body>'
        '<iframe src="https://example.com/embed/video"></iframe>'
        '</body></html>'
    )
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await ContentAnalysisModule().run(ctx, http)

    assert not any(f.id == "PC-CNT-002" for f in ctx.findings)


async def test_api_key_in_source(ctx):
    """PC-CNT-003 is added when an API key pattern is found in page source."""
    html = (
        '<html><body>'
        '<script>var api_key = "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890";</script>'
        '</body></html>'
    )
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await ContentAnalysisModule().run(ctx, http)

    assert any(f.id == "PC-CNT-003" for f in ctx.findings)


async def test_clean_page_no_findings(ctx):
    """A normal WordPress page should produce no content-analysis findings."""
    html = (
        '<html>'
        '<head><title>My WordPress Site</title>'
        '<script src="https://example.com/wp-includes/js/jquery.js?ver=3.7.1"></script>'
        '</head>'
        '<body>'
        '<p>Hello, world!</p>'
        '</body>'
        '</html>'
    )
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await ContentAnalysisModule().run(ctx, http)

    assert ctx.findings == []


async def test_api_key_short_value_not_flagged(ctx):
    """Short values after api_key= should NOT trigger PC-CNT-003 (< 20 chars)."""
    html = (
        '<html><body>'
        '<script>var api_key = "short";</script>'
        '</body></html>'
    )
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await ContentAnalysisModule().run(ctx, http)

    assert not any(f.id == "PC-CNT-003" for f in ctx.findings)


async def test_http_error_response_no_crash(ctx):
    """Module should handle HTTP errors gracefully with no findings."""
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await ContentAnalysisModule().run(ctx, http)

    # No exception raised; findings may be empty
    assert not any(f.id in ("PC-CNT-001", "PC-CNT-002", "PC-CNT-003") for f in ctx.findings)
