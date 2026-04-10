import pytest
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.waf import WAFModule


@pytest.fixture
def ctx():
    return ScanContext(ScanOptions(url="https://example.com"))


@pytest.mark.asyncio
async def test_detects_cloudflare(ctx):
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(
            200, headers={"server": "cloudflare", "cf-ray": "abc123"}, text=""
        ))
        async with PlecostHTTPClient(ctx.opts) as http:
            await WAFModule().run(ctx, http)
    assert ctx.waf_detected == "Cloudflare"


@pytest.mark.asyncio
async def test_detects_sucuri(ctx):
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(
            200, headers={"x-sucuri-id": "12345"}, text=""
        ))
        async with PlecostHTTPClient(ctx.opts) as http:
            await WAFModule().run(ctx, http)
    assert ctx.waf_detected == "Sucuri"


@pytest.mark.asyncio
async def test_no_waf_detected(ctx):
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(
            200, headers={"server": "nginx"}, text=""
        ))
        async with PlecostHTTPClient(ctx.opts) as http:
            await WAFModule().run(ctx, http)
    assert ctx.waf_detected is None
