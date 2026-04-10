import pytest
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.http_headers import HTTPHeadersModule


@pytest.fixture
def ctx():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    return ctx


@pytest.mark.asyncio
async def test_detects_missing_hsts(ctx):
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, headers={"server": "nginx"}, text="")
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await HTTPHeadersModule().run(ctx, http)
    assert any(f.id == "PC-HDR-001" for f in ctx.findings)


@pytest.mark.asyncio
async def test_detects_server_version_disclosure(ctx):
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, headers={"server": "Apache/2.4.51 (Ubuntu)"}, text="")
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await HTTPHeadersModule().run(ctx, http)
    assert any(f.id == "PC-HDR-007" for f in ctx.findings)


@pytest.mark.asyncio
async def test_detects_php_version_disclosure(ctx):
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, headers={"x-powered-by": "PHP/8.1.2"}, text="")
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await HTTPHeadersModule().run(ctx, http)
    assert any(f.id == "PC-HDR-008" for f in ctx.findings)
