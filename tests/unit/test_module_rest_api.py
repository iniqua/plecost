import pytest
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.rest_api import RESTAPIModule


@pytest.fixture
def ctx():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    return ctx


@pytest.mark.asyncio
async def test_detects_rest_link_in_html(ctx):
    html = '<link rel="https://api.w.org/" href="https://example.com/wp-json/"/>'
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await RESTAPIModule().run(ctx, http)
    assert any(f.id == "PC-REST-001" for f in ctx.findings)


@pytest.mark.asyncio
async def test_detects_cors_misconfiguration(ctx):
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=""))
        respx.route(url__regex=r".*/oembed.*").mock(return_value=httpx.Response(404))
        respx.get("https://example.com/wp-json/wp/v2/").mock(
            return_value=httpx.Response(200, headers={"access-control-allow-origin": "*"}, text="{}")
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await RESTAPIModule().run(ctx, http)
    assert any(f.id == "PC-REST-003" for f in ctx.findings)
