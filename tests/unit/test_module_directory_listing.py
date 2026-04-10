import pytest
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.directory_listing import DirectoryListingModule


@pytest.fixture
def ctx():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    return ctx


@pytest.mark.asyncio
async def test_detects_directory_listing(ctx):
    dir_html = "<html><title>Index of /wp-content/</title><body>Index of /wp-content/</body></html>"
    async with respx.mock:
        respx.get("https://example.com/wp-content/").mock(
            return_value=httpx.Response(200, text=dir_html)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(403))
        async with PlecostHTTPClient(ctx.opts) as http:
            await DirectoryListingModule().run(ctx, http)
    assert any(f.id == "PC-DIR-001" for f in ctx.findings)


@pytest.mark.asyncio
async def test_no_directory_listing_if_403(ctx):
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(403))
        async with PlecostHTTPClient(ctx.opts) as http:
            await DirectoryListingModule().run(ctx, http)
    assert not any(f.id.startswith("PC-DIR") for f in ctx.findings)
