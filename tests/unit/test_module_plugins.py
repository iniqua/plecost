import pytest
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.plugins import PluginsModule


@pytest.fixture
def ctx():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    return ctx


@pytest.mark.asyncio
async def test_detects_plugin_via_passive_html(ctx):
    html = '<script src="/wp-content/plugins/woocommerce/assets/js/main.js?ver=8.0.0"></script>'
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.route(url__regex=r".*/readme\.txt").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            mod = PluginsModule(wordlist=["woocommerce"])
            await mod.run(ctx, http)
    assert any(p.slug == "woocommerce" for p in ctx.plugins)
    assert ctx.plugins[0].version == "8.0.0"


@pytest.mark.asyncio
async def test_detects_plugin_version_via_readme(ctx):
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=""))
        respx.get("https://example.com/wp-content/plugins/akismet/readme.txt").mock(
            return_value=httpx.Response(200, text="Stable tag: 5.3.1\n")
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            mod = PluginsModule(wordlist=["akismet"])
            await mod.run(ctx, http)
    assert any(p.slug == "akismet" and p.version == "5.3.1" for p in ctx.plugins)
