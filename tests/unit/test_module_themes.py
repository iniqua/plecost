import pytest
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.themes import ThemesModule


@pytest.fixture
def ctx():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    return ctx


@pytest.mark.asyncio
async def test_detects_theme_via_passive_html(ctx):
    html = '<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css?ver=1.2"/>'
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.route(url__regex=r".*/style\.css").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            mod = ThemesModule(wordlist=[])
            await mod.run(ctx, http)
    assert any(t.slug == "twentytwentyfour" for t in ctx.themes)


@pytest.mark.asyncio
async def test_detects_theme_version_via_style_css(ctx):
    css = "/*\nTheme Name: Twenty Twenty-Four\nVersion: 1.2.3\n*/"
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=""))
        respx.get("https://example.com/wp-content/themes/twentytwentyfour/style.css").mock(
            return_value=httpx.Response(200, text=css)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            mod = ThemesModule(wordlist=["twentytwentyfour"])
            await mod.run(ctx, http)
    assert any(t.slug == "twentytwentyfour" and t.version == "1.2.3" for t in ctx.themes)
