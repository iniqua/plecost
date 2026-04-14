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


@pytest.mark.asyncio
async def test_passive_does_not_overwrite_theme_version_with_none(ctx):
    """Multiple occurrences of the same slug: version from first match is not lost."""
    html = (
        '<link href="/wp-content/themes/astra/style.css?ver=3.9.0"/>'
        '<img src="/wp-content/themes/astra/images/logo.png"/>'  # no ?ver=
    )
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.route(url__regex=r".*/style\.css").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            mod = ThemesModule(wordlist=[])
            await mod.run(ctx, http)
    theme = next((t for t in ctx.themes if t.slug == "astra"), None)
    assert theme is not None
    assert theme.version == "3.9.0", f"version lost: got {theme.version!r}"


@pytest.mark.asyncio
async def test_passive_upgrades_none_to_theme_version_on_later_occurrence(ctx):
    """If first occurrence has no ?ver= but later one does, version is captured."""
    html = (
        '<img src="/wp-content/themes/astra/images/logo.png"/>'  # no ?ver=
        '<link href="/wp-content/themes/astra/style.css?ver=3.9.0"/>'
    )
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.route(url__regex=r".*/style\.css").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            mod = ThemesModule(wordlist=[])
            await mod.run(ctx, http)
    theme = next((t for t in ctx.themes if t.slug == "astra"), None)
    assert theme is not None
    assert theme.version == "3.9.0", f"version not upgraded: got {theme.version!r}"


@pytest.mark.asyncio
async def test_passive_only_theme_gets_active_version_check(ctx):
    """Theme found passively but not in wordlist still gets style.css fetch."""
    html = '<img src="/wp-content/themes/custom-theme/images/banner.png"/>'
    css = "/*\nTheme Name: Custom Theme\nVersion: 4.2.1\n*/"
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.get("https://example.com/wp-content/themes/__plecost_probe__/style.css").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://example.com/wp-content/themes/custom-theme/style.css").mock(
            return_value=httpx.Response(200, text=css)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            mod = ThemesModule(wordlist=[])  # custom-theme NOT in wordlist
            await mod.run(ctx, http)
    theme = next((t for t in ctx.themes if t.slug == "custom-theme"), None)
    assert theme is not None
    assert theme.version == "4.2.1", f"passive-only theme version not fetched: got {theme.version!r}"
