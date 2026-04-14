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


@pytest.mark.asyncio
async def test_passive_does_not_overwrite_version_with_none(ctx):
    """Multiple occurrences of the same slug: version from first match is not lost."""
    html = (
        '<script src="/wp-content/plugins/akismet/js/main.js?ver=5.3.1"></script>'
        '<img src="/wp-content/plugins/akismet/images/logo.png"/>'  # no ?ver=
    )
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.route(url__regex=r".*/readme\.txt").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            mod = PluginsModule(wordlist=[])
            await mod.run(ctx, http)
    plugin = next((p for p in ctx.plugins if p.slug == "akismet"), None)
    assert plugin is not None
    assert plugin.version == "5.3.1", f"version lost: got {plugin.version!r}"


@pytest.mark.asyncio
async def test_passive_upgrades_none_to_version_on_later_occurrence(ctx):
    """If first occurrence has no ?ver= but later one does, version is captured."""
    html = (
        '<img src="/wp-content/plugins/akismet/images/logo.png"/>'  # no ?ver=
        '<script src="/wp-content/plugins/akismet/js/main.js?ver=5.3.1"></script>'
    )
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.route(url__regex=r".*/readme\.txt").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            mod = PluginsModule(wordlist=[])
            await mod.run(ctx, http)
    plugin = next((p for p in ctx.plugins if p.slug == "akismet"), None)
    assert plugin is not None
    assert plugin.version == "5.3.1", f"version not upgraded: got {plugin.version!r}"


@pytest.mark.asyncio
async def test_passive_only_plugin_gets_active_version_check(ctx):
    """Plugin found passively but not in wordlist still gets readme.txt fetch."""
    html = '<img src="/wp-content/plugins/custom-plugin/images/icon.png"/>'
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.get("https://example.com/wp-content/plugins/__plecost_probe__/readme.txt").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://example.com/wp-content/plugins/custom-plugin/readme.txt").mock(
            return_value=httpx.Response(200, text="Stable tag: 2.5.0\n")
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            mod = PluginsModule(wordlist=[])  # custom-plugin NOT in wordlist
            await mod.run(ctx, http)
    plugin = next((p for p in ctx.plugins if p.slug == "custom-plugin"), None)
    assert plugin is not None
    assert plugin.version == "2.5.0", f"passive-only plugin version not fetched: got {plugin.version!r}"
