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


@pytest.mark.asyncio
async def test_style_css_version_beats_qver_in_html(ctx):
    """Version: in style.css must override the ?ver= captured from HTML."""
    html = '<link href="/wp-content/themes/mytheme/style.css?ver=1.0"/>'
    css = "/*\nTheme Name: My Theme\nVersion: 3.5.2\nAuthor: Dev\n*/"
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.get("https://example.com/wp-content/themes/__plecost_probe__/style.css").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://example.com/wp-content/themes/mytheme/style.css").mock(
            return_value=httpx.Response(200, text=css)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            mod = ThemesModule(wordlist=["mytheme"])
            await mod.run(ctx, http)
    theme = next((t for t in ctx.themes if t.slug == "mytheme"), None)
    assert theme is not None
    assert theme.version == "3.5.2", f"style.css version should win over ?ver=: got {theme.version!r}"


@pytest.mark.asyncio
async def test_soft_200_server_filters_false_positive_themes(ctx):
    """When server returns 200 for all paths, non-real themes are excluded."""
    fake_body = "WordPress 404 page or mu-plugins output"
    real_css = "/*\nTheme Name: Real Theme\nVersion: 2.0.0\nAuthor: Dev\n*/"
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=""))
        # Probe also returns 200 → baseline_is_soft_200=True
        respx.get("https://example.com/wp-content/themes/__plecost_probe__/style.css").mock(
            return_value=httpx.Response(200, text=fake_body)
        )
        respx.get("https://example.com/wp-content/themes/real-theme/style.css").mock(
            return_value=httpx.Response(200, text=real_css)
        )
        respx.get("https://example.com/wp-content/themes/fake-theme/style.css").mock(
            return_value=httpx.Response(200, text=fake_body)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            mod = ThemesModule(wordlist=["real-theme", "fake-theme"])
            await mod.run(ctx, http)
    slugs = {t.slug for t in ctx.themes}
    assert "real-theme" in slugs, "real theme with valid style.css should be detected"
    assert "fake-theme" not in slugs, "fake theme returning non-CSS content should be excluded"


@pytest.mark.asyncio
async def test_passive_html_theme_kept_when_style_css_unreadable(ctx):
    """Theme in HTML is kept with version=None when style.css returns fake 200.

    If the theme appeared in the page HTML it is considered installed even if
    its style.css is unreadable (blocked or WordPress routing fake 200).
    Only brute-force wordlist candidates are discarded on content mismatch.
    """
    fake_body = "WordPress 404 page or mu-plugins output"
    html = '<link href="/wp-content/themes/hidden-theme/style.css"/>'
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        # Probe returns 200 → baseline_is_soft_200=True
        respx.get("https://example.com/wp-content/themes/__plecost_probe__/style.css").mock(
            return_value=httpx.Response(200, text=fake_body)
        )
        respx.get("https://example.com/wp-content/themes/hidden-theme/style.css").mock(
            return_value=httpx.Response(200, text=fake_body)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            mod = ThemesModule(wordlist=[])  # not in wordlist, passive-only
            await mod.run(ctx, http)
    theme = next((t for t in ctx.themes if t.slug == "hidden-theme"), None)
    assert theme is not None, "HTML-detected theme must be kept even when style.css is unreadable"
    assert theme.version is None, "version should be None when style.css cannot be validated"
