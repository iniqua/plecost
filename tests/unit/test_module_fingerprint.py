import pytest
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.fingerprint import FingerprintModule


@pytest.fixture
def ctx():
    return ScanContext(ScanOptions(url="https://example.com"))


@pytest.mark.asyncio
async def test_detects_wordpress_via_meta_generator(ctx):
    html = '<html><head><meta name="generator" content="WordPress 6.4.2"/></head></html>'
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await FingerprintModule().run(ctx, http)
    assert ctx.is_wordpress is True
    assert ctx.wordpress_version == "6.4.2"


@pytest.mark.asyncio
async def test_detects_wordpress_via_readme(ctx):
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="<html></html>"))
        respx.get("https://example.com/readme.html").mock(
            return_value=httpx.Response(200, text="<br/> version 6.5")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await FingerprintModule().run(ctx, http)
    assert ctx.is_wordpress is True
    assert ctx.wordpress_version == "6.5"


@pytest.mark.asyncio
async def test_not_wordpress_if_no_indicators(ctx):
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await FingerprintModule().run(ctx, http)
    assert ctx.is_wordpress is False


@pytest.mark.asyncio
async def test_adds_version_disclosure_finding(ctx):
    html = '<meta name="generator" content="WordPress 6.4.2"/>'
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await FingerprintModule().run(ctx, http)
    assert any(f.id == "PC-FP-001" for f in ctx.findings)
