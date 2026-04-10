import pytest
import respx
import httpx
from plecost.scanner import Scanner
from plecost.models import ScanOptions, ScanResult


@pytest.mark.asyncio
async def test_scanner_returns_scan_result():
    opts = ScanOptions(url="https://example.com", modules=["fingerprint", "waf"])
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        scanner = Scanner(opts)
        result = await scanner.run()
    assert isinstance(result, ScanResult)
    assert result.url == "https://example.com"
    assert result.scan_id != ""
    assert result.duration_seconds >= 0


@pytest.mark.asyncio
async def test_scanner_detects_wordpress():
    opts = ScanOptions(url="https://example.com", modules=["fingerprint"])
    html = '<meta name="generator" content="WordPress 6.4.2"/>'
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        scanner = Scanner(opts)
        result = await scanner.run()
    assert result.is_wordpress is True
    assert result.wordpress_version == "6.4.2"


def test_scanner_api_is_importable():
    from plecost import Scanner, ScanOptions
    assert Scanner is not None
    assert ScanOptions is not None
