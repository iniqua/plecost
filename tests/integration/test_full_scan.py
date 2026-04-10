import pytest
import respx
import httpx
from plecost.scanner import Scanner
from plecost.models import ScanOptions, Severity

WP_HOMEPAGE = '''
<html>
<head>
<meta name="generator" content="WordPress 6.4.2"/>
<link rel="stylesheet" href="/wp-content/plugins/woocommerce/assets/css/main.css?ver=8.0.0"/>
</head>
<body></body>
</html>
'''


@pytest.mark.asyncio
async def test_full_scan_detects_wordpress_and_plugin():
    opts = ScanOptions(
        url="https://example.com",
        modules=["fingerprint", "plugins", "waf"],
    )
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=WP_HOMEPAGE))
        respx.route(url__regex=r".*/readme\.txt").mock(return_value=httpx.Response(404))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        scanner = Scanner(opts)
        result = await scanner.run()
    assert result.is_wordpress is True
    assert result.wordpress_version == "6.4.2"
    assert any(p.slug == "woocommerce" for p in result.plugins)
    assert any(f.id == "PC-FP-001" for f in result.findings)


@pytest.mark.asyncio
async def test_full_scan_with_misconfigs():
    opts = ScanOptions(url="https://example.com", modules=["fingerprint", "misconfigs"])
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=WP_HOMEPAGE))
        respx.get("https://example.com/wp-config.php").mock(
            return_value=httpx.Response(200, text="<?php define('DB_PASSWORD', 'secret');")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        scanner = Scanner(opts)
        result = await scanner.run()
    assert any(f.id == "PC-MCFG-001" for f in result.findings)
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
