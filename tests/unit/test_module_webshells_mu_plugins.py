import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Severity
from plecost.modules.webshells.detectors.mu_plugins import MuPluginsDetector


async def test_reports_php_in_mu_plugins():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            return_value=httpx.Response(200, text="<?php eval($_POST['x']); ?>")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    assert any(f.id == "PC-WSH-150" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


async def test_no_finding_when_all_mu_plugins_404():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    assert findings == []


async def test_no_finding_on_403():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.route(url__regex=r".*/mu-plugins/.*").mock(return_value=httpx.Response(403))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    assert findings == []


async def test_no_finding_cloudflare_catch_all():
    """Catch-all dinámico: probe_a y probe_b devuelven 200 con tamaños similares."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_a__.php"
        ).mock(return_value=httpx.Response(200, content=b"x" * 18125))
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_b__.php"
        ).mock(return_value=httpx.Response(200, content=b"x" * 18131))
        respx.route(url__regex=r".*").mock(
            return_value=httpx.Response(200, content=b"x" * 18128)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    assert findings == []


async def test_reports_php_despite_catch_all_when_size_differs():
    """Catch-all activo pero un path devuelve respuesta de tamaño muy distinto."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    webshell_body = b"<?php eval($_POST['x']); ?>"  # ~26 bytes, muy distinto de 18125
    async with respx.mock:
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_a__.php"
        ).mock(return_value=httpx.Response(200, content=b"x" * 18125))
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_b__.php"
        ).mock(return_value=httpx.Response(200, content=b"x" * 18131))
        respx.get("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            return_value=httpx.Response(200, content=webshell_body)
        )
        respx.route(url__regex=r".*").mock(
            return_value=httpx.Response(200, content=b"x" * 18128)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    assert any(f.id == "PC-WSH-150" for f in findings)
    hit_urls = [f.evidence["url"] for f in findings if f.id == "PC-WSH-150"]
    assert any("redirect.php" in u for u in hit_urls)
