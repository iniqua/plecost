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
