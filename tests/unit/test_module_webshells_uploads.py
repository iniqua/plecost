import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Severity
from plecost.modules.webshells.detectors.uploads_php import UploadsPhpDetector


def make_ctx():
    c = ScanContext(ScanOptions(url="https://example.com"))
    c.is_wordpress = True
    return c


async def test_reports_php_in_uploads_root():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get("https://example.com/wp-content/uploads/shell.php").mock(
            return_value=httpx.Response(200, text="<?php system($_GET['cmd']); ?>")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            detector = UploadsPhpDetector()
            findings = await detector.detect(ctx, http)
    assert any(f.id == "PC-WSH-100" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


async def test_reports_php_in_dated_subdir():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get("https://example.com/wp-content/uploads/2024/03/backdoor.php").mock(
            return_value=httpx.Response(200, text="webshell")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            detector = UploadsPhpDetector()
            findings = await detector.detect(ctx, http)
    assert any(f.id == "PC-WSH-100" for f in findings)


async def test_no_finding_when_uploads_returns_403():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.route(url__regex=r".*/wp-content/uploads/.*\.php").mock(
            return_value=httpx.Response(403)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            detector = UploadsPhpDetector()
            findings = await detector.detect(ctx, http)
    assert findings == []
