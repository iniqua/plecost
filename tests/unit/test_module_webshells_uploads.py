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
    # deep=True is required: fast mode only scans the current year; 2024 paths need deep mode
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
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


async def test_no_finding_cloudflare_catch_all():
    """Cloudflare/Hugo catch-all: todos los paths devuelven 200 con tamaño similar."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    large_body_a = b"x" * 18125
    large_body_b = b"x" * 18131  # +6 bytes por CF-Ray ID
    async with respx.mock:
        respx.get(
            "https://example.com/wp-content/uploads/__plecost_probe_a__.php"
        ).mock(return_value=httpx.Response(200, content=large_body_a))
        respx.get(
            "https://example.com/wp-content/uploads/__plecost_probe_b__.php"
        ).mock(return_value=httpx.Response(200, content=large_body_b))
        # Todos los paths del wordlist devuelven tamaño similar al catch-all
        respx.route(url__regex=r".*").mock(
            return_value=httpx.Response(200, content=b"x" * 18128)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await UploadsPhpDetector().detect(ctx, http)
    assert findings == []


async def test_reports_php_despite_catch_all_when_size_differs():
    """Catch-all activo pero un path devuelve respuesta de tamaño muy distinto (webshell real)."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    webshell_body = b"<?php system($_GET['c']); ?>"  # ~27 bytes, muy distinto de 18125
    async with respx.mock:
        respx.get(
            "https://example.com/wp-content/uploads/__plecost_probe_a__.php"
        ).mock(return_value=httpx.Response(200, content=b"x" * 18125))
        respx.get(
            "https://example.com/wp-content/uploads/__plecost_probe_b__.php"
        ).mock(return_value=httpx.Response(200, content=b"x" * 18131))
        respx.get("https://example.com/wp-content/uploads/shell.php").mock(
            return_value=httpx.Response(200, content=webshell_body)
        )
        # El resto del wordlist devuelve el HTML catch-all
        respx.route(url__regex=r".*").mock(
            return_value=httpx.Response(200, content=b"x" * 18128)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await UploadsPhpDetector().detect(ctx, http)
    assert any(f.id == "PC-WSH-100" for f in findings)
    hit_urls = [f.evidence["url"] for f in findings if f.id == "PC-WSH-100"]
    assert any("shell.php" in u for u in hit_urls)
