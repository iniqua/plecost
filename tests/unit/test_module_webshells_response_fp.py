import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Severity
from plecost.modules.webshells.detectors.response_fp import ResponseFingerprintDetector


async def test_detects_china_chopper_blank_200():
    """China Chopper returns exactly empty body with 200 OK."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get("https://example.com/plecost-probe-nonexistent.php").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://example.com/wp-content/uploads/shell.php").mock(
            return_value=httpx.Response(200, content=b"", headers={"content-type": "text/html"})
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await ResponseFingerprintDetector().detect(ctx, http)
    assert any(f.id == "PC-WSH-200" for f in findings)
    assert any("china_chopper" in f.evidence.get("family", "") for f in findings)


async def test_detects_wso_form_parameters():
    """WSO shell has a form with fields: a, c, p1, p2, p3, charset."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    wso_html = '<form><input name="a"><input name="c"><input name="charset"></form>'
    async with respx.mock:
        respx.get("https://example.com/plecost-probe-nonexistent.php").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://example.com/wp-content/uploads/wso.php").mock(
            return_value=httpx.Response(200, text=wso_html, headers={"content-type": "text/html"})
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await ResponseFingerprintDetector().detect(ctx, http)
    assert any("wso" in f.evidence.get("family", "") for f in findings)


async def test_detects_b374k_string():
    """b374k shell contains the string 'b374k' in its body.
    Uses shell.php (present in fast wordlist) to trigger the body fingerprint."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get("https://example.com/plecost-probe-nonexistent.php").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://example.com/wp-content/uploads/shell.php").mock(
            return_value=httpx.Response(200, text="<html>b374k shell v3.2</html>",
                                        headers={"content-type": "text/html"})
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await ResponseFingerprintDetector().detect(ctx, http)
    assert any("b374k" in f.evidence.get("family", "") for f in findings)


async def test_detects_polyglot_image_php():
    """A file starting with GIF89a but containing <?php is a polyglot webshell."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    polyglot = b"GIF89a<?php system($_GET['cmd']); ?>"
    async with respx.mock:
        respx.get("https://example.com/plecost-probe-nonexistent.php").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://example.com/wp-content/uploads/image.php").mock(
            return_value=httpx.Response(200, content=polyglot,
                                        headers={"content-type": "text/html"})
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await ResponseFingerprintDetector().detect(ctx, http)
    assert any("polyglot" in f.evidence.get("family", "") for f in findings)


async def test_no_finding_on_normal_html():
    """A 200 response with normal WordPress HTML must not trigger a finding."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    normal_html = "<html><head><title>My Blog</title></head><body><p>Hello</p></body></html>"
    async with respx.mock:
        respx.get("https://example.com/plecost-probe-nonexistent.php").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://example.com/wp-content/uploads/cache.php").mock(
            return_value=httpx.Response(200, text=normal_html,
                                        headers={"content-type": "text/html"})
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await ResponseFingerprintDetector().detect(ctx, http)
    # Normal HTML with no webshell signatures must produce no findings
    assert findings == []
