import pytest
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Severity
from plecost.modules.webshells.detectors.known_paths import KnownPathsDetector


@pytest.fixture
def ctx():
    c = ScanContext(ScanOptions(url="https://example.com"))
    c.is_wordpress = True
    return c


async def test_reports_finding_when_known_path_returns_200(ctx):
    """A known webshell path returning 200 with text/html must emit PC-WSH-001."""
    async with respx.mock:
        # Preflight: random path returns 404 (not a catch-all site)
        respx.get("https://example.com/plecost-probe-nonexistent.php").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://example.com/wp-content/uploads/shell.php").mock(
            return_value=httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text="<html>shell output</html>",
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            detector = KnownPathsDetector()
            findings = await detector.detect(ctx, http)
    assert any(f.id == "PC-WSH-001" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


async def test_no_finding_when_all_paths_404(ctx):
    """No findings if all probed paths return 404."""
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            detector = KnownPathsDetector()
            findings = await detector.detect(ctx, http)
    assert findings == []


async def test_no_finding_on_image_content_type(ctx):
    """A known path returning 200 with image/jpeg must NOT emit a finding (FP guard)."""
    async with respx.mock:
        respx.get("https://example.com/plecost-probe-nonexistent.php").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://example.com/wp-content/uploads/shell.php").mock(
            return_value=httpx.Response(
                200,
                headers={"content-type": "image/jpeg"},
                content=b"\xff\xd8\xff",
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            detector = KnownPathsDetector()
            findings = await detector.detect(ctx, http)
    assert findings == []


async def test_skips_when_catch_all_site(ctx):
    """If the site returns 200 for all paths (catch-all), skip to avoid mass FPs."""
    async with respx.mock:
        # Preflight returns 200 — catch-all site
        respx.get("https://example.com/plecost-probe-nonexistent.php").mock(
            return_value=httpx.Response(200, text="<html>404 page</html>")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200, text="page"))
        async with PlecostHTTPClient(ctx.opts) as http:
            detector = KnownPathsDetector()
            findings = await detector.detect(ctx, http)
    assert findings == []
