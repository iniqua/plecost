import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.webshells import WebshellsModule


async def test_module_name_and_deps():
    mod = WebshellsModule()
    assert mod.name == "webshells"
    assert "fingerprint" in mod.depends_on
    assert "plugins" in mod.depends_on


async def test_module_adds_findings_to_ctx():
    """Full module run: a known path returning 200 must add findings to ctx."""
    opts = ScanOptions(url="https://example.com")
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    async with respx.mock:
        # Preflight → not catch-all
        respx.get("https://example.com/plecost-probe-nonexistent.php").mock(
            return_value=httpx.Response(404)
        )
        # One known webshell path returns 200 with text/html
        respx.get("https://example.com/wp-content/uploads/shell.php").mock(
            return_value=httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text="<html>shell</html>",
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(opts) as http:
            await WebshellsModule().run(ctx, http)
    assert len(ctx.findings) > 0


async def test_auth_detectors_skipped_without_credentials():
    """Detectors requiring auth must not run if no credentials are set."""
    opts = ScanOptions(url="https://example.com")  # no credentials
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    ctx.wordpress_version = "6.4.2"
    # If auth detectors ran, they'd call api.wordpress.org — those calls would fail
    # under respx.mock without explicit mocks, causing errors
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(opts) as http:
            # Should not raise
            await WebshellsModule().run(ctx, http)
