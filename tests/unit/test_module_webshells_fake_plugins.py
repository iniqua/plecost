import base64
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Plugin, Severity
from plecost.modules.webshells.detectors.fake_plugins import FakePluginRestDetector


def _make_ctx_with_creds() -> ScanContext:
    opts = ScanOptions(url="https://example.com", credentials=("admin", "secret"))
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    # Add one known legitimate plugin
    ctx.add_plugin(Plugin(
        slug="woocommerce", version="8.0.0", latest_version="8.0.0",
        url="https://example.com/wp-content/plugins/woocommerce/"
    ))
    return ctx


async def test_detects_fake_plugin_not_in_ctx():
    """A plugin returned by REST API but NOT in ctx.plugins is flagged."""
    ctx = _make_ctx_with_creds()
    rest_response = [
        {
            "plugin": "blnmrpb/index.php",
            "name": "blnmrpb",
            "status": "active",
        }
    ]
    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/plugins").mock(
            return_value=httpx.Response(200, json=rest_response)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await FakePluginRestDetector().detect(ctx, http)
    assert any(f.id == "PC-WSH-300" for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


async def test_no_finding_for_known_plugin():
    """A plugin that IS in ctx.plugins must not be flagged."""
    ctx = _make_ctx_with_creds()
    rest_response = [
        {
            "plugin": "woocommerce/woocommerce.php",
            "name": "WooCommerce",
            "status": "active",
        }
    ]
    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/plugins").mock(
            return_value=httpx.Response(200, json=rest_response)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await FakePluginRestDetector().detect(ctx, http)
    assert findings == []


async def test_skips_when_no_credentials():
    """Without credentials, the detector must skip gracefully."""
    opts = ScanOptions(url="https://example.com")
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200, json=[]))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await FakePluginRestDetector().detect(ctx, http)
    assert findings == []


async def test_skips_when_rest_api_returns_401():
    """If REST API returns 401, skip gracefully without error."""
    ctx = _make_ctx_with_creds()
    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/plugins").mock(
            return_value=httpx.Response(401, json={"code": "rest_forbidden"})
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await FakePluginRestDetector().detect(ctx, http)
    assert findings == []
