import pytest
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.rest_api import RESTAPIModule


@pytest.fixture
def ctx():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    return ctx


async def test_detects_rest_link_in_html(ctx):
    html = '<link rel="https://api.w.org/" href="https://example.com/wp-json/"/>'
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await RESTAPIModule().run(ctx, http)
    assert any(f.id == "PC-REST-001" for f in ctx.findings)


async def test_detects_cors_misconfiguration(ctx):
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=""))
        respx.route(url__regex=r".*/oembed.*").mock(return_value=httpx.Response(404))
        respx.get("https://example.com/wp-json/wp/v2/").mock(
            return_value=httpx.Response(200, headers={"access-control-allow-origin": "*"}, text="{}")
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await RESTAPIModule().run(ctx, http)
    assert any(f.id == "PC-REST-003" for f in ctx.findings)


async def test_rest_api_user_enum_handles_exception(ctx):
    """An exception during user enumeration probe must not crash the module."""
    async with respx.mock:
        # Raise a network error for the root page (used by _check_rest_link)
        respx.get("https://example.com/").mock(side_effect=httpx.ConnectError("network error"))
        # Raise for oembed endpoint
        respx.route(url__regex=r".*/oembed.*").mock(side_effect=httpx.ConnectError("network error"))
        # Raise for CORS endpoint
        respx.get("https://example.com/wp-json/wp/v2/").mock(side_effect=httpx.ConnectError("network error"))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404, text="Not Found"))
        async with PlecostHTTPClient(ctx.opts) as http:
            # Should not raise despite all requests failing
            await RESTAPIModule().run(ctx, http)

    rest_findings = [f for f in ctx.findings if f.id.startswith("PC-REST")]
    assert len(rest_findings) == 0


async def test_rest_api_no_finding_on_401(ctx):
    """A 401 response on /wp-json/wp/v2/users must not emit PC-REST-001."""
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(401, text="Unauthorized"))
        respx.route(url__regex=r".*/oembed.*").mock(return_value=httpx.Response(404, text="Not Found"))
        respx.get("https://example.com/wp-json/wp/v2/").mock(
            return_value=httpx.Response(401, text="Unauthorized")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404, text="Not Found"))
        async with PlecostHTTPClient(ctx.opts) as http:
            await RESTAPIModule().run(ctx, http)

    assert not any(f.id == "PC-REST-001" for f in ctx.findings)


async def test_rest_api_cors_wildcard_detected(ctx):
    """GET /wp-json/wp/v2/ with Access-Control-Allow-Origin: * must emit PC-REST-003."""
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=""))
        respx.route(url__regex=r".*/oembed.*").mock(return_value=httpx.Response(404, text="Not Found"))
        respx.get("https://example.com/wp-json/wp/v2/").mock(
            return_value=httpx.Response(
                200,
                headers={"access-control-allow-origin": "*"},
                text="{}",
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404, text="Not Found"))
        async with PlecostHTTPClient(ctx.opts) as http:
            await RESTAPIModule().run(ctx, http)

    assert any(f.id == "PC-REST-003" for f in ctx.findings)
