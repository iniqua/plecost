import pytest
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.fingerprint import FingerprintModule


@pytest.fixture
def ctx():
    return ScanContext(ScanOptions(url="https://example.com"))


@pytest.mark.asyncio
async def test_detects_wordpress_via_meta_generator(ctx):
    html = '<html><head><meta name="generator" content="WordPress 6.4.2"/></head></html>'
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await FingerprintModule().run(ctx, http)
    assert ctx.is_wordpress is True
    assert ctx.wordpress_version == "6.4.2"


@pytest.mark.asyncio
async def test_detects_wordpress_via_readme(ctx):
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="<html></html>"))
        respx.get("https://example.com/readme.html").mock(
            return_value=httpx.Response(200, text="<br/> version 6.5")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await FingerprintModule().run(ctx, http)
    assert ctx.is_wordpress is True
    assert ctx.wordpress_version == "6.5"


@pytest.mark.asyncio
async def test_not_wordpress_if_no_indicators(ctx):
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await FingerprintModule().run(ctx, http)
    assert ctx.is_wordpress is False


@pytest.mark.asyncio
async def test_adds_version_disclosure_finding(ctx):
    html = '<meta name="generator" content="WordPress 6.4.2"/>'
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await FingerprintModule().run(ctx, http)
    assert any(f.id == "PC-FP-001" for f in ctx.findings)


# ---------------------------------------------------------------------------
# _try_feed()
# ---------------------------------------------------------------------------

async def test_detects_via_rss_feed(ctx):
    feed_body = (
        '<?xml version="1.0"?><rss><channel>'
        '<generator>https://wordpress.org/6.4</generator>'
        '</channel></rss>'
    )
    async with respx.mock:
        # homepage: no meta generator, no wp-content
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="<html></html>"))
        # readme.html: 404 → _try_readme fails
        respx.get("https://example.com/readme.html").mock(return_value=httpx.Response(404))
        # feed: 200 with generator tag
        respx.get("https://example.com/feed/").mock(return_value=httpx.Response(200, text=feed_body))
        # catch-all
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404, text="Not Found"))
        async with PlecostHTTPClient(ctx.opts) as http:
            await FingerprintModule().run(ctx, http)
    assert ctx.is_wordpress is True
    assert ctx.wordpress_version == "6.4"


# ---------------------------------------------------------------------------
# _try_rest_api()
# ---------------------------------------------------------------------------

async def test_detects_via_rest_api_namespaces(ctx):
    import json
    api_body = json.dumps({"namespaces": ["wp/v2"], "name": "My Site"})
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="<html></html>"))
        respx.get("https://example.com/readme.html").mock(return_value=httpx.Response(404))
        respx.get("https://example.com/feed/").mock(return_value=httpx.Response(404))
        respx.get("https://example.com/wp-json/").mock(
            return_value=httpx.Response(
                200,
                text=api_body,
                headers={"Content-Type": "application/json"},
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404, text="Not Found"))
        async with PlecostHTTPClient(ctx.opts) as http:
            await FingerprintModule().run(ctx, http)
    assert ctx.is_wordpress is True


async def test_detects_via_rest_api_version(ctx):
    import json
    api_body = json.dumps({"namespaces": ["wp/v2"], "version": "6.4.2"})
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="<html></html>"))
        respx.get("https://example.com/readme.html").mock(return_value=httpx.Response(404))
        respx.get("https://example.com/feed/").mock(return_value=httpx.Response(404))
        respx.get("https://example.com/wp-json/").mock(
            return_value=httpx.Response(
                200,
                text=api_body,
                headers={"Content-Type": "application/json"},
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404, text="Not Found"))
        async with PlecostHTTPClient(ctx.opts) as http:
            await FingerprintModule().run(ctx, http)
    assert ctx.is_wordpress is True
    assert ctx.wordpress_version == "6.4.2"


async def test_rest_api_non_json_not_detected(ctx):
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="<html></html>"))
        respx.get("https://example.com/readme.html").mock(return_value=httpx.Response(404))
        respx.get("https://example.com/feed/").mock(return_value=httpx.Response(404))
        respx.get("https://example.com/wp-json/").mock(
            return_value=httpx.Response(
                200,
                text="<html>Not JSON</html>",
                headers={"Content-Type": "text/html"},
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404, text="Not Found"))
        async with PlecostHTTPClient(ctx.opts) as http:
            await FingerprintModule().run(ctx, http)
    assert ctx.is_wordpress is False


# ---------------------------------------------------------------------------
# _try_wp_paths() — normal server (baseline returns 404)
# ---------------------------------------------------------------------------

async def test_wp_paths_normal_server_wp_login(ctx):
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="<html></html>"))
        respx.get("https://example.com/readme.html").mock(return_value=httpx.Response(404))
        respx.get("https://example.com/feed/").mock(return_value=httpx.Response(404))
        respx.get("https://example.com/wp-json/").mock(return_value=httpx.Response(404))
        # baseline probe → 404 (normal server)
        respx.get("https://example.com/__plecost_probe_nonexistent__/").mock(
            return_value=httpx.Response(404, text="Not Found")
        )
        # wp-login.php → 200 (exists → WordPress confirmed)
        respx.get("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(200, text="<html>Login</html>")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404, text="Not Found"))
        async with PlecostHTTPClient(ctx.opts) as http:
            await FingerprintModule().run(ctx, http)
    assert ctx.is_wordpress is True


async def test_wp_paths_normal_server_not_detected_if_baseline_not_404(ctx):
    """When baseline returns 200 (WAF blanket) and wp-login.php body has no WP keywords,
    WordPress should NOT be detected."""
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="<html></html>"))
        respx.get("https://example.com/readme.html").mock(return_value=httpx.Response(404))
        respx.get("https://example.com/feed/").mock(return_value=httpx.Response(404))
        respx.get("https://example.com/wp-json/").mock(return_value=httpx.Response(404))
        # baseline probe → 200 (WAF blanket — status codes meaningless)
        respx.get("https://example.com/__plecost_probe_nonexistent__/").mock(
            return_value=httpx.Response(200, text="WAF blocked")
        )
        # all WP paths return 200 but body has NO WP keywords
        respx.get("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(200, text="<html>Access Denied</html>")
        )
        respx.get("https://example.com/wp-admin/").mock(
            return_value=httpx.Response(200, text="<html>Access Denied</html>")
        )
        respx.get("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(200, text="<html>Access Denied</html>")
        )
        respx.get("https://example.com/wp-cron.php").mock(
            return_value=httpx.Response(200, text="<html>Access Denied</html>")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404, text="Not Found"))
        async with PlecostHTTPClient(ctx.opts) as http:
            await FingerprintModule().run(ctx, http)
    assert ctx.is_wordpress is False


# ---------------------------------------------------------------------------
# _try_wp_paths() — WAF blanket block (baseline returns 200)
# ---------------------------------------------------------------------------

async def test_wp_paths_waf_detects_via_body_keywords(ctx):
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="<html></html>"))
        respx.get("https://example.com/readme.html").mock(return_value=httpx.Response(404))
        respx.get("https://example.com/feed/").mock(return_value=httpx.Response(404))
        respx.get("https://example.com/wp-json/").mock(return_value=httpx.Response(404))
        # baseline probe → 200 (WAF blanket)
        respx.get("https://example.com/__plecost_probe_nonexistent__/").mock(
            return_value=httpx.Response(200, text="WAF blocked")
        )
        # wp-login.php → 200 with "wp-login" keyword in body
        respx.get("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(200, text='<form id="loginform" action="/wp-login.php">')
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404, text="Not Found"))
        async with PlecostHTTPClient(ctx.opts) as http:
            await FingerprintModule().run(ctx, http)
    assert ctx.is_wordpress is True


async def test_wp_paths_waf_detects_via_link_header(ctx):
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="<html></html>"))
        respx.get("https://example.com/readme.html").mock(return_value=httpx.Response(404))
        respx.get("https://example.com/feed/").mock(return_value=httpx.Response(404))
        respx.get("https://example.com/wp-json/").mock(return_value=httpx.Response(404))
        # baseline probe → 200 (WAF blanket)
        respx.get("https://example.com/__plecost_probe_nonexistent__/").mock(
            return_value=httpx.Response(200, text="WAF blocked")
        )
        # wp-login.php → 200 with Link header pointing to api.w.org
        respx.get("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(
                200,
                text="<html>Access Denied</html>",
                headers={"Link": '<https://api.w.org/>; rel="https://api.w.org/"'},
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404, text="Not Found"))
        async with PlecostHTTPClient(ctx.opts) as http:
            await FingerprintModule().run(ctx, http)
    assert ctx.is_wordpress is True
