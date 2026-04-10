import pytest
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.users import UsersModule


@pytest.fixture
def ctx():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    return ctx


@pytest.mark.asyncio
async def test_enumerates_users_via_rest_api(ctx):
    users_json = '[{"id":1,"name":"admin","slug":"admin"}]'
    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(200, text=users_json)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)
    assert any(u.username == "admin" for u in ctx.users)
    assert any(f.id == "PC-USR-001" for f in ctx.findings)


@pytest.mark.asyncio
async def test_rest_api_exposed_adds_finding(ctx):
    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(200, text='[{"id":1,"slug":"editor","name":"Editor User"}]')
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)
    rest_findings = [f for f in ctx.findings if f.id == "PC-USR-001"]
    assert len(rest_findings) == 1
    assert rest_findings[0].severity.value == "MEDIUM"


@pytest.mark.asyncio
async def test_rest_api_returns_html_no_finding(ctx):
    """When REST API returns HTML (restricted), no finding should be added and no exception raised."""
    html_body = "<html><body><h1>Unauthorized</h1></body></html>"
    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(200, text=html_body, headers={"content-type": "text/html"})
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)
    rest_findings = [f for f in ctx.findings if f.id == "PC-USR-001"]
    assert len(rest_findings) == 0
    assert len(ctx.users) == 0


@pytest.mark.asyncio
async def test_author_archives_enumerates_users(ctx):
    """Author archive 301 redirects expose usernames."""
    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(403)
        )
        respx.get("https://example.com/?author=1").mock(
            return_value=httpx.Response(
                301,
                headers={"location": "https://example.com/author/johndoe/"},
            )
        )
        respx.route(url__regex=r".*author=.*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)
    assert any(u.username == "johndoe" for u in ctx.users)
    assert any(f.id == "PC-USR-002" for f in ctx.findings)
