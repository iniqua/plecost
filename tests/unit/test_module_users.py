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
