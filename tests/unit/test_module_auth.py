import pytest
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.auth import AuthModule


@pytest.fixture
def ctx_with_creds():
    ctx = ScanContext(ScanOptions(url="https://example.com", credentials=("admin", "secret")))
    ctx.is_wordpress = True
    return ctx


@pytest.fixture
def ctx_no_creds():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    return ctx


@pytest.mark.asyncio
async def test_skips_if_no_credentials(ctx_no_creds):
    async with respx.mock:
        async with PlecostHTTPClient(ctx_no_creds.opts) as http:
            await AuthModule().run(ctx_no_creds, http)
    assert not any(f.module == "auth" for f in ctx_no_creds.findings)


@pytest.mark.asyncio
async def test_detects_open_registration(ctx_with_creds):
    async with respx.mock:
        # Register more specific routes first
        respx.route(url__regex=r".*wp-login\.php\?action=register.*").mock(
            return_value=httpx.Response(200, text="<input name='user_login'/>")
        )
        respx.post("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(302, headers={"location": "/wp-admin/"})
        )
        respx.get("https://example.com/wp-admin/").mock(
            return_value=httpx.Response(200, text="<html>Dashboard</html>")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx_with_creds.opts) as http:
            await AuthModule().run(ctx_with_creds, http)
    # Auth module should have run without crashing
    assert any(f.id == "PC-AUTH-002" for f in ctx_with_creds.findings)
