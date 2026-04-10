import pytest
import respx
import httpx
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions


@pytest.fixture
def opts():
    return ScanOptions(url="https://example.com", timeout=5)


@pytest.mark.asyncio
async def test_get_returns_response(opts):
    async with respx.mock:
        respx.get("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(200, text="<html>wp-login</html>")
        )
        async with PlecostHTTPClient(opts) as client:
            resp = await client.get("https://example.com/wp-login.php")
            assert resp.status_code == 200


@pytest.mark.asyncio
async def test_user_agent_header(opts):
    async with respx.mock:
        route = respx.get("https://example.com/").mock(return_value=httpx.Response(200))
        async with PlecostHTTPClient(opts) as client:
            await client.get("https://example.com/")
        assert route.calls[0].request.headers["user-agent"] == "Plecost/4.0"


@pytest.mark.asyncio
async def test_stealth_uses_random_ua():
    opts = ScanOptions(url="https://example.com", stealth=True)
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200))
        async with PlecostHTTPClient(opts) as client:
            await client.get("https://example.com/")
            ua = client._client.headers["user-agent"]
            assert ua != "Plecost/4.0"
