import pytest
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.xmlrpc import XMLRPCModule


@pytest.fixture
def ctx():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    return ctx


@pytest.mark.asyncio
async def test_detects_xmlrpc_accessible(ctx):
    async with respx.mock:
        respx.get("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(405, text="XML-RPC server accepts POST requests only.")
        )
        respx.post("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(200, text="<methodResponse><params></params></methodResponse>")
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await XMLRPCModule().run(ctx, http)
    assert any(f.id == "PC-XMLRPC-001" for f in ctx.findings)


@pytest.mark.asyncio
async def test_detects_pingback(ctx):
    methods_response = """<methodResponse><params><param><value><array><data>
    <value><string>pingback.ping</string></value>
    <value><string>system.listMethods</string></value>
    </data></array></value></param></params></methodResponse>"""
    async with respx.mock:
        respx.get("https://example.com/xmlrpc.php").mock(return_value=httpx.Response(200, text=""))
        respx.post("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(200, text=methods_response)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await XMLRPCModule().run(ctx, http)
    assert any(f.id == "PC-XMLRPC-002" for f in ctx.findings)


@pytest.mark.asyncio
async def test_no_xmlrpc_if_404(ctx):
    async with respx.mock:
        respx.get("https://example.com/xmlrpc.php").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await XMLRPCModule().run(ctx, http)
    assert not any(f.id.startswith("PC-XMLRPC") for f in ctx.findings)
