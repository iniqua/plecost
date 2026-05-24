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


# --- AC-1: WordPress application-level protection via faultCode=405 ---
async def test_wp_application_level_protection_no_005_finding(ctx):
    """AC-1: WordPress returns faultCode=405 (method disabled) → no PC-XMLRPC-005, yes PC-XMLRPC-006."""
    wp_blocked_response = """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse><fault><value><struct>
<member><name>faultCode</name><value><int>405</int></value></member>
<member><name>faultString</name><value><string>XML-RPC services are disabled on this site.</string></value></member>
</struct></value></fault></methodResponse>"""

    async with respx.mock:
        respx.get("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(405, text="XML-RPC server accepts POST requests only.")
        )
        respx.post("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(200, text=wp_blocked_response)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await XMLRPCModule().run(ctx, http)

    assert not any(f.id == "PC-XMLRPC-005" for f in ctx.findings), (
        "Must NOT emit PC-XMLRPC-005 when WordPress blocks via faultCode=405"
    )
    assert any(f.id == "PC-XMLRPC-006" for f in ctx.findings), (
        "Must emit PC-XMLRPC-006 (guardrails active) when WP disables methods"
    )
    # Verify the evidence describes WordPress application-level protection
    finding_006 = next(f for f in ctx.findings if f.id == "PC-XMLRPC-006")
    assert "application-level" in finding_006.evidence.get("protection_type", ""), (
        "PC-XMLRPC-006 evidence must describe WordPress application-level protection"
    )


# --- AC-2: Wrong credentials (faultCode=403) → method is functional → PC-XMLRPC-005 ---
async def test_wrong_credentials_emits_005(ctx):
    """AC-2: WordPress returns faultCode=403 (wrong credentials, method functional) → emits PC-XMLRPC-005."""
    wrong_creds_response = """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse><fault><value><struct>
<member><name>faultCode</name><value><int>403</int></value></member>
<member><name>faultString</name><value><string>Incorrect username or password.</string></value></member>
</struct></value></fault></methodResponse>"""

    async with respx.mock:
        respx.get("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(405, text="XML-RPC server accepts POST requests only.")
        )
        respx.post("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(200, text=wrong_creds_response)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await XMLRPCModule().run(ctx, http)

    assert any(f.id == "PC-XMLRPC-005" for f in ctx.findings), (
        "Must emit PC-XMLRPC-005 when credentials fail (faultCode=403 — method is functional)"
    )
    assert not any(f.id == "PC-XMLRPC-006" for f in ctx.findings), (
        "Must NOT emit PC-XMLRPC-006 when faultCode=403 (no brute-force protection)"
    )


# --- AC-3: HTTP 403 from WAF → existing logic unchanged → PC-XMLRPC-006, no PC-XMLRPC-005 ---
async def test_http_403_block_emits_006(ctx):
    """AC-3: WAF returns HTTP 403 on attempt 3 → emits PC-XMLRPC-006, not PC-XMLRPC-005."""
    ok_response = """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse><fault><value><struct>
<member><name>faultCode</name><value><int>403</int></value></member>
<member><name>faultString</name><value><string>Incorrect username or password.</string></value></member>
</struct></value></fault></methodResponse>"""
    waf_block = httpx.Response(403, text="Forbidden")

    call_count = 0

    def side_effect(request):
        nonlocal call_count
        call_count += 1
        if call_count >= 3:
            return waf_block
        return httpx.Response(200, text=ok_response)

    async with respx.mock:
        respx.get("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(405, text="XML-RPC server accepts POST requests only.")
        )
        respx.post("https://example.com/xmlrpc.php").mock(side_effect=side_effect)
        async with PlecostHTTPClient(ctx.opts) as http:
            await XMLRPCModule().run(ctx, http)

    assert not any(f.id == "PC-XMLRPC-005" for f in ctx.findings), (
        "Must NOT emit PC-XMLRPC-005 when WAF blocks via HTTP 403"
    )
    assert any(f.id == "PC-XMLRPC-006" for f in ctx.findings), (
        "Must emit PC-XMLRPC-006 when WAF blocks via HTTP 403"
    )
    finding_006 = next(f for f in ctx.findings if f.id == "PC-XMLRPC-006")
    assert finding_006.evidence.get("protection_type") == "WAF/Rate-limiter", (
        "PC-XMLRPC-006 evidence must say WAF/Rate-limiter for HTTP 403 blocks"
    )


# AC-6: PC-XMLRPC-007 publishing methods

async def test_pc_xmlrpc_007_publishing_methods_detected(ctx):
    """AC-6: system.listMethods includes wp.newPost → PC-XMLRPC-007 LOW."""
    list_methods_response = """<?xml version="1.0"?>
<methodResponse>
  <params><param><value><array><data>
    <value><string>system.listMethods</string></value>
    <value><string>wp.newPost</string></value>
    <value><string>metaWeblog.newPost</string></value>
    <value><string>blogger.newPost</string></value>
    <value><string>pingback.ping</string></value>
  </data></array></value></param></params>
</methodResponse>"""
    async with respx.mock:
        respx.get("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(200, text="XML-RPC")
        )
        respx.post("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(200, text=list_methods_response)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await XMLRPCModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-XMLRPC-007" in ids
    from plecost.models import Severity
    f = next(f for f in ctx.findings if f.id == "PC-XMLRPC-007")
    assert f.severity == Severity.LOW


async def test_pc_xmlrpc_007_not_emitted_when_no_publish_methods(ctx):
    """AC-6: system.listMethods without publish methods → no PC-XMLRPC-007."""
    list_methods_response = """<?xml version="1.0"?>
<methodResponse>
  <params><param><value><array><data>
    <value><string>system.listMethods</string></value>
    <value><string>system.multicall</string></value>
  </data></array></value></param></params>
</methodResponse>"""
    async with respx.mock:
        respx.get("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(200, text="XML-RPC")
        )
        respx.post("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(200, text=list_methods_response)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            await XMLRPCModule().run(ctx, http)
    assert not any(f.id == "PC-XMLRPC-007" for f in ctx.findings)
