"""Unit tests for the brute/ subpackage module (AC-9)."""
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, User, Severity
from plecost.modules.brute import BruteModule
from plecost.modules.brute.attackers.xmlrpc import XMLRPCAttacker
from plecost.modules.brute.attackers.wp_login import WPLoginAttacker


def _make_ctx(brute_force: bool = True, with_users: bool = True) -> ScanContext:
    opts = ScanOptions(url="https://example.com", brute_force=brute_force)
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    if with_users:
        ctx.add_user(User(id=1, username="admin", display_name="Admin", source="rest_api"))
    return ctx


# -----------------------------------------------------------------------
# BruteModule integration tests
# -----------------------------------------------------------------------

async def test_brute_module_skips_when_brute_force_false():
    """AC-9: brute_force=False → module must do nothing."""
    ctx = _make_ctx(brute_force=False)
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteModule().run(ctx, http)
    assert ctx.findings == []


async def test_brute_module_skips_when_no_users():
    """AC-9: brute_force=True but no users → no findings."""
    ctx = _make_ctx(brute_force=True, with_users=False)
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteModule().run(ctx, http)
    assert ctx.findings == []


async def test_brute_module_emits_pc_brute_003_when_no_protection():
    """AC-9: no rate limiting detected → PC-BRUTE-003 HIGH."""
    ctx = _make_ctx(brute_force=True)
    ctx.xmlrpc_accessible = False  # skip XML-RPC attacker
    # wp-login returns 200 with error page (not success, not rate limit)
    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(200, text="<html>ERROR: Invalid username</html>")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-BRUTE-003" in ids
    f = next(f for f in ctx.findings if f.id == "PC-BRUTE-003")
    assert f.severity == Severity.HIGH


async def test_brute_module_emits_pc_brute_002_on_success():
    """AC-9: wp-login success → PC-BRUTE-002 CRITICAL."""
    ctx = _make_ctx(brute_force=True)
    ctx.xmlrpc_accessible = False
    # Simulate successful login: redirect to /wp-admin/
    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(
                302,
                headers={"location": "/wp-admin/"},
                text=""
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-BRUTE-002" in ids
    f = next(f for f in ctx.findings if f.id == "PC-BRUTE-002")
    assert f.severity == Severity.CRITICAL


# -----------------------------------------------------------------------
# XMLRPCAttacker unit tests
# -----------------------------------------------------------------------

async def test_xmlrpc_attacker_pc_brute_001_on_success():
    """AC-9: XML-RPC success (no <fault>) → PC-BRUTE-001 CRITICAL."""
    opts = ScanOptions(url="https://example.com", brute_force=True)
    ctx = ScanContext(opts)
    ctx.is_wordpress = True

    async with respx.mock:
        respx.post("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(200, text="<methodResponse><params>success</params></methodResponse>")
        )
        async with PlecostHTTPClient(opts) as http:
            findings = await XMLRPCAttacker().attack(ctx, http, ["admin"], ["password"])

    ids = [f.id for f in findings]
    assert "PC-BRUTE-001" in ids
    f = next(f for f in findings if f.id == "PC-BRUTE-001")
    assert f.severity == Severity.CRITICAL


async def test_xmlrpc_attacker_pc_brute_004_on_rate_limit():
    """AC-9: 3 consecutive 429 → PC-BRUTE-004 INFO."""
    opts = ScanOptions(url="https://example.com", brute_force=True)
    ctx = ScanContext(opts)
    ctx.is_wordpress = True

    async with respx.mock:
        respx.post("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(429, text="Too Many Requests")
        )
        async with PlecostHTTPClient(opts) as http:
            findings = await XMLRPCAttacker().attack(ctx, http, ["admin"], ["p1", "p2", "p3", "p4"])

    ids = [f.id for f in findings]
    assert "PC-BRUTE-004" in ids


async def test_xmlrpc_attacker_no_finding_on_fault():
    """AC-9: XML-RPC fault (invalid credentials) → no PC-BRUTE-001."""
    opts = ScanOptions(url="https://example.com", brute_force=True)
    ctx = ScanContext(opts)

    async with respx.mock:
        respx.post("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(200, text="<fault><value><int>403</int></value></fault>")
        )
        async with PlecostHTTPClient(opts) as http:
            findings = await XMLRPCAttacker().attack(ctx, http, ["admin"], ["wrongpw"])

    assert not any(f.id == "PC-BRUTE-001" for f in findings)


# -----------------------------------------------------------------------
# WPLoginAttacker unit tests
# -----------------------------------------------------------------------

async def test_wp_login_attacker_success_via_cookie():
    """AC-9: wordpress_logged_in_ cookie → PC-BRUTE-002 CRITICAL."""
    opts = ScanOptions(url="https://example.com", brute_force=True)
    ctx = ScanContext(opts)

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(
                200,
                headers={"set-cookie": "wordpress_logged_in_abc=xyz; path=/"},
                text="logged in"
            )
        )
        async with PlecostHTTPClient(opts) as http:
            findings = await WPLoginAttacker().attack(ctx, http, ["admin"], ["password"])

    ids = [f.id for f in findings]
    assert "PC-BRUTE-002" in ids


async def test_wp_login_attacker_success_via_redirect():
    """AC-9: redirect to /wp-admin/ → PC-BRUTE-002."""
    opts = ScanOptions(url="https://example.com", brute_force=True)
    ctx = ScanContext(opts)

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(
                302,
                headers={"location": "https://example.com/wp-admin/"},
                text=""
            )
        )
        async with PlecostHTTPClient(opts) as http:
            findings = await WPLoginAttacker().attack(ctx, http, ["admin"], ["password"])

    ids = [f.id for f in findings]
    assert "PC-BRUTE-002" in ids


async def test_wp_login_attacker_rate_limit_via_403():
    """AC-9: 3 consecutive 403 → PC-BRUTE-004 INFO."""
    opts = ScanOptions(url="https://example.com", brute_force=True)
    ctx = ScanContext(opts)

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(403, text="Forbidden")
        )
        async with PlecostHTTPClient(opts) as http:
            findings = await WPLoginAttacker().attack(ctx, http, ["admin"], ["p1", "p2", "p3", "p4"])

    ids = [f.id for f in findings]
    assert "PC-BRUTE-004" in ids
