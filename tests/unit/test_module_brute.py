"""Unit tests for the brute/ subpackage module (AC-9)."""
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, User, Severity
from plecost.modules.brute import BruteModule
from plecost.modules.brute.attackers.xmlrpc import XMLRPCAttacker
from plecost.modules.brute.attackers.wp_login import WPLoginAttacker
from plecost.modules.brute.attackers.xmlrpc import _mask_password as xmlrpc_mask
from plecost.modules.brute.attackers.wp_login import _mask_password as wp_mask


def _make_ctx(brute_force: bool = True, with_users: bool = True) -> ScanContext:
    opts = ScanOptions(url="https://example.com", brute_force=brute_force, brute_force_use_defaults=True)
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


async def test_brute_module_does_nothing_when_brute_force_false():
    """AC-9b: brute_force=False → module makes zero HTTP requests and emits no findings."""
    ctx = _make_ctx(brute_force=False)
    ctx.xmlrpc_accessible = True  # even with xmlrpc accessible, must still skip
    async with respx.mock:
        # Use respx strict mode: any unexpected HTTP call will raise an error,
        # proving that the module made no requests at all.
        # respx.mock in strict mode raises httpx.ConnectError for unmatched routes,
        # so we add NO routes — any request would fail the test.
        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteModule().run(ctx, http)
    # No findings and no HTTP requests made
    assert ctx.findings == [], "brute_force=False must produce zero findings"


async def test_brute_module_skips_when_no_users():
    """AC-9: brute_force=True but no users → no findings."""
    ctx = _make_ctx(brute_force=True, with_users=False)
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteModule().run(ctx, http)
    assert ctx.findings == []


async def test_brute_module_emits_pc_brute_003_when_no_protection_xmlrpc():
    """AC-9: XML-RPC accessible, no rate limiting → PC-BRUTE-003 HIGH."""
    ctx = _make_ctx(brute_force=True)
    ctx.xmlrpc_accessible = True
    # XML-RPC returns 200 with fault (invalid creds, no rate limit, no success)
    async with respx.mock:
        respx.post("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(
                200,
                text="<methodResponse><fault><value><int>403</int></value></fault></methodResponse>"
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-BRUTE-003" in ids
    f = next(f for f in ctx.findings if f.id == "PC-BRUTE-003")
    assert f.severity == Severity.HIGH


async def test_brute_module_no_pc_brute_003_when_xmlrpc_not_accessible():
    """AC-9: BruteModule only tests XML-RPC; if not accessible, no PC-BRUTE-003."""
    ctx = _make_ctx(brute_force=True)
    ctx.xmlrpc_accessible = False  # BruteModule skips all attacks → no PC-BRUTE-003
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-BRUTE-003" not in ids


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


# -----------------------------------------------------------------------
# F-4: XML-RPC success detection — must require <methodResponse>
# -----------------------------------------------------------------------

async def test_xmlrpc_attacker_no_finding_on_200_without_method_response():
    """F-4: 200 response without <methodResponse> must NOT be treated as success."""
    opts = ScanOptions(url="https://example.com", brute_force=True)
    ctx = ScanContext(opts)

    async with respx.mock:
        # 200 without <fault> but also without <methodResponse>
        respx.post("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(200, text="<html>Some page without fault</html>")
        )
        async with PlecostHTTPClient(opts) as http:
            findings = await XMLRPCAttacker().attack(ctx, http, ["admin"], ["wrongpw"])

    assert not any(f.id == "PC-BRUTE-001" for f in findings)


# -----------------------------------------------------------------------
# F-5: Password masking in evidence
# -----------------------------------------------------------------------

def test_mask_password_xmlrpc():
    """F-5: _mask_password in xmlrpc.py masks correctly."""
    assert xmlrpc_mask("password") == "p***d"
    assert xmlrpc_mask("ab") == "a***"
    assert xmlrpc_mask("abc") == "a***"


def test_mask_password_wp_login():
    """F-5: _mask_password in wp_login.py masks correctly."""
    assert wp_mask("password") == "p***d"
    assert wp_mask("ab") == "a***"
    assert wp_mask("abc") == "a***"


async def test_xmlrpc_attacker_credentials_masked_in_evidence():
    """F-5: credentials in evidence must be masked, not plaintext."""
    opts = ScanOptions(url="https://example.com", brute_force=True)
    ctx = ScanContext(opts)

    async with respx.mock:
        respx.post("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(
                200, text="<methodResponse><params>success</params></methodResponse>"
            )
        )
        async with PlecostHTTPClient(opts) as http:
            findings = await XMLRPCAttacker().attack(ctx, http, ["admin"], ["secretpw"])

    brute_finding = next((f for f in findings if f.id == "PC-BRUTE-001"), None)
    assert brute_finding is not None
    creds = brute_finding.evidence.get("credentials", "")
    assert "secretpw" not in creds  # plaintext password must not appear
    assert "s***w" in creds  # masked form must appear


async def test_wp_login_attacker_credentials_masked_in_evidence():
    """F-5: wp-login credentials in evidence must be masked."""
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
            findings = await WPLoginAttacker().attack(ctx, http, ["admin"], ["secretpw"])

    brute_finding = next((f for f in findings if f.id == "PC-BRUTE-002"), None)
    assert brute_finding is not None
    creds = brute_finding.evidence.get("credentials", "")
    assert "secretpw" not in creds
    assert "s***w" in creds


# -----------------------------------------------------------------------
# F-6: Evidence values must be strings
# -----------------------------------------------------------------------

async def test_xmlrpc_attacker_evidence_consecutive_blocks_is_string():
    """F-6: consecutive_blocks in PC-BRUTE-004 evidence must be a string."""
    opts = ScanOptions(url="https://example.com", brute_force=True)
    ctx = ScanContext(opts)

    async with respx.mock:
        respx.post("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(429, text="Too Many Requests")
        )
        async with PlecostHTTPClient(opts) as http:
            findings = await XMLRPCAttacker().attack(ctx, http, ["admin"], ["p1", "p2", "p3", "p4"])

    f = next((f for f in findings if f.id == "PC-BRUTE-004"), None)
    assert f is not None
    assert isinstance(f.evidence.get("consecutive_blocks"), str)


async def test_wp_login_attacker_evidence_consecutive_blocks_is_string():
    """F-6: consecutive_blocks in PC-BRUTE-004 evidence must be a string."""
    opts = ScanOptions(url="https://example.com", brute_force=True)
    ctx = ScanContext(opts)

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(403, text="Forbidden")
        )
        async with PlecostHTTPClient(opts) as http:
            findings = await WPLoginAttacker().attack(ctx, http, ["admin"], ["p1", "p2", "p3", "p4"])

    f = next((f for f in findings if f.id == "PC-BRUTE-004"), None)
    assert f is not None
    assert isinstance(f.evidence.get("consecutive_blocks"), str)


# -----------------------------------------------------------------------
# F-3: Deduplication of PC-BRUTE-004
# -----------------------------------------------------------------------

async def test_brute_module_deduplicates_findings():
    """F-3: BruteModule must not emit duplicate PC-BRUTE-004 findings."""
    ctx = _make_ctx(brute_force=True)
    ctx.xmlrpc_accessible = True

    async with respx.mock:
        respx.post("https://example.com/xmlrpc.php").mock(
            return_value=httpx.Response(429, text="Too Many Requests")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteModule().run(ctx, http)

    brute_004_findings = [f for f in ctx.findings if f.id == "PC-BRUTE-004"]
    assert len(brute_004_findings) <= 1
