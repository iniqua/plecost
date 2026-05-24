"""Unit tests for emergency_scripts module (AC-8)."""
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Severity
from plecost.modules.emergency_scripts import EmergencyScriptsModule


def _make_ctx() -> ScanContext:
    opts = ScanOptions(url="https://example.com")
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    return ctx


async def test_pc_emrg_001_detected_form_signature():
    """AC-8: /emergency.php with <form in body → PC-EMRG-001."""
    ctx = _make_ctx()
    async with respx.mock:
        respx.get("https://example.com/emergency.php").mock(
            return_value=httpx.Response(200, text="<form method='post'><input name='pwd'></form>")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await EmergencyScriptsModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-EMRG-001" in ids
    f = next(f for f in ctx.findings if f.id == "PC-EMRG-001")
    assert f.severity == Severity.HIGH


async def test_pc_emrg_001_detected_wp_hash_password():
    """AC-8: /emergency.php with wp_hash_password( signature → PC-EMRG-001."""
    ctx = _make_ctx()
    async with respx.mock:
        respx.get("https://example.com/emergency.php").mock(
            return_value=httpx.Response(200, text="$hash = wp_hash_password( $pwd );")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await EmergencyScriptsModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-EMRG-001" in ids


async def test_pc_emrg_002_wp_emergency():
    """AC-8: /wp-emergency.php with update_user_meta( → PC-EMRG-002."""
    ctx = _make_ctx()
    async with respx.mock:
        respx.get("https://example.com/wp-emergency.php").mock(
            return_value=httpx.Response(200, text="update_user_meta( $id, 'role', 'admin' );")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await EmergencyScriptsModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-EMRG-002" in ids


async def test_pc_emrg_003_reset():
    """AC-8: /reset.php with <input → PC-EMRG-003."""
    ctx = _make_ctx()
    async with respx.mock:
        respx.get("https://example.com/reset.php").mock(
            return_value=httpx.Response(200, text="<input type='password' name='pwd'>")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await EmergencyScriptsModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-EMRG-003" in ids


async def test_pc_emrg_004_pw_reset():
    """AC-8: /pw-reset.php → PC-EMRG-004."""
    ctx = _make_ctx()
    async with respx.mock:
        respx.get("https://example.com/pw-reset.php").mock(
            return_value=httpx.Response(200, text="<form action='pw-reset.php'>Reset Password</form>")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await EmergencyScriptsModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-EMRG-004" in ids


async def test_pc_emrg_005_emergency_reset():
    """AC-8: /emergency-reset.php → PC-EMRG-005."""
    ctx = _make_ctx()
    async with respx.mock:
        respx.get("https://example.com/emergency-reset.php").mock(
            return_value=httpx.Response(200, text="wp_hash_password   ( $pwd )")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await EmergencyScriptsModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-EMRG-005" in ids


async def test_no_finding_without_php_signature():
    """AC-8: 200 response without PHP signatures → no finding."""
    ctx = _make_ctx()
    async with respx.mock:
        respx.get("https://example.com/emergency.php").mock(
            return_value=httpx.Response(200, text="<html><body>Nothing here</body></html>")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await EmergencyScriptsModule().run(ctx, http)
    assert ctx.findings == []


async def test_no_finding_when_404():
    """AC-8: 404 response → no finding."""
    ctx = _make_ctx()
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await EmergencyScriptsModule().run(ctx, http)
    assert ctx.findings == []


async def test_skips_when_not_wordpress():
    """AC-8: not WordPress → skip."""
    ctx = _make_ctx()
    ctx.is_wordpress = False
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200, text="<form>"))
        async with PlecostHTTPClient(ctx.opts) as http:
            await EmergencyScriptsModule().run(ctx, http)
    assert ctx.findings == []


async def test_signature_only_first_512_bytes():
    """AC-8: signature only in bytes beyond 512 → no finding."""
    ctx = _make_ctx()
    # Put the signature after 512 bytes
    padding = "X" * 600
    body = padding + "<form>"
    async with respx.mock:
        respx.get("https://example.com/emergency.php").mock(
            return_value=httpx.Response(200, text=body)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await EmergencyScriptsModule().run(ctx, http)
    assert ctx.findings == []
