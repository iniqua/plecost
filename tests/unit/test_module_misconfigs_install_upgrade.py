"""
SPEC LOCK tests for MisconfigsModule — install.php (AC-2) and upgrade.php (AC-3).

Each test would FAIL if the implementation had the specific bug it guards against.
"""
import respx
import httpx
import pytest
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Severity
from plecost.modules.misconfigs import MisconfigsModule


@pytest.fixture
def ctx():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    return ctx


# -----------------------------------------------------------------------
# AC-2: install.php — PC-MCFG-007
# Rule: only emit if body[:4096] contains <input name="weblog_title"
# -----------------------------------------------------------------------

# AC-2: body contains the installation form → MUST emit PC-MCFG-007
async def test_ac2_install_php_with_weblog_title_form_emits_finding(ctx):
    """AC-2: install.php body contains <input name="weblog_title" → PC-MCFG-007 MEDIUM."""
    install_body = (
        '<html><body>'
        '<form action="install.php" method="post">'
        '<input name="weblog_title" type="text" value="">'
        '<input name="admin_email" type="email" value="">'
        '</form>'
        '</body></html>'
    )
    async with respx.mock:
        respx.get("https://example.com/wp-admin/install.php").mock(
            return_value=httpx.Response(200, text=install_body)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await MisconfigsModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-MCFG-007" in ids, (
        "AC-2: install.php with weblog_title form must emit PC-MCFG-007"
    )
    f = next(f for f in ctx.findings if f.id == "PC-MCFG-007")
    assert f.severity == Severity.MEDIUM, "AC-2: PC-MCFG-007 must have MEDIUM severity"


# AC-2: body does NOT contain the form → must NOT emit PC-MCFG-007
async def test_ac2_install_php_already_installed_no_finding(ctx):
    """AC-2: install.php returns 'Already installed' without the form → NO PC-MCFG-007."""
    already_installed_body = (
        '<html><body>'
        '<h1>Already Installed</h1>'
        '<p>WordPress has already been installed. Log in below or go back to your site.</p>'
        '</body></html>'
    )
    async with respx.mock:
        respx.get("https://example.com/wp-admin/install.php").mock(
            return_value=httpx.Response(200, text=already_installed_body)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await MisconfigsModule().run(ctx, http)
    assert not any(f.id == "PC-MCFG-007" for f in ctx.findings), (
        "AC-2: 'Already installed' page without weblog_title must NOT emit PC-MCFG-007"
    )


# AC-2: body contains weblog_title but only in first 4096 bytes → emits finding
async def test_ac2_install_php_form_within_4096_bytes_emits_finding(ctx):
    """AC-2: weblog_title within first 4096 bytes of body → PC-MCFG-007 emitted."""
    # Form near the beginning — well within the 4096-byte window
    install_body = (
        '<html><head><title>WordPress › Installation</title></head><body>'
        '<form id="setup" method="post" action="install.php?step=2">'
        '<input name="weblog_title" type="text" value="" size="25">'
        '</form>'
        '</body></html>'
    )
    assert len(install_body) < 4096, "Test precondition: body is smaller than 4096 bytes"
    async with respx.mock:
        respx.get("https://example.com/wp-admin/install.php").mock(
            return_value=httpx.Response(200, text=install_body)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await MisconfigsModule().run(ctx, http)
    assert any(f.id == "PC-MCFG-007" for f in ctx.findings), (
        "AC-2: weblog_title in first 4096 bytes → PC-MCFG-007 must be emitted"
    )


# AC-2: install.php returns 404 → NO finding
async def test_ac2_install_php_404_no_finding(ctx):
    """AC-2: install.php returns 404 → no PC-MCFG-007."""
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await MisconfigsModule().run(ctx, http)
    assert not any(f.id == "PC-MCFG-007" for f in ctx.findings)


# AC-2: install.php returns login redirect page (no form, no weblog_title) → NO finding
async def test_ac2_install_php_login_redirect_no_finding(ctx):
    """AC-2: install.php redirects to login page (no installation form) → NO PC-MCFG-007."""
    login_redirect_body = (
        '<html><body>'
        '<p>You are already logged in.</p>'
        '<a href="wp-login.php">Log in</a>'
        '</body></html>'
    )
    async with respx.mock:
        respx.get("https://example.com/wp-admin/install.php").mock(
            return_value=httpx.Response(200, text=login_redirect_body)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await MisconfigsModule().run(ctx, http)
    assert not any(f.id == "PC-MCFG-007" for f in ctx.findings), (
        "AC-2: install.php with login redirect but no installation form must NOT emit PC-MCFG-007"
    )


# -----------------------------------------------------------------------
# AC-3: upgrade.php — PC-MCFG-008
# Rule: only emit if body[:4096] contains <form action="upgrade.php" or do_upgrade
# -----------------------------------------------------------------------

# AC-3: body contains <form action="upgrade.php" → MUST emit PC-MCFG-008
async def test_ac3_upgrade_php_with_form_action_emits_finding(ctx):
    """AC-3: upgrade.php body contains <form action="upgrade.php" → PC-MCFG-008 MEDIUM."""
    upgrade_body = (
        '<html><body>'
        '<h1>WordPress Update</h1>'
        '<p>Click the button below to update the database.</p>'
        '<form action="upgrade.php?step=1" method="post">'
        '<input type="submit" value="Update WordPress Database">'
        '</form>'
        '</body></html>'
    )
    async with respx.mock:
        respx.get("https://example.com/wp-admin/upgrade.php").mock(
            return_value=httpx.Response(200, text=upgrade_body)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await MisconfigsModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-MCFG-008" in ids, (
        "AC-3: upgrade.php with form action='upgrade.php' must emit PC-MCFG-008"
    )
    f = next(f for f in ctx.findings if f.id == "PC-MCFG-008")
    assert f.severity == Severity.MEDIUM, "AC-3: PC-MCFG-008 must have MEDIUM severity"


# AC-3: body contains do_upgrade → MUST emit PC-MCFG-008
async def test_ac3_upgrade_php_with_do_upgrade_link_emits_finding(ctx):
    """AC-3: upgrade.php body contains do_upgrade → PC-MCFG-008 MEDIUM."""
    upgrade_body = (
        '<html><body>'
        '<h1>WordPress Update</h1>'
        '<a href="upgrade.php?step=1&do_upgrade=true">Run the Upgrader</a>'
        '</body></html>'
    )
    async with respx.mock:
        respx.get("https://example.com/wp-admin/upgrade.php").mock(
            return_value=httpx.Response(200, text=upgrade_body)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await MisconfigsModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-MCFG-008" in ids, (
        "AC-3: upgrade.php with do_upgrade must emit PC-MCFG-008"
    )


# AC-3: body contains "No upgrade required" without the form → must NOT emit
async def test_ac3_upgrade_php_no_upgrade_required_no_finding(ctx):
    """AC-3: upgrade.php returns 'No upgrade required' without form → NO PC-MCFG-008."""
    no_upgrade_body = (
        '<html><body>'
        '<h1>No upgrade required</h1>'
        '<p>Your WordPress database is already up-to-date!</p>'
        '<a href="../wp-admin/">Go to the WordPress admin panel</a>'
        '</body></html>'
    )
    async with respx.mock:
        respx.get("https://example.com/wp-admin/upgrade.php").mock(
            return_value=httpx.Response(200, text=no_upgrade_body)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await MisconfigsModule().run(ctx, http)
    assert not any(f.id == "PC-MCFG-008" for f in ctx.findings), (
        "AC-3: 'No upgrade required' page without form must NOT emit PC-MCFG-008"
    )


# AC-3: upgrade.php returns 404 → NO finding
async def test_ac3_upgrade_php_404_no_finding(ctx):
    """AC-3: upgrade.php returns 404 → no PC-MCFG-008."""
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await MisconfigsModule().run(ctx, http)
    assert not any(f.id == "PC-MCFG-008" for f in ctx.findings)


# AC-3: body is a generic HTML page with no upgrade markers → NO finding
async def test_ac3_upgrade_php_generic_html_no_finding(ctx):
    """AC-3: upgrade.php returns generic HTML with no upgrade form or do_upgrade → NO PC-MCFG-008."""
    generic_body = (
        '<html><body>'
        '<p>Access denied. You must be logged in as an administrator.</p>'
        '</body></html>'
    )
    async with respx.mock:
        respx.get("https://example.com/wp-admin/upgrade.php").mock(
            return_value=httpx.Response(200, text=generic_body)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await MisconfigsModule().run(ctx, http)
    assert not any(f.id == "PC-MCFG-008" for f in ctx.findings), (
        "AC-3: generic HTML without upgrade form or do_upgrade must NOT emit PC-MCFG-008"
    )
