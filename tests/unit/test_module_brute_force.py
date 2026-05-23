"""
Tests for BruteForceModule.

Spec lock references:
  AC-8:  Only activates with brute_force=True or module_options["brute_force"]["enabled"]="true"
  AC-9:  ~60 internal + 7 dynamic variants
  AC-10: External wordlist via asyncio.to_thread; limits 10k/50k; combine flag
  AC-11: Primary: wordpress_logged_in_ cookie; fallback: redirect to /wp-admin/
  AC-12: _check_2fa() called in login flow; HIGH/7.5 with 2FA, CRITICAL/9.8 without
  AC-13: 429/403 stop; 200+block-string stop; ConnectError stop
  AC-14: Single PC-BRU-001; credentials as list; masked passwords
  AC-15: Semaphore(1); delay outside sem; report_progress in finally
"""
import os
import tempfile
import pytest
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, User
from plecost.modules.brute_force import BruteForceModule, _mask_password, _build_dynamic_variants


BASE = "https://example.com"
LOGIN_URL = f"{BASE}/wp-login.php"


@pytest.fixture
def ctx_with_user():
    """Context with one known user and brute_force=True."""
    opts = ScanOptions(url=BASE, brute_force=True)
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    ctx.users.append(User(id=1, username="admin", display_name="Admin", source="rest_api"))
    return ctx


@pytest.fixture
def ctx_disabled():
    """Context with brute_force=False (default)."""
    opts = ScanOptions(url=BASE)
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    ctx.users.append(User(id=1, username="admin", display_name="Admin", source="rest_api"))
    return ctx


# ---------------------------------------------------------------------- #
# Unit helpers                                                            #
# ---------------------------------------------------------------------- #

def test_mask_password_long():
    assert _mask_password("password123") == "pa***3"


def test_mask_password_short():
    assert _mask_password("ab") == "a***"


def test_dynamic_variants():
    variants = _build_dynamic_variants("admin")
    assert variants == [
        "admin",
        "admin123",
        "admin!",
        "admin2024",
        "admin2025",
        "admin#",
        "admin1234",
    ]
    assert len(variants) == 7


# ---------------------------------------------------------------------- #
# AC-8: Activation                                                        #
# ---------------------------------------------------------------------- #

async def test_module_disabled_by_default(ctx_disabled):
    """AC-8: BruteForceModule does NOT run without brute_force=True."""
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx_disabled.opts) as http:
            await BruteForceModule().run(ctx_disabled, http)
    assert len(ctx_disabled.findings) == 0


async def test_module_enabled_via_scan_options():
    """AC-8: Activates when ScanOptions.brute_force=True."""
    mod = BruteForceModule()
    opts = ScanOptions(url=BASE, brute_force=True)
    ctx = ScanContext(opts)
    assert mod._is_enabled(ctx) is True


async def test_module_enabled_via_module_options():
    """AC-8: Activates when module_options['brute_force']['enabled']='true'."""
    mod = BruteForceModule()
    opts = ScanOptions(url=BASE, module_options={"brute_force": {"enabled": "true"}})
    ctx = ScanContext(opts)
    assert mod._is_enabled(ctx) is True


async def test_module_not_enabled_by_aggressive():
    """AC-8: aggressive=True ALONE does not activate BruteForceModule."""
    mod = BruteForceModule()
    opts = ScanOptions(url=BASE, aggressive=True)
    ctx = ScanContext(opts)
    assert mod._is_enabled(ctx) is False


# ---------------------------------------------------------------------- #
# AC-9/10: Password list building                                         #
# ---------------------------------------------------------------------- #

async def test_internal_passwords_include_dynamic_variants():
    """AC-9: dynamic variants are included in internal list."""
    mod = BruteForceModule()
    opts = ScanOptions(url=BASE, brute_force=True)
    ctx = ScanContext(opts)
    passwords = await mod._build_password_list(ctx, ["admin"])
    assert "admin123" in passwords
    assert "admin2024" in passwords
    assert "admin!" in passwords
    assert "admin#" in passwords
    assert "admin1234" in passwords


async def test_external_wordlist_replaces_internal():
    """AC-10: external wordlist replaces internal by default."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as fh:
        fh.write("secret1\nsecret2\nsecret3\n")
        wl_path = fh.name
    try:
        mod = BruteForceModule()
        opts = ScanOptions(url=BASE, brute_force=True, brute_force_wordlist=wl_path)
        ctx = ScanContext(opts)
        passwords = await mod._build_password_list(ctx, ["admin"])
        assert "secret1" in passwords
        assert "secret2" in passwords
        # Internal passwords should NOT be present (replaced)
        assert "password" not in passwords
    finally:
        os.unlink(wl_path)


async def test_external_wordlist_combine():
    """AC-10: --brute-force-combine adds internal to external."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as fh:
        fh.write("uniquepass1\nuniquepass2\n")
        wl_path = fh.name
    try:
        mod = BruteForceModule()
        opts = ScanOptions(
            url=BASE, brute_force=True,
            brute_force_wordlist=wl_path, brute_force_combine=True
        )
        ctx = ScanContext(opts)
        passwords = await mod._build_password_list(ctx, ["admin"])
        assert "uniquepass1" in passwords
        # Internal passwords should also be present (combined)
        assert "password" in passwords
    finally:
        os.unlink(wl_path)


async def test_deep_mode_limit_50k():
    """AC-10: deep mode allows up to 50k passwords."""
    mod = BruteForceModule()
    opts = ScanOptions(url=BASE, brute_force=True, deep=True)
    ctx = ScanContext(opts)
    passwords = await mod._build_password_list(ctx, ["user"])
    assert len(passwords) <= 50000


async def test_fast_mode_limit_10k():
    """AC-10: fast mode limits to 10k passwords."""
    mod = BruteForceModule()
    opts = ScanOptions(url=BASE, brute_force=True, deep=False)
    ctx = ScanContext(opts)
    passwords = await mod._build_password_list(ctx, ["user"])
    assert len(passwords) <= 10000


# ---------------------------------------------------------------------- #
# AC-11: Login success detection                                          #
# ---------------------------------------------------------------------- #

async def test_success_via_set_cookie(ctx_with_user):
    """AC-11 PRIMARY: wordpress_logged_in_ cookie triggers success."""
    progress_calls = []
    ctx_with_user._on_progress = lambda n, c, t: progress_calls.append((n, c, t))

    async with respx.mock:
        # 2FA check
        respx.get(LOGIN_URL).mock(return_value=httpx.Response(200, text="<form>login</form>"))
        # First login attempt succeeds
        respx.post(LOGIN_URL).mock(
            return_value=httpx.Response(
                200,
                headers={"set-cookie": "wordpress_logged_in_abc=xyz; Path=/"},
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx_with_user.opts) as http:
            await BruteForceModule().run(ctx_with_user, http)

    bru_findings = [f for f in ctx_with_user.findings if f.id == "PC-BRU-001"]
    assert len(bru_findings) == 1
    assert "admin" in bru_findings[0].evidence["credentials"]


async def test_success_via_wp_admin_redirect(ctx_with_user):
    """AC-11 FALLBACK: redirect to /wp-admin/ triggers success."""
    async with respx.mock:
        respx.get(LOGIN_URL).mock(return_value=httpx.Response(200, text="<form>login</form>"))
        # First attempt fails, second succeeds with wp-admin redirect
        call_count = {"n": 0}
        def side_effect(request):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return httpx.Response(200, text="<p>Wrong password</p>")
            return httpx.Response(302, headers={"location": f"{BASE}/wp-admin/"})
        respx.post(LOGIN_URL).mock(side_effect=side_effect)
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx_with_user.opts) as http:
            # Patch the password list to have only 2 passwords to speed up test
            mod = BruteForceModule()
            original = mod._build_password_list
            async def short_list(c, u):
                return ["wrongpass", "correctpass"]
            mod._build_password_list = short_list
            await mod.run(ctx_with_user, http)

    bru_findings = [f for f in ctx_with_user.findings if f.id == "PC-BRU-001"]
    assert len(bru_findings) == 1


# ---------------------------------------------------------------------- #
# AC-12: 2FA detection                                                    #
# ---------------------------------------------------------------------- #

async def test_2fa_detected_high_severity(ctx_with_user):
    """AC-12: with 2FA detected, PC-BRU-001 uses HIGH/7.5."""
    async with respx.mock:
        # Login page has 2FA indicator
        respx.get(LOGIN_URL).mock(
            return_value=httpx.Response(200, text="<form>two-factor authentication</form>")
        )
        respx.post(LOGIN_URL).mock(
            return_value=httpx.Response(
                200,
                headers={"set-cookie": "wordpress_logged_in_abc=xyz; Path=/"},
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx_with_user.opts) as http:
            mod = BruteForceModule()
            async def short_list(c, u):
                return ["pass1"]
            mod._build_password_list = short_list
            await mod.run(ctx_with_user, http)

    bru_findings = [f for f in ctx_with_user.findings if f.id == "PC-BRU-001"]
    assert len(bru_findings) == 1
    assert bru_findings[0].severity.value == "HIGH"
    assert bru_findings[0].cvss_score == 7.5

    # PC-BRU-002 should also be emitted when 2FA detected
    bru002 = [f for f in ctx_with_user.findings if f.id == "PC-BRU-002"]
    assert len(bru002) == 1


async def test_no_2fa_critical_severity(ctx_with_user):
    """AC-12: without 2FA, PC-BRU-001 uses CRITICAL/9.8."""
    async with respx.mock:
        respx.get(LOGIN_URL).mock(
            return_value=httpx.Response(200, text="<form>login</form>")
        )
        respx.post(LOGIN_URL).mock(
            return_value=httpx.Response(
                200,
                headers={"set-cookie": "wordpress_logged_in_abc=xyz; Path=/"},
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx_with_user.opts) as http:
            mod = BruteForceModule()
            async def short_list(c, u):
                return ["pass1"]
            mod._build_password_list = short_list
            await mod.run(ctx_with_user, http)

    bru_findings = [f for f in ctx_with_user.findings if f.id == "PC-BRU-001"]
    assert len(bru_findings) == 1
    assert bru_findings[0].severity.value == "CRITICAL"
    assert bru_findings[0].cvss_score == 9.8


# ---------------------------------------------------------------------- #
# AC-13: Rate limiting                                                    #
# ---------------------------------------------------------------------- #

async def test_rate_limited_429_stops(ctx_with_user):
    """AC-13: HTTP 429 stops brute force and emits PC-BRU-003."""
    async with respx.mock:
        respx.get(LOGIN_URL).mock(return_value=httpx.Response(200, text="<form>login</form>"))
        respx.post(LOGIN_URL).mock(return_value=httpx.Response(429))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx_with_user.opts) as http:
            mod = BruteForceModule()
            async def short_list(c, u):
                return ["pass1", "pass2"]
            mod._build_password_list = short_list
            await mod.run(ctx_with_user, http)

    assert any(f.id == "PC-BRU-003" for f in ctx_with_user.findings)
    assert not any(f.id == "PC-BRU-001" for f in ctx_with_user.findings)


async def test_rate_limited_200_block_string_stops(ctx_with_user):
    """AC-13: HTTP 200 with block string stops brute force."""
    async with respx.mock:
        respx.get(LOGIN_URL).mock(return_value=httpx.Response(200, text="<form>login</form>"))
        respx.post(LOGIN_URL).mock(
            return_value=httpx.Response(200, text="Too many failed login attempts. You have been locked out.")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx_with_user.opts) as http:
            mod = BruteForceModule()
            async def short_list(c, u):
                return ["pass1", "pass2"]
            mod._build_password_list = short_list
            await mod.run(ctx_with_user, http)

    assert any(f.id == "PC-BRU-003" for f in ctx_with_user.findings)


# ---------------------------------------------------------------------- #
# AC-14: Evidence format                                                  #
# ---------------------------------------------------------------------- #

async def test_credentials_masked_in_evidence(ctx_with_user):
    """AC-14: passwords in evidence are masked."""
    async with respx.mock:
        respx.get(LOGIN_URL).mock(return_value=httpx.Response(200, text="<form>login</form>"))
        respx.post(LOGIN_URL).mock(
            return_value=httpx.Response(
                200,
                headers={"set-cookie": "wordpress_logged_in_abc=xyz; Path=/"},
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx_with_user.opts) as http:
            mod = BruteForceModule()
            async def short_list(c, u):
                return ["password123"]
            mod._build_password_list = short_list
            await mod.run(ctx_with_user, http)

    bru_findings = [f for f in ctx_with_user.findings if f.id == "PC-BRU-001"]
    assert len(bru_findings) == 1
    creds_evidence = bru_findings[0].evidence["credentials"]
    # Should be masked: pa***3
    assert "pa***3" in creds_evidence
    # Full password must NOT appear
    assert "password123" not in creds_evidence


# ---------------------------------------------------------------------- #
# No users → PC-BRU-003                                                  #
# ---------------------------------------------------------------------- #

async def test_no_users_emits_pc_bru_003():
    """No usernames → PC-BRU-003 (skipped) rather than crashing."""
    opts = ScanOptions(url=BASE, brute_force=True)
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    # No users added

    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(opts) as http:
            await BruteForceModule().run(ctx, http)

    assert any(f.id == "PC-BRU-003" for f in ctx.findings)
    assert not any(f.id == "PC-BRU-001" for f in ctx.findings)


# ---------------------------------------------------------------------- #
# No valid credentials → PC-BRU-004                                      #
# ---------------------------------------------------------------------- #

async def test_no_credentials_emits_pc_bru_004(ctx_with_user):
    """All passwords fail → PC-BRU-004 emitted."""
    async with respx.mock:
        respx.get(LOGIN_URL).mock(return_value=httpx.Response(200, text="<form>login</form>"))
        respx.post(LOGIN_URL).mock(
            return_value=httpx.Response(200, text="<p>Wrong password.</p>")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx_with_user.opts) as http:
            mod = BruteForceModule()
            async def short_list(c, u):
                return ["wrongpass1"]
            mod._build_password_list = short_list
            await mod.run(ctx_with_user, http)

    assert any(f.id == "PC-BRU-004" for f in ctx_with_user.findings)
    assert not any(f.id == "PC-BRU-001" for f in ctx_with_user.findings)
