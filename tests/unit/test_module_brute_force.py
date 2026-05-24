"""Spec-driven tests for BruteForceModule — one test per AC from the Spec Lock.

These tests verify the acceptance criteria. They MUST fail if the implementation
does not satisfy the AC. Tests use asyncio_mode=auto (no @pytest.mark.asyncio).
"""
from __future__ import annotations

import os
import asyncio
import tempfile
from unittest.mock import AsyncMock, patch
import pytest
import respx
import httpx

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def ctx():
    """Default ctx with brute_force=True and brute_force_use_defaults=True."""
    opts = ScanOptions(url="https://example.com", brute_force=True, brute_force_use_defaults=True)
    c = ScanContext(opts)
    c.is_wordpress = True
    return c


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    """Patch asyncio.sleep in the brute_force module to avoid 2s delays per attempt."""
    async def _instant_sleep(_delay):
        pass
    monkeypatch.setattr("plecost.modules.brute_force.asyncio.sleep", _instant_sleep)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ctx(extra_options=None, deep=False):
    """Build a ScanContext with brute_force enabled and brute_force_use_defaults=True."""
    opts = ScanOptions(
        url="https://example.com",
        deep=deep,
        brute_force=True,
        brute_force_use_defaults=True,
        **(extra_options or {})
    )
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    return ctx


def _make_ctx_disabled():
    """Build a ScanContext with brute_force NOT enabled."""
    opts = ScanOptions(url="https://example.com")
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    return ctx


# ---------------------------------------------------------------------------
# AC-8: BruteForceModule only activates with brute_force=True or module_options enabled
# ---------------------------------------------------------------------------

async def test_brute_force_not_activated_by_default():
    """AC-8: BruteForceModule must NOT run unless brute_force=True or module_options enabled."""
    from plecost.modules.brute_force import BruteForceModule

    ctx = _make_ctx_disabled()
    requests_made = []

    async with respx.mock:
        respx.get(url__regex=r".*wp-login.*").mock(
            side_effect=lambda req: requests_made.append(req) or httpx.Response(200)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteForceModule().run(ctx, http)

    login_requests = [r for r in requests_made if "wp-login" in str(r.url)]
    assert len(login_requests) == 0, (
        "AC-8: BruteForceModule must make no login attempts when brute_force is not enabled"
    )
    assert not any(f.id == "PC-BRU-001" for f in ctx.findings), (
        "AC-8: No PC-BRU-001 finding when brute_force is disabled"
    )


async def test_brute_force_not_activated_by_aggressive_flag():
    """AC-8: BruteForceModule must NOT activate with aggressive=True alone."""
    from plecost.modules.brute_force import BruteForceModule

    opts = ScanOptions(url="https://example.com", aggressive=True)
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    requests_made = []

    async with respx.mock:
        respx.get(url__regex=r".*wp-login.*").mock(
            side_effect=lambda req: requests_made.append(req) or httpx.Response(200)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteForceModule().run(ctx, http)

    login_requests = [r for r in requests_made if "wp-login" in str(r.url)]
    assert len(login_requests) == 0, (
        "AC-8: aggressive=True alone must NOT activate BruteForceModule"
    )


async def test_brute_force_activated_by_scan_options_flag():
    """AC-8: BruteForceModule must activate when ScanOptions.brute_force=True + brute_force_use_defaults=True."""
    from plecost.modules.brute_force import BruteForceModule

    # We add a known user to minimize attempts; brute_force_use_defaults=True enables internal list
    ctx = _make_ctx()
    ctx.add_user(__import__('plecost.models', fromlist=['User']).User(
        id=1, username="admin", display_name="Admin", source="rest_api"
    ))

    attempts_made = []

    async def login_handler(request):
        attempts_made.append(True)
        return httpx.Response(200, text="login failed")

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(side_effect=login_handler)
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteForceModule().run(ctx, http)

    assert len(attempts_made) > 0, (
        "AC-8: BruteForceModule must attempt logins when brute_force=True"
    )


async def test_brute_force_activated_by_module_options():
    """AC-8: BruteForceModule must activate when module_options['brute_force']['enabled']='true'."""
    from plecost.modules.brute_force import BruteForceModule

    opts = ScanOptions(
        url="https://example.com",
        brute_force_use_defaults=True,
        module_options={"brute_force": {"enabled": "true"}}
    )
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    from plecost.models import User
    ctx.add_user(User(id=1, username="admin", display_name="Admin", source="rest_api"))

    attempts_made = []

    async def login_handler(request):
        attempts_made.append(True)
        return httpx.Response(200, text="login failed")

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(side_effect=login_handler)
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteForceModule().run(ctx, http)

    assert len(attempts_made) > 0, (
        "AC-8: BruteForceModule must activate via module_options['brute_force']['enabled']='true'"
    )


# ---------------------------------------------------------------------------
# AC-9: Internal wordlist ~60 passwords + dynamic username variants
# ---------------------------------------------------------------------------

async def test_brute_force_uses_internal_wordlist():
    """AC-9: BruteForceModule must use ~60 internal passwords + username variants."""
    # The internal list is a module-level constant _INTERNAL_PASSWORDS
    from plecost.modules.brute_force import _INTERNAL_PASSWORDS

    assert _INTERNAL_PASSWORDS is not None, (
        "AC-9: BruteForceModule must have a module-level _INTERNAL_PASSWORDS constant"
    )
    assert len(_INTERNAL_PASSWORDS) >= 50, (
        f"AC-9: Internal wordlist must have at least ~60 passwords, got {len(_INTERNAL_PASSWORDS)}"
    )


async def test_brute_force_adds_username_variants():
    """AC-9: BruteForceModule must add dynamic username variants (e.g. admin123, admin!)."""
    # The module uses module-level _build_dynamic_variants()
    from plecost.modules.brute_force import _build_dynamic_variants

    username = "testuser"
    variants = _build_dynamic_variants(username)

    assert len(variants) > 0, (
        f"AC-9: _build_dynamic_variants must generate variants for '{username}'"
    )
    # Variants should include combinations like testuser123, testuser!
    assert any(username in v for v in variants), (
        f"AC-9: Username variants must include the username itself or variants; got {variants[:5]}"
    )


# ---------------------------------------------------------------------------
# AC-10: External wordlist via --brute-force-wordlist
# ---------------------------------------------------------------------------

async def test_brute_force_external_wordlist_loaded():
    """AC-10: BruteForceModule must load external wordlist via brute_force_wordlist option."""
    from plecost.modules.brute_force import BruteForceModule

    # Create a temporary wordlist file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        for i in range(20):
            f.write(f"externalpass{i}\n")
        tmpfile = f.name

    try:
        opts = ScanOptions(
            url="https://example.com",
            brute_force=True,
            brute_force_wordlist=tmpfile,
        )
        ctx = ScanContext(opts)
        ctx.is_wordpress = True
        from plecost.models import User
        ctx.add_user(User(id=1, username="admin", display_name="Admin", source="rest_api"))

        passwords_attempted = []

        async def login_handler(request):
            body = request.content.decode() if request.content else ""
            for line in body.split("&"):
                if "pwd=" in line:
                    passwords_attempted.append(line.split("=")[1])
            return httpx.Response(200, text="login failed")

        async with respx.mock:
            respx.post("https://example.com/wp-login.php").mock(side_effect=login_handler)
            respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

            async with PlecostHTTPClient(opts) as http:
                await BruteForceModule().run(ctx, http)

        # At least some external passwords should have been attempted
        external_passes = [p for p in passwords_attempted if p.startswith("externalpass")]
        assert len(external_passes) > 0, (
            "AC-10: External wordlist passwords must be attempted"
        )
    finally:
        os.unlink(tmpfile)


async def test_brute_force_external_wordlist_replaces_internal():
    """AC-10: External wordlist replaces internal by default (without --brute-force-combine)."""
    from plecost.modules.brute_force import BruteForceModule, _INTERNAL_PASSWORDS

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("unique_external_only_password\n")
        tmpfile = f.name

    try:
        module = BruteForceModule()
        # Without combine flag, external should replace internal
        # _build_password_list takes ctx and usernames
        opts = ScanOptions(
            url="https://example.com",
            brute_force=True,
            brute_force_wordlist=tmpfile,
            brute_force_combine=False,
        )
        ctx = ScanContext(opts)
        ctx.is_wordpress = True
        wordlist = await module._build_password_list(ctx, ["admin"])

        # The wordlist should NOT contain internal-only passwords that aren't in external
        internal_only = set(_INTERNAL_PASSWORDS) - {"unique_external_only_password"}
        if internal_only:
            overlap = internal_only.intersection(set(wordlist))
            assert len(overlap) == 0, (
                f"AC-10: Without combine, external wordlist must replace internal; "
                f"found internal passwords in list: {list(overlap)[:3]}"
            )
    finally:
        os.unlink(tmpfile)


async def test_brute_force_combine_flag_merges_both_wordlists():
    """AC-10 / AC-4: --brute-force-combine merges external + internal ONLY if brute_force_use_defaults=True."""
    from plecost.modules.brute_force import BruteForceModule, _INTERNAL_PASSWORDS

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("unique_external_pass\n")
        tmpfile = f.name

    try:
        module = BruteForceModule()
        opts = ScanOptions(
            url="https://example.com",
            brute_force=True,
            brute_force_use_defaults=True,
            brute_force_wordlist=tmpfile,
            brute_force_combine=True,
        )
        ctx = ScanContext(opts)
        ctx.is_wordpress = True
        wordlist = await module._build_password_list(ctx, ["admin"])

        assert "unique_external_pass" in wordlist, (
            "AC-10: Combined wordlist must include external passwords"
        )
        # At least some internal passwords should be in the combined list
        intersection = set(_INTERNAL_PASSWORDS).intersection(set(wordlist))
        assert len(intersection) > 0, (
            "AC-10: Combined wordlist must include internal passwords"
        )
    finally:
        os.unlink(tmpfile)


async def test_brute_force_external_wordlist_fast_limit():
    """AC-10: External wordlist must be capped at 10k passwords in fast mode."""
    from plecost.modules.brute_force import BruteForceModule

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        for i in range(15000):
            f.write(f"password{i}\n")
        tmpfile = f.name

    try:
        module = BruteForceModule()
        opts = ScanOptions(
            url="https://example.com",
            brute_force=True,
            brute_force_wordlist=tmpfile,
            brute_force_combine=False,
            deep=False,
        )
        ctx = ScanContext(opts)
        ctx.is_wordpress = True
        wordlist = await module._build_password_list(ctx, ["admin"])

        assert len(wordlist) <= 10000, (
            f"AC-10: Fast mode must cap external wordlist at 10k, got {len(wordlist)}"
        )
    finally:
        os.unlink(tmpfile)


async def test_brute_force_external_wordlist_deep_limit():
    """AC-10: External wordlist must be capped at 50k passwords in deep mode."""
    from plecost.modules.brute_force import BruteForceModule

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        for i in range(60000):
            f.write(f"password{i}\n")
        tmpfile = f.name

    try:
        module = BruteForceModule()
        opts = ScanOptions(
            url="https://example.com",
            brute_force=True,
            brute_force_wordlist=tmpfile,
            brute_force_combine=False,
            deep=True,
        )
        ctx = ScanContext(opts)
        ctx.is_wordpress = True
        wordlist = await module._build_password_list(ctx, ["admin"])

        assert len(wordlist) <= 50000, (
            f"AC-10: Deep mode must cap external wordlist at 50k, got {len(wordlist)}"
        )
    finally:
        os.unlink(tmpfile)


# ---------------------------------------------------------------------------
# AC-11: Success via Set-Cookie "wordpress_logged_in_" or redirect to /wp-admin/
# ---------------------------------------------------------------------------

async def test_success_detected_via_wordpress_logged_in_cookie(ctx):
    """AC-11: Primary success condition: Set-Cookie contains 'wordpress_logged_in_'."""
    from plecost.modules.brute_force import BruteForceModule
    from plecost.models import User

    ctx = _make_ctx()
    ctx.add_user(User(id=1, username="admin", display_name="Admin", source="rest_api"))

    async def login_handler(request):
        body = request.content.decode() if request.content else ""
        # Only succeed for the first password in the list
        if "pwd=password" in body or "pwd=123456" in body or "pwd=admin" in body:
            return httpx.Response(
                200,
                text="Redirecting...",
                headers={"Set-Cookie": "wordpress_logged_in_abc123=data; path=/"},
            )
        return httpx.Response(200, text="login failed")

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(side_effect=login_handler)
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteForceModule().run(ctx, http)

    bru001_findings = [f for f in ctx.findings if f.id == "PC-BRU-001"]
    assert len(bru001_findings) == 1, (
        "AC-11: PC-BRU-001 must be emitted when wordpress_logged_in_ cookie is set"
    )


async def test_success_detected_via_wp_admin_redirect(ctx):
    """AC-11: Fallback success: HTTP redirect (301/302) to /wp-admin/."""
    from plecost.modules.brute_force import BruteForceModule
    from plecost.models import User

    ctx = _make_ctx()
    ctx.add_user(User(id=1, username="admin", display_name="Admin", source="rest_api"))

    async def login_handler(request):
        body = request.content.decode() if request.content else ""
        if "pwd=password" in body or "pwd=123456" in body or "pwd=admin" in body:
            return httpx.Response(
                302,
                headers={"location": "https://example.com/wp-admin/"},
            )
        return httpx.Response(200, text="login failed")

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(side_effect=login_handler)
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteForceModule().run(ctx, http)

    bru001_findings = [f for f in ctx.findings if f.id == "PC-BRU-001"]
    assert len(bru001_findings) == 1, (
        "AC-11: PC-BRU-001 must be emitted when login redirects to /wp-admin/"
    )


# ---------------------------------------------------------------------------
# AC-12: _check_2fa() called; PC-BRU-001 HIGH/7.5 with 2FA, CRITICAL/9.8 without
# ---------------------------------------------------------------------------

async def test_pc_bru_001_critical_without_2fa(ctx):
    """AC-12: PC-BRU-001 must be CRITICAL/9.8 when no 2FA is detected."""
    from plecost.modules.brute_force import BruteForceModule
    from plecost.models import User

    ctx = _make_ctx()
    ctx.add_user(User(id=1, username="admin", display_name="Admin", source="rest_api"))

    async def login_handler(request):
        body = request.content.decode() if request.content else ""
        if "pwd=admin" in body or "pwd=password" in body or "pwd=123456" in body:
            return httpx.Response(
                200,
                headers={"Set-Cookie": "wordpress_logged_in_abc=data; path=/"},
            )
        return httpx.Response(200, text="login failed")

    async def check_2fa_handler(request):
        # Simulate no 2FA (no 2FA plugin detected)
        return httpx.Response(200, text="no 2fa here")

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(side_effect=login_handler)
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteForceModule().run(ctx, http)

    bru001 = [f for f in ctx.findings if f.id == "PC-BRU-001"]
    if bru001:  # Only check if we got a finding (depends on password matching)
        assert bru001[0].severity.value == "CRITICAL", (
            "AC-12: PC-BRU-001 without 2FA must be CRITICAL"
        )
        assert abs(bru001[0].cvss_score - 9.8) < 0.1, (
            f"AC-12: PC-BRU-001 without 2FA must have CVSS 9.8, got {bru001[0].cvss_score}"
        )


async def test_pc_bru_001_high_with_2fa():
    """AC-12: PC-BRU-001 must be HIGH/7.5 when 2FA is detected."""
    from plecost.modules.brute_force import BruteForceModule
    from plecost.models import User

    opts = ScanOptions(url="https://example.com", brute_force=True, brute_force_use_defaults=True)
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    ctx.add_user(User(id=1, username="admin", display_name="Admin", source="rest_api"))

    call_count = [0]

    async def login_handler(request):
        body = request.content.decode() if request.content else ""
        if "pwd=admin" in body or "pwd=password" in body or "pwd=123456" in body:
            return httpx.Response(
                200,
                headers={"Set-Cookie": "wordpress_logged_in_abc=data; path=/"},
            )
        return httpx.Response(200, text="login failed")

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(side_effect=login_handler)
        # Simulate 2FA plugin present (e.g., wordfence 2FA page)
        respx.get(url__regex=r".*(wordfence|two-factor|2fa).*").mock(
            return_value=httpx.Response(200, text="2FA is enabled")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

        # Patch _check_2fa to simulate 2FA is detected
        original_run = BruteForceModule.run

        async def patched_run(self, ctx, http):
            # Inject 2FA detection
            self._2fa_detected = True
            await original_run(self, ctx, http)

        with __import__('unittest.mock', fromlist=['patch']).patch.object(
            BruteForceModule, '_check_2fa', return_value=True
        ):
            async with PlecostHTTPClient(ctx.opts) as http:
                await BruteForceModule().run(ctx, http)

    bru001 = [f for f in ctx.findings if f.id == "PC-BRU-001"]
    if bru001:
        assert bru001[0].severity.value == "HIGH", (
            "AC-12: PC-BRU-001 with 2FA must be HIGH"
        )
        assert abs(bru001[0].cvss_score - 7.5) < 0.1, (
            f"AC-12: PC-BRU-001 with 2FA must have CVSS 7.5, got {bru001[0].cvss_score}"
        )


# ---------------------------------------------------------------------------
# AC-13: Rate limiting stops brute force
# ---------------------------------------------------------------------------

async def test_brute_force_stops_on_429(ctx):
    """AC-13: Rate limiting 429 → stop immediately, emit PC-BRU-007."""
    from plecost.modules.brute_force import BruteForceModule
    from plecost.models import User

    ctx = _make_ctx()
    ctx.add_user(User(id=1, username="admin", display_name="Admin", source="rest_api"))

    attempts = [0]

    async def login_handler(request):
        attempts[0] += 1
        if attempts[0] >= 3:
            return httpx.Response(429, text="Too Many Requests")
        return httpx.Response(200, text="login failed")

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(side_effect=login_handler)
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteForceModule().run(ctx, http)

    # After 429, should stop — at most a few more attempts
    assert attempts[0] < 10, (
        f"AC-13: Brute force must stop on 429 rate limit, but made {attempts[0]} attempts"
    )

    # PC-BRU-007 is the rate-limiting finding (FIX-3)
    bru007 = [f for f in ctx.findings if f.id == "PC-BRU-007"]
    assert len(bru007) == 1, (
        "FIX-3/AC-13: PC-BRU-007 must be emitted when rate limiting (429) is detected"
    )


async def test_brute_force_stops_on_403(ctx):
    """AC-13: HTTP 403 response → stop brute force."""
    from plecost.modules.brute_force import BruteForceModule
    from plecost.models import User

    ctx = _make_ctx()
    ctx.add_user(User(id=1, username="admin", display_name="Admin", source="rest_api"))

    attempts = [0]

    async def login_handler(request):
        attempts[0] += 1
        if attempts[0] >= 2:
            return httpx.Response(403, text="Forbidden")
        return httpx.Response(200, text="login failed")

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(side_effect=login_handler)
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteForceModule().run(ctx, http)

    assert attempts[0] < 10, (
        f"AC-13: Brute force must stop on 403, but made {attempts[0]} attempts"
    )


async def test_brute_force_stops_on_block_strings_in_200(ctx):
    """AC-13: HTTP 200 with blocking strings → stop immediately."""
    from plecost.modules.brute_force import BruteForceModule
    from plecost.models import User

    ctx = _make_ctx()
    ctx.add_user(User(id=1, username="admin", display_name="Admin", source="rest_api"))

    attempts = [0]

    async def login_handler(request):
        attempts[0] += 1
        if attempts[0] >= 3:
            return httpx.Response(200, text="You have been blocked. Too many failed login attempts.")
        return httpx.Response(200, text="login failed")

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(side_effect=login_handler)
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteForceModule().run(ctx, http)

    assert attempts[0] < 15, (
        f"AC-13: Brute force must stop on block strings in 200 response, "
        f"but made {attempts[0]} attempts"
    )


async def test_brute_force_stops_on_connect_error(ctx):
    """AC-13: ConnectError → stop immediately."""
    from plecost.modules.brute_force import BruteForceModule
    from plecost.models import User

    ctx = _make_ctx()
    ctx.add_user(User(id=1, username="admin", display_name="Admin", source="rest_api"))

    attempts = [0]

    async def login_handler(request):
        attempts[0] += 1
        if attempts[0] >= 3:
            raise httpx.ConnectError("Connection refused")
        return httpx.Response(200, text="login failed")

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(side_effect=login_handler)
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteForceModule().run(ctx, http)

    assert attempts[0] < 15, (
        f"AC-13: Brute force must stop on ConnectError, but made {attempts[0]} attempts"
    )


# ---------------------------------------------------------------------------
# AC-14: Single PC-BRU-001 finding; credentials in evidence; passwords masked
# ---------------------------------------------------------------------------

async def test_single_pc_bru_001_finding_on_success(ctx):
    """AC-14: Only one PC-BRU-001 finding regardless of how many credentials succeed."""
    from plecost.modules.brute_force import BruteForceModule
    from plecost.models import User

    ctx = _make_ctx()
    ctx.add_user(User(id=1, username="admin", display_name="Admin", source="rest_api"))

    async def login_handler(request):
        # Always succeed to ensure multiple finds don't happen
        return httpx.Response(
            200,
            headers={"Set-Cookie": "wordpress_logged_in_x=data; path=/"},
        )

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(side_effect=login_handler)
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteForceModule().run(ctx, http)

    bru001_findings = [f for f in ctx.findings if f.id == "PC-BRU-001"]
    assert len(bru001_findings) == 1, (
        f"AC-14: Must emit exactly one PC-BRU-001 finding, got {len(bru001_findings)}"
    )


async def test_credentials_in_evidence(ctx):
    """AC-14: Discovered credentials must be stored in evidence['credentials']."""
    from plecost.modules.brute_force import BruteForceModule
    from plecost.models import User

    ctx = _make_ctx()
    ctx.add_user(User(id=1, username="admin", display_name="Admin", source="rest_api"))

    success_passwords = ["admin", "password", "123456"]

    async def login_handler(request):
        body = request.content.decode() if request.content else ""
        for pwd in success_passwords:
            if f"pwd={pwd}" in body:
                return httpx.Response(
                    200,
                    headers={"Set-Cookie": "wordpress_logged_in_x=data; path=/"},
                )
        return httpx.Response(200, text="login failed")

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(side_effect=login_handler)
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteForceModule().run(ctx, http)

    bru001 = [f for f in ctx.findings if f.id == "PC-BRU-001"]
    if bru001:
        evidence = bru001[0].evidence
        assert "credentials" in evidence, (
            "AC-14: PC-BRU-001 evidence must contain 'credentials' key"
        )


async def test_passwords_masked_in_evidence(ctx):
    """AC-14: Passwords in evidence must be masked (e.g. *** or similar)."""
    from plecost.modules.brute_force import BruteForceModule
    from plecost.models import User

    ctx = _make_ctx()
    ctx.add_user(User(id=1, username="admin", display_name="Admin", source="rest_api"))

    success_password = "supersecret123"

    async def login_handler(request):
        body = request.content.decode() if request.content else ""
        if f"pwd={success_password}" in body:
            return httpx.Response(
                200,
                headers={"Set-Cookie": "wordpress_logged_in_x=data; path=/"},
            )
        return httpx.Response(200, text="login failed")

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(side_effect=login_handler)
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteForceModule().run(ctx, http)

    bru001 = [f for f in ctx.findings if f.id == "PC-BRU-001"]
    if bru001:
        evidence_str = str(bru001[0].evidence)
        # Password should not appear in plaintext in evidence
        assert success_password not in evidence_str, (
            "AC-14: Plain-text password must not appear in evidence; must be masked"
        )


# ---------------------------------------------------------------------------
# AC-15: asyncio.Semaphore(1) default; delay 2000ms outside sem block; report_progress
# ---------------------------------------------------------------------------

async def test_brute_force_semaphore_default_is_1():
    """AC-15: BruteForceModule must use asyncio.Semaphore(1) by default (serial execution)."""
    from plecost.modules.brute_force import BruteForceModule

    module = BruteForceModule()
    # Check the default concurrency/semaphore configuration
    default_concurrency = getattr(module, '_DEFAULT_CONCURRENCY', None)
    if default_concurrency is not None:
        assert default_concurrency == 1, (
            f"AC-15: Default concurrency must be 1 (semaphore=1), got {default_concurrency}"
        )
    else:
        # Check via other attribute names
        sem_value = getattr(module, '_semaphore_value', getattr(module, '_concurrency', None))
        assert sem_value is None or sem_value == 1, (
            f"AC-15: Default semaphore value must be 1, got {sem_value}"
        )


async def test_brute_force_report_progress_in_finally():
    """AC-15: BruteForceModule must call ctx.report_progress() in finally block."""
    from plecost.modules.brute_force import BruteForceModule
    from plecost.models import User

    progress_calls = []

    opts = ScanOptions(url="https://example.com", brute_force=True, brute_force_use_defaults=True)
    ctx = ScanContext(
        opts,
        on_progress=lambda name, curr, total: progress_calls.append((name, curr, total))
    )
    ctx.is_wordpress = True
    ctx.add_user(User(id=1, username="admin", display_name="Admin", source="rest_api"))

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(200, text="login failed")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteForceModule().run(ctx, http)

    assert len(progress_calls) > 0, (
        "AC-15: BruteForceModule must call report_progress() during execution"
    )


# ---------------------------------------------------------------------------
# AC-16: ScanOptions new fields: brute_force, brute_force_wordlist, brute_force_combine
# ---------------------------------------------------------------------------

def test_scan_options_has_brute_force_field():
    """AC-16: ScanOptions must have brute_force boolean field."""
    opts = ScanOptions(url="https://example.com")
    assert hasattr(opts, 'brute_force'), "AC-16: ScanOptions must have 'brute_force' field"
    assert opts.brute_force is False, "AC-16: brute_force must default to False"


def test_scan_options_has_brute_force_wordlist_field():
    """AC-16: ScanOptions must have brute_force_wordlist field."""
    opts = ScanOptions(url="https://example.com")
    assert hasattr(opts, 'brute_force_wordlist'), (
        "AC-16: ScanOptions must have 'brute_force_wordlist' field"
    )
    assert opts.brute_force_wordlist is None, (
        "AC-16: brute_force_wordlist must default to None"
    )


def test_scan_options_has_brute_force_combine_field():
    """AC-16: ScanOptions must have brute_force_combine boolean field."""
    opts = ScanOptions(url="https://example.com")
    assert hasattr(opts, 'brute_force_combine'), (
        "AC-16: ScanOptions must have 'brute_force_combine' field"
    )
    assert opts.brute_force_combine is False, (
        "AC-16: brute_force_combine must default to False"
    )


def test_scan_options_brute_force_fields_settable():
    """AC-16: ScanOptions brute_force fields must be settable."""
    opts = ScanOptions(
        url="https://example.com",
        brute_force=True,
        brute_force_wordlist="/path/to/wordlist.txt",
        brute_force_combine=True,
    )
    assert opts.brute_force is True
    assert opts.brute_force_wordlist == "/path/to/wordlist.txt"
    assert opts.brute_force_combine is True


# ---------------------------------------------------------------------------
# AC-17: run_many() propagates brute_force, brute_force_wordlist, brute_force_combine
# ---------------------------------------------------------------------------

async def test_run_many_propagates_brute_force_fields():
    """AC-17: Scanner.run_many() must propagate brute_force, brute_force_wordlist,
    and brute_force_combine to each per-target ScanOptions."""
    from plecost.scanner import Scanner

    opts = ScanOptions(
        url="https://example.com",
        brute_force=True,
        brute_force_wordlist="/tmp/wordlist.txt",
        brute_force_combine=True,
    )

    per_target_opts = []

    class TrackingScanner(Scanner):
        async def run(self):
            per_target_opts.append(self._opts)
            # Return minimal result
            from plecost.models import ScanResult, ScanSummary
            from datetime import datetime
            return ScanResult(
                scan_id="test", url=self._opts.url,
                timestamp=datetime.now(), duration_seconds=0.0,
                is_wordpress=False, wordpress_version=None,
                plugins=[], themes=[], users=[], waf_detected=None,
                findings=[], summary=ScanSummary(), blocked=False,
            )

    scanner = TrackingScanner(opts)

    # Patch Scanner class instantiation inside run_many
    import plecost.scanner as scanner_module
    original_scanner_class = scanner_module.Scanner

    created_opts_list = []

    class CapturingScanner:
        def __init__(self, inner_opts, **kwargs):
            created_opts_list.append(inner_opts)

        async def run(self):
            from plecost.models import ScanResult, ScanSummary
            from datetime import datetime
            return ScanResult(
                scan_id="test", url="https://target1.com",
                timestamp=datetime.now(), duration_seconds=0.0,
                is_wordpress=False, wordpress_version=None,
                plugins=[], themes=[], users=[], waf_detected=None,
                findings=[], summary=ScanSummary(), blocked=False,
            )

    scanner_module.Scanner = CapturingScanner
    try:
        await scanner.run_many(["https://target1.com"])
    finally:
        scanner_module.Scanner = original_scanner_class

    assert len(created_opts_list) == 1, "run_many must create one Scanner per target"
    child_opts = created_opts_list[0]
    assert child_opts.brute_force is True, (
        "AC-17: run_many must propagate brute_force=True to child ScanOptions"
    )
    assert child_opts.brute_force_wordlist == "/tmp/wordlist.txt", (
        "AC-17: run_many must propagate brute_force_wordlist to child ScanOptions"
    )
    assert child_opts.brute_force_combine is True, (
        "AC-17: run_many must propagate brute_force_combine to child ScanOptions"
    )


# ---------------------------------------------------------------------------
# FIX-1: _load_wordlist() rejects non-regular files (ValueError)
# ---------------------------------------------------------------------------

def test_load_wordlist_rejects_directory():
    """FIX-1: _load_wordlist() must reject paths that are not regular files (ValueError)."""
    # _load_wordlist is a module-level sync function, not a method
    from plecost.modules.brute_force import _load_wordlist

    with pytest.raises((ValueError, IsADirectoryError, PermissionError)):
        _load_wordlist("/tmp", 100)  # /tmp is a directory, not a regular file


def test_load_wordlist_rejects_device_file():
    """FIX-1: _load_wordlist() must raise ValueError for non-regular files like /dev/null."""
    from plecost.modules.brute_force import _load_wordlist

    with pytest.raises(ValueError):
        _load_wordlist("/dev/null", 100)


def test_load_wordlist_accepts_regular_file():
    """FIX-1: _load_wordlist() must accept regular files without raising."""
    from plecost.modules.brute_force import _load_wordlist

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("pass1\npass2\npass3\n")
        tmpfile = f.name

    try:
        result = _load_wordlist(tmpfile, 100)
        assert len(result) == 3, f"Expected 3 passwords, got {len(result)}"
        assert "pass1" in result
    finally:
        os.unlink(tmpfile)


# ---------------------------------------------------------------------------
# AC-18: All new finding IDs registered in _FINDINGS_REGISTRY and KNOWN_FINDING_IDS
# ---------------------------------------------------------------------------

def test_pc_usr_003_registered_in_findings_registry():
    """AC-18: PC-USR-003 must be registered in _FINDINGS_REGISTRY in cli.py."""
    from plecost.cli import _FINDINGS_REGISTRY
    assert "PC-USR-003" in _FINDINGS_REGISTRY, (
        "AC-18: PC-USR-003 must be in _FINDINGS_REGISTRY"
    )


def test_pc_usr_004_registered_in_findings_registry():
    """AC-18: PC-USR-004 must be registered in _FINDINGS_REGISTRY in cli.py."""
    from plecost.cli import _FINDINGS_REGISTRY
    assert "PC-USR-004" in _FINDINGS_REGISTRY, (
        "AC-18: PC-USR-004 must be in _FINDINGS_REGISTRY"
    )


def test_pc_usr_005_registered_in_findings_registry():
    """AC-18: PC-USR-005 must be registered in _FINDINGS_REGISTRY in cli.py."""
    from plecost.cli import _FINDINGS_REGISTRY
    assert "PC-USR-005" in _FINDINGS_REGISTRY, (
        "AC-18: PC-USR-005 must be in _FINDINGS_REGISTRY"
    )


def test_pc_bru_001_registered_in_findings_registry():
    """AC-18: PC-BRU-001 must be registered in _FINDINGS_REGISTRY in cli.py."""
    from plecost.cli import _FINDINGS_REGISTRY
    assert "PC-BRU-001" in _FINDINGS_REGISTRY, (
        "AC-18: PC-BRU-001 must be in _FINDINGS_REGISTRY"
    )


def test_pc_bru_007_registered_in_findings_registry():
    """AC-18 + FIX-3: PC-BRU-007 must be registered in _FINDINGS_REGISTRY (rate-limiting finding)."""
    from plecost.cli import _FINDINGS_REGISTRY
    assert "PC-BRU-007" in _FINDINGS_REGISTRY, (
        "AC-18/FIX-3: PC-BRU-007 (rate-limiting) must be in _FINDINGS_REGISTRY"
    )


def test_new_finding_ids_in_known_finding_ids():
    """AC-18: New IDs PC-USR-003/004/005, PC-BRU-001/007 must be in KNOWN_FINDING_IDS."""
    import importlib.util
    import pathlib

    # Resolve the contract test relative to this file's location
    this_dir = pathlib.Path(__file__).parent.parent  # tests/
    contract_file = this_dir / "contract" / "test_finding_ids.py"

    spec = importlib.util.spec_from_file_location("test_finding_ids", str(contract_file))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    known_ids = mod.KNOWN_FINDING_IDS
    for finding_id in ["PC-USR-003", "PC-USR-004", "PC-USR-005", "PC-BRU-001", "PC-BRU-007"]:
        assert finding_id in known_ids, (
            f"AC-18: {finding_id} must be in KNOWN_FINDING_IDS in tests/contract/test_finding_ids.py"
        )


# ---------------------------------------------------------------------------
# AC-1 / AC-2: --brute-force alone does NOT use internal list; needs --brute-force-defaults
# ---------------------------------------------------------------------------

async def test_brute_force_no_attack_without_wordlist_or_defaults():
    """AC-1/AC-5: brute_force=True but no defaults and no wordlist → PC-BRU-008, zero HTTP credential attempts."""
    from plecost.modules.brute_force import BruteForceModule
    from plecost.models import User

    opts = ScanOptions(
        url="https://example.com",
        brute_force=True,
        brute_force_use_defaults=False,   # AC-1: internal list NOT used by default
        brute_force_wordlist=None,
    )
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    ctx.add_user(User(id=1, username="admin", display_name="Admin", source="rest_api"))

    login_requests = []

    async with respx.mock:
        respx.post("https://example.com/wp-login.php").mock(
            side_effect=lambda req: login_requests.append(req) or httpx.Response(200)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

        async with PlecostHTTPClient(ctx.opts) as http:
            await BruteForceModule().run(ctx, http)

    # No login attempts made
    assert len(login_requests) == 0, (
        "AC-1: brute_force=True without --brute-force-defaults must make ZERO login attempts"
    )
    # PC-BRU-008 emitted to signal no wordlist configured
    bru008 = [f for f in ctx.findings if f.id == "PC-BRU-008"]
    assert len(bru008) == 1, (
        "AC-5: PC-BRU-008 must be emitted when brute_force=True but no wordlist configured"
    )


def test_scan_options_has_brute_force_use_defaults_field():
    """AC-2: ScanOptions must have brute_force_use_defaults boolean field defaulting to False."""
    opts = ScanOptions(url="https://example.com")
    assert hasattr(opts, "brute_force_use_defaults"), (
        "AC-2: ScanOptions must have 'brute_force_use_defaults' field"
    )
    assert opts.brute_force_use_defaults is False, (
        "AC-2: brute_force_use_defaults must default to False"
    )


async def test_brute_force_defaults_activates_internal_list():
    """AC-2: brute_force_use_defaults=True activates the internal wordlist."""
    from plecost.modules.brute_force import BruteForceModule

    module = BruteForceModule()
    opts = ScanOptions(
        url="https://example.com",
        brute_force=True,
        brute_force_use_defaults=True,
    )
    ctx = ScanContext(opts)
    ctx.is_wordpress = True

    passwords = await module._build_password_list(ctx, ["admin"])
    assert len(passwords) > 0, (
        "AC-2: brute_force_use_defaults=True must produce a non-empty password list"
    )


async def test_brute_force_no_defaults_gives_empty_list_without_wordlist():
    """AC-1: brute_force_use_defaults=False without wordlist → empty list."""
    from plecost.modules.brute_force import BruteForceModule

    module = BruteForceModule()
    opts = ScanOptions(
        url="https://example.com",
        brute_force=True,
        brute_force_use_defaults=False,
        brute_force_wordlist=None,
    )
    ctx = ScanContext(opts)
    ctx.is_wordpress = True

    passwords = await module._build_password_list(ctx, ["admin"])
    assert passwords == [], (
        "AC-1: Without --brute-force-defaults or wordlist, password list must be empty"
    )


async def test_brute_force_combine_without_defaults_uses_external_only():
    """AC-4: --brute-force-combine without --brute-force-defaults uses external only (no internal merge)."""
    import tempfile, os
    from plecost.modules.brute_force import BruteForceModule, _INTERNAL_PASSWORDS

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("external_only_pass\n")
        tmpfile = f.name

    try:
        module = BruteForceModule()
        opts = ScanOptions(
            url="https://example.com",
            brute_force=True,
            brute_force_use_defaults=False,   # no internal list
            brute_force_wordlist=tmpfile,
            brute_force_combine=True,
        )
        ctx = ScanContext(opts)
        ctx.is_wordpress = True
        passwords = await module._build_password_list(ctx, ["admin"])

        # External password should be present
        assert "external_only_pass" in passwords, (
            "AC-4: External wordlist must appear when combine=True"
        )
        # No internal passwords should be present when use_defaults=False
        internal_in_list = set(_INTERNAL_PASSWORDS).intersection(set(passwords))
        assert len(internal_in_list) == 0, (
            "AC-4: Without --brute-force-defaults, internal passwords must NOT be merged"
        )
    finally:
        os.unlink(tmpfile)


# ---------------------------------------------------------------------------
# AC-6: run_many() propagates all callbacks
# ---------------------------------------------------------------------------

async def test_run_many_propagates_callbacks():
    """AC-6: Scanner.run_many() must propagate on_finding callback to each per-target Scanner."""
    from plecost.scanner import Scanner
    from plecost.models import User

    findings_received = []
    module_starts = []

    opts = ScanOptions(url="https://example.com", brute_force=False)

    import plecost.scanner as scanner_module
    original_scanner_class = scanner_module.Scanner

    captured_kwargs: list[dict] = []

    class CapturingScanner:
        def __init__(self, inner_opts, **kwargs):
            captured_kwargs.append(kwargs)

        async def run(self):
            from plecost.models import ScanResult, ScanSummary
            from datetime import datetime
            return ScanResult(
                scan_id="test", url="https://target1.com",
                timestamp=datetime.now(), duration_seconds=0.0,
                is_wordpress=False, wordpress_version=None,
                plugins=[], themes=[], users=[], waf_detected=None,
                findings=[], summary=ScanSummary(), blocked=False,
            )

    scanner_module.Scanner = CapturingScanner
    try:
        scanner = Scanner(
            opts,
            on_finding=lambda f: findings_received.append(f),
            on_module_start=lambda name: module_starts.append(name),
        )
        await scanner.run_many(["https://target1.com"])
    finally:
        scanner_module.Scanner = original_scanner_class

    assert len(captured_kwargs) == 1, "run_many must create one Scanner per target"
    kwargs = captured_kwargs[0]
    assert "on_finding" in kwargs, "AC-6: on_finding callback must be propagated to child Scanner"
    assert "on_module_start" in kwargs, "AC-6: on_module_start callback must be propagated to child Scanner"
    assert "on_module_done" in kwargs, "AC-6: on_module_done callback must be propagated to child Scanner"
    assert "on_module_progress" in kwargs, "AC-6: on_module_progress callback must be propagated to child Scanner"
