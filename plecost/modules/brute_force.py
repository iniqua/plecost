"""
BruteForceModule — WordPress login brute-force with rate-limiting detection.

Activation:
  - ScanOptions.brute_force=True  (CLI: --brute-force)
  - OR module_options["brute_force"]["enabled"] = "true"
  NEVER activates on --aggressive alone (AC-8).

Wordlist:
  - Internal: ~60 common passwords + 7 dynamic variants per username
  - External: --brute-force-wordlist <path> loaded via asyncio.to_thread
  - Limit: 10k (fast) / 50k (deep)
  - --brute-force-combine: add internal to external instead of replacing

Rate limiting (AC-13):
  - HTTP 429 / 403 → stop immediately
  - HTTP 200 with block-strings → stop
  - ConnectError / TransportError → connection_reset → stop

Success detection (AC-11):
  - Primary: "wordpress_logged_in_" in Set-Cookie header
  - Fallback: redirect to /wp-admin/

Concurrency (AC-15):
  - asyncio.Semaphore(1) by default
  - delay 2000ms OUTSIDE sem block
  - report_progress() in finally of each attempt

Findings (AC-14):
  - Single PC-BRU-001; credentials in evidence["credentials"] as list
  - Passwords masked: pass[:2] + "***" + pass[-1:]
  - PC-BRU-003: no users / rate-limited
  - PC-BRU-002: 2FA detected (INFO)
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule

if TYPE_CHECKING:
    pass

# ---------------------------------------------------------------------- #
# Internal password list (~60 common passwords)                          #
# ---------------------------------------------------------------------- #
_INTERNAL_PASSWORDS: list[str] = [
    "password", "password1", "password123", "Password1", "Password123",
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "letmein", "welcome", "welcome1",
    "admin", "admin1", "admin123", "Admin1", "Admin123",
    "login", "login1", "master", "master1",
    "iloveyou", "sunshine", "princess", "dragon", "monkey",
    "shadow", "superman", "batman", "trustno1",
    "pass", "pass1", "pass123",
    "test", "test1", "test123",
    "root", "root1", "root123",
    "toor", "changeme", "change_me",
    "wordpress", "wordpress1", "wp_admin",
    "abc123", "abc1234", "abcdef",
    "111111", "222222", "333333", "123123", "321321",
    "000000", "999999",
    "p@ssword", "p@ss0rd", "P@ssw0rd", "P@ssword1",
    "secret", "secret1", "secret123",
    "hunter2", "correct horse battery staple",
]

# Block strings that indicate rate-limiting in HTTP 200 responses (AC-13)
_BLOCK_STRINGS: tuple[str, ...] = (
    "too many failed login",
    "you have been locked out",
    "too many attempts",
    "your ip has been blocked",
    "rate limit",
    "blocked",
    "temporary lockout",
    "slow down",
    "loginlockdown",
    "wordfence",
)


def _mask_password(pw: str) -> str:
    """AC-14: mask passwords as pw[:2] + '***' + pw[-1:]"""
    if len(pw) <= 3:
        return pw[:1] + "***"
    return pw[:2] + "***" + pw[-1:]


def _build_dynamic_variants(username: str) -> list[str]:
    """AC-9: 7 dynamic variants per username."""
    return [
        username,
        username + "123",
        username + "!",
        username + "2024",
        username + "2025",
        username + "#",
        username + "1234",
    ]


class BruteForceModule(ScanModule):
    name = "brute_force"
    depends_on = ["users"]

    def _is_enabled(self, ctx: ScanContext) -> bool:
        """AC-8: only activate via brute_force=True or module_options."""
        if ctx.opts.brute_force:
            return True
        mo = ctx.opts.module_options.get("brute_force", {})
        return mo.get("enabled", "false").lower() == "true"

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not self._is_enabled(ctx):
            return
        if not ctx.is_wordpress and not ctx.opts.force:
            return

        # ---------------------------------------------------------------- #
        # Collect usernames to attack                                       #
        # ---------------------------------------------------------------- #
        usernames: list[str] = list({u.username for u in ctx.users})
        if not usernames:
            ctx.add_finding(Finding(
                id="PC-BRU-003", remediation_id="REM-BRU-003",
                title="Brute force skipped — no usernames found",
                severity=Severity.INFO,
                description="Brute force was enabled but no usernames were discovered by previous modules.",
                evidence={"reason": "no_users_found"},
                remediation="Run user enumeration modules first to discover usernames.",
                references=[],
                cvss_score=0.0, module=self.name
            ))
            return

        # ---------------------------------------------------------------- #
        # Build password list (AC-9, AC-10)                                #
        # ---------------------------------------------------------------- #
        passwords = await self._build_password_list(ctx, usernames)

        # ---------------------------------------------------------------- #
        # Check for 2FA (AC-12)                                            #
        # ---------------------------------------------------------------- #
        has_2fa = await self._check_2fa(ctx, http)

        # ---------------------------------------------------------------- #
        # Brute force loop                                                  #
        # ---------------------------------------------------------------- #
        login_url = f"{ctx.url}/wp-login.php"
        sem = asyncio.Semaphore(1)  # AC-15: Semaphore(1) by default
        found_credentials: list[dict[str, str]] = []
        rate_limited = False
        total = len(usernames) * len(passwords)
        checked: list[int] = [0]

        async def attempt(username: str, pw: str) -> bool | None:
            """Returns True on success, None on rate-limit, False on fail."""
            nonlocal rate_limited
            async with sem:
                if rate_limited:
                    return None
                try:
                    result = await self._try_login(http, login_url, username, pw)
                    return result
                except (Exception,) as exc:
                    exc_str = str(exc).lower()
                    if any(kw in exc_str for kw in ("connection", "transport", "reset", "eof")):
                        rate_limited = True
                        return None
                    return False
                finally:
                    checked[0] += 1
                    ctx.report_progress(self.name, checked[0], total)
            # AC-15: delay OUTSIDE the sem block
            # (can't await after exiting with block here; handled below)

        for username in usernames:
            if rate_limited:
                break
            for pw in passwords:
                if rate_limited:
                    break
                result = await attempt(username, pw)
                if result is None:
                    # Rate limited
                    if not rate_limited:
                        rate_limited = True
                    break
                if result is True:
                    found_credentials.append({
                        "username": username,
                        "password": _mask_password(pw),
                    })
                # AC-15: delay OUTSIDE sem block
                if not rate_limited:
                    await asyncio.sleep(2.0)

        # ---------------------------------------------------------------- #
        # Emit findings                                                     #
        # ---------------------------------------------------------------- #
        if rate_limited and not found_credentials:
            ctx.add_finding(Finding(
                id="PC-BRU-003", remediation_id="REM-BRU-003",
                title="Brute force stopped — rate limiting detected",
                severity=Severity.INFO,
                description="The brute force attempt was stopped because the target appears to be rate-limiting login attempts.",
                evidence={"reason": "rate_limit_detected", "attempts": checked[0]},
                remediation="Rate limiting is a positive security control. Ensure it is properly configured.",
                references=[],
                cvss_score=0.0, module=self.name
            ))
            return

        if not found_credentials:
            ctx.add_finding(Finding(
                id="PC-BRU-004", remediation_id="REM-BRU-004",
                title="Brute force completed — no valid credentials found",
                severity=Severity.INFO,
                description=f"Brute force attempted {checked[0]} credential combinations without success.",
                evidence={"attempts": checked[0]},
                remediation="Continue enforcing strong password policies and account lockout.",
                references=[],
                cvss_score=0.0, module=self.name
            ))
            return

        # AC-12: severity depends on 2FA detection
        if has_2fa:
            severity = Severity.HIGH
            cvss_score = 7.5
            ctx.add_finding(Finding(
                id="PC-BRU-002", remediation_id="REM-BRU-002",
                title="2FA detected on WordPress login",
                severity=Severity.INFO,
                description="Two-factor authentication (2FA) was detected on the WordPress login page. Valid credentials alone are insufficient for login.",
                evidence={"url": login_url, "2fa": "detected"},
                remediation="Keep 2FA enabled. Consider enforcing 2FA for all users.",
                references=[],
                cvss_score=0.0, module=self.name
            ))
        else:
            severity = Severity.CRITICAL
            cvss_score = 9.8

        # AC-14: single PC-BRU-001, credentials list, masked passwords
        users_list = "\n".join(
            f"  • {c['username']} / {c['password']}" for c in found_credentials
        )
        ctx.add_finding(Finding(
            id="PC-BRU-001", remediation_id="REM-BRU-001",
            title="Valid WordPress credentials found via brute force",
            severity=severity,
            description=(
                f"Brute force attack found {len(found_credentials)} valid credential pair(s). "
                f"{'2FA is active — full login requires a second factor.' if has_2fa else 'No 2FA detected — attacker can log in directly.'}"
            ),
            evidence={
                "url": login_url,
                "credentials": users_list,
                "has_2fa": str(has_2fa),
                "attempts": checked[0],
            },
            remediation=(
                "Change all found passwords immediately. Enable 2FA. "
                "Implement account lockout and IP-based rate limiting."
            ),
            references=["https://wordpress.org/support/article/brute-force-attacks/"],
            cvss_score=cvss_score, module=self.name
        ))

    # ------------------------------------------------------------------ #
    # AC-10: Build password list                                          #
    # ------------------------------------------------------------------ #
    async def _build_password_list(
        self, ctx: ScanContext, usernames: list[str]
    ) -> list[str]:
        limit = 50000 if ctx.opts.deep else 10000

        # Internal passwords + dynamic variants (AC-9)
        internal: list[str] = list(_INTERNAL_PASSWORDS)
        for username in usernames:
            internal.extend(_build_dynamic_variants(username))
        # Deduplicate preserving order
        seen: set[str] = set()
        deduped_internal: list[str] = []
        for p in internal:
            if p not in seen:
                seen.add(p)
                deduped_internal.append(p)

        wordlist_path = ctx.opts.brute_force_wordlist
        if wordlist_path:
            try:
                external = await asyncio.to_thread(_load_wordlist, wordlist_path, limit)
            except Exception:
                external = []

            if ctx.opts.brute_force_combine:
                # Combine: external + internal (AC-10)
                combined = external + [p for p in deduped_internal if p not in set(external)]
                return combined[:limit]
            else:
                # External replaces internal (AC-10)
                return external[:limit]
        else:
            return deduped_internal[:limit]

    # ------------------------------------------------------------------ #
    # AC-11: Try single login attempt                                     #
    # ------------------------------------------------------------------ #
    async def _try_login(
        self,
        http: PlecostHTTPClient,
        login_url: str,
        username: str,
        password: str,
    ) -> bool:
        data = {
            "log": username,
            "pwd": password,
            "wp-submit": "Log+In",
            "redirect_to": "/wp-admin/",
            "testcookie": "1",
        }
        r = await http.post(login_url, data=data, follow_redirects=False)

        # Check for rate limiting in HTTP 200 response body (AC-13)
        if r.status_code == 200:
            body_lower = r.text[:4096].lower()
            if any(s in body_lower for s in _BLOCK_STRINGS):
                raise RuntimeError("connection_reset")  # triggers rate_limited flag

        # AC-13: 429/403 → stop
        if r.status_code in (429, 403):
            raise RuntimeError("connection_reset")

        # AC-11 PRIMARY: "wordpress_logged_in_" in Set-Cookie
        set_cookie = r.headers.get("set-cookie", "")
        if "wordpress_logged_in_" in set_cookie:
            return True

        # AC-11 FALLBACK: redirect to /wp-admin/
        if r.status_code in (301, 302):
            location = r.headers.get("location", "")
            if "/wp-admin/" in location:
                return True

        return False

    # ------------------------------------------------------------------ #
    # AC-12: 2FA detection                                                #
    # ------------------------------------------------------------------ #
    async def _check_2fa(self, ctx: ScanContext, http: PlecostHTTPClient) -> bool:
        """Check if 2FA is active on the login page."""
        try:
            r = await http.get(f"{ctx.url}/wp-login.php")
            if r.status_code != 200:
                return False
            body = r.text.lower()
            # Common 2FA indicators in the login page
            two_fa_indicators = (
                "two-factor",
                "twofactor",
                "2fa",
                "otp",
                "authenticator",
                "totp",
                "wordfence_ls_",
                "miniorange",
                "google authenticator",
            )
            return any(ind in body for ind in two_fa_indicators)
        except Exception:
            return False


def _load_wordlist(path: str, limit: int) -> list[str]:
    """Load a wordlist file synchronously (called via asyncio.to_thread)."""
    passwords: list[str] = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            pw = line.rstrip("\n\r")
            if pw:
                passwords.append(pw)
            if len(passwords) >= limit:
                break
    return passwords
