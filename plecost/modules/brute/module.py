"""
Brute Force module (brute subpackage) — AC-9

This module is ONLY active when ScanOptions.brute_force=True.

It runs two attack vectors in sequence:
  1. XMLRPCAttacker: brute-force via XML-RPC (if ctx.xmlrpc_accessible)
  2. WPLoginAttacker: brute-force via wp-login.php

Findings:
  PC-BRUTE-001 (CRITICAL) — credentials found via XML-RPC
  PC-BRUTE-002 (CRITICAL) — credentials found via wp-login
  PC-BRUTE-003 (HIGH)     — no brute force protection detected
  PC-BRUTE-004 (INFO)     — protection confirmed (rate limiting)
"""
from __future__ import annotations

from pathlib import Path

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule
from plecost.modules.brute.attackers.xmlrpc import XMLRPCAttacker
from plecost.modules.brute.attackers.wp_login import WPLoginAttacker

_WORDLIST_PATH = Path(__file__).parent / "wordlists" / "fast.txt"


def _load_fast_wordlist() -> list[str]:
    """Load the internal fast wordlist."""
    try:
        return [
            line.strip()
            for line in _WORDLIST_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except Exception:
        return ["admin", "password", "123456", "wordpress"]


class BruteModule(ScanModule):
    name = "brute"
    depends_on = ["fingerprint", "users", "xmlrpc"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        # AC-9: only activate when brute_force=True
        if not ctx.opts.brute_force:
            return
        if not ctx.is_wordpress and not ctx.opts.force:
            return

        usernames: list[str] = list({u.username for u in ctx.users})
        if not usernames:
            # No users discovered — cannot brute force
            return

        passwords = _load_fast_wordlist()
        all_findings: list[Finding] = []

        # Attack 1: XML-RPC (if accessible)
        if ctx.xmlrpc_accessible:
            xmlrpc_findings = await XMLRPCAttacker().attack(ctx, http, usernames, passwords)
            all_findings.extend(xmlrpc_findings)

        # Attack 2: wp-login.php
        wp_login_findings = await WPLoginAttacker().attack(ctx, http, usernames, passwords)
        all_findings.extend(wp_login_findings)

        # Emit all findings from attackers
        for finding in all_findings:
            ctx.add_finding(finding)

        # Determine overall protection state
        has_success = any(f.id in ("PC-BRUTE-001", "PC-BRUTE-002") for f in all_findings)
        has_protection = any(f.id == "PC-BRUTE-004" for f in all_findings)

        if not has_success and not has_protection:
            # No credentials found AND no protection detected
            ctx.add_finding(Finding(
                id="PC-BRUTE-003", remediation_id="REM-BRUTE-003",
                title="No brute force protection detected on login endpoints",
                severity=Severity.HIGH,
                description=(
                    "Multiple credential attempts were made against the WordPress login "
                    "endpoints without triggering any rate limiting or blocking response. "
                    "This indicates the site lacks brute force protection."
                ),
                evidence={
                    "xmlrpc_tested": str(ctx.xmlrpc_accessible),
                    "wp_login_tested": "true",
                    "usernames_tested": str(len(usernames)),
                },
                remediation=(
                    "Implement account lockout and rate limiting. Use a security plugin "
                    "such as Wordfence or limit-login-attempts-reloaded. "
                    "Consider disabling XML-RPC if not needed."
                ),
                references=[
                    "https://wordpress.org/support/article/brute-force-attacks/",
                    "https://kinsta.com/blog/wordpress-login-page/#how-to-protect-your-wordpress-login-page",
                ],
                cvss_score=7.5, module=self.name
            ))
