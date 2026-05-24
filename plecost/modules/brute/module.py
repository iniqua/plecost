"""
Brute Force module (brute subpackage) — AC-9

This module is ONLY active when ScanOptions.brute_force=True.

It runs one attack vector:
  1. XMLRPCAttacker: brute-force via XML-RPC (if ctx.xmlrpc_accessible)

NOTE: WPLoginAttacker is NOT used here — BruteForceModule (brute_force.py)
already attacks wp-login.php when brute_force=True. Running both concurrently
would be a dual-attack on the same endpoint (F-1 fix).

Findings:
  PC-BRUTE-001 (CRITICAL) — credentials found via XML-RPC
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
        # WPLoginAttacker is intentionally omitted — BruteForceModule covers wp-login.php
        if ctx.xmlrpc_accessible:
            xmlrpc_findings = await XMLRPCAttacker().attack(ctx, http, usernames, passwords)
            all_findings.extend(xmlrpc_findings)

        # Deduplicate findings by ID before emitting (F-3 fix)
        emitted_ids: set[str] = set()
        for finding in all_findings:
            if finding.id not in emitted_ids:
                ctx.add_finding(finding)
                emitted_ids.add(finding.id)

        # Determine overall protection state
        has_success = any(f.id in ("PC-BRUTE-001", "PC-BRUTE-002") for f in all_findings)
        has_protection = any(f.id == "PC-BRUTE-004" for f in all_findings)

        if not has_success and not has_protection and ctx.xmlrpc_accessible:
            # No credentials found AND no protection detected on XML-RPC
            # (wp-login.php protection is assessed by BruteForceModule)
            ctx.add_finding(Finding(
                id="PC-BRUTE-003", remediation_id="REM-BRUTE-003",
                title="No brute force protection detected on XML-RPC endpoint",
                severity=Severity.HIGH,
                description=(
                    "Multiple credential attempts were made against the WordPress XML-RPC "
                    "endpoint without triggering any rate limiting or blocking response. "
                    "This indicates the site lacks brute force protection on XML-RPC."
                ),
                evidence={
                    "xmlrpc_tested": str(ctx.xmlrpc_accessible),
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
