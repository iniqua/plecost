"""
Emergency Scripts detector — AC-8

Checks for common emergency/reset PHP scripts that attackers leave or
that administrators accidentally leave exposed after password resets.

Paths checked:
  /emergency.php       → PC-EMRG-001
  /wp-emergency.php    → PC-EMRG-002
  /reset.php           → PC-EMRG-003
  /pw-reset.php        → PC-EMRG-004
  /emergency-reset.php → PC-EMRG-005

Detection: any of the PHP invariants in body[:512]:
  - wp_hash_password\\s*\\(
  - update_user_meta\\s*\\(
  - <form
  - <input
"""
from __future__ import annotations

import asyncio
import re

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule
from plecost.i18n import t

# PHP invariant signatures — any match confirms emergency script
_SIGNATURES: list[re.Pattern[str]] = [
    re.compile(r'wp_hash_password\s*\(', re.I),
    re.compile(r'update_user_meta\s*\(', re.I),
    re.compile(r'<form', re.I),
    re.compile(r'<input', re.I),
]

# (path, finding_id, rem_id)
_EMERGENCY_PATHS: list[tuple[str, str, str]] = [
    ("/emergency.php",       "PC-EMRG-001", "REM-EMRG-001"),
    ("/wp-emergency.php",    "PC-EMRG-002", "REM-EMRG-002"),
    ("/reset.php",           "PC-EMRG-003", "REM-EMRG-003"),
    ("/pw-reset.php",        "PC-EMRG-004", "REM-EMRG-004"),
    ("/emergency-reset.php", "PC-EMRG-005", "REM-EMRG-005"),
]


def _has_emergency_signature(body: str) -> bool:
    """Return True if any PHP invariant signature matches in the first 512 bytes."""
    sample = body[:512]
    return any(sig.search(sample) for sig in _SIGNATURES)


class EmergencyScriptsModule(ScanModule):
    name = "emergency_scripts"
    depends_on = ["fingerprint"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress and not ctx.opts.force:
            return

        await asyncio.gather(*[
            self._check(ctx, http, path, finding_id, rem_id)
            for path, finding_id, rem_id in _EMERGENCY_PATHS
        ], return_exceptions=True)

    async def _check(
        self,
        ctx: ScanContext,
        http: PlecostHTTPClient,
        path: str,
        finding_id: str,
        rem_id: str,
    ) -> None:
        url = ctx.url + path
        try:
            r = await http.get(url)
            if r.status_code != 200:
                return
            if not _has_emergency_signature(r.text):
                return

            id_key = finding_id.lower().replace("-", "_")
            ctx.add_finding(Finding(
                id=finding_id, remediation_id=rem_id,
                title=t(f"findings.{id_key}.title"),
                severity=Severity.HIGH,
                description=t(f"findings.{id_key}.description"),
                evidence={"url": url, "status_code": r.status_code},
                remediation=t(f"findings.{id_key}.remediation"),
                references=[
                    "https://wordpress.org/support/article/hardening-wordpress/"
                ],
                cvss_score=8.8, module=self.name
            ))
        except Exception:
            pass
