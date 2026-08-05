from __future__ import annotations

import asyncio
import base64
import secrets

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.webshells.base import BaseDetector
from plecost.modules.webshells.wordlists import MU_PLUGINS_NAMES

_MU_PLUGINS_BASE = "/wp-content/mu-plugins/"
_PROBE_A = "/wp-content/mu-plugins/__plecost_probe_a__.php"
_PROBE_B = "/wp-content/mu-plugins/__plecost_probe_b__.php"
_TOLERANCE = 0.05
_CC_PARAMS = ["password", "cmd", "c", "pass", "p", "key"]


async def _confirm_china_chopper(
    http: PlecostHTTPClient, url: str
) -> tuple[bool, str]:
    """
    Sends POST probes to confirm China Chopper-style webshell execution.

    For each candidate parameter, tries two payloads:
      1. printf(strrev("REVERSED_NONCE")) — PHP reverses it back to the forward nonce.
         A WAF that blindly reflects the POST body returns the reversed_nonce,
         which does NOT match the forward nonce we check → no false positive.
      2. eval(base64_decode(...)) wrapping the same strrev payload.

    Verification: `if nonce in r.text` — only PHP executing strrev() can produce
    the forward nonce from a payload that contains only the reversed nonce.

    Returns (True, param_name) on first confirmation, (False, "") if none confirm.
    All exceptions are swallowed silently.
    """
    nonce = secrets.token_hex(8)          # "ab12cd34ef56ab78"  — we verify this in r.text
    reversed_nonce = nonce[::-1]          # "87ba65fe43dc21ba"  — goes into the payload

    for param in _CC_PARAMS:
        # Payload 1: PHP executes strrev() → produces the forward nonce
        direct_payload = f'printf(strrev("{reversed_nonce}"));'
        try:
            r = await http.post(url, data={param: direct_payload})
            if nonce in r.text:
                return (True, param)
        except Exception:
            pass

        # Payload 2: eval(base64_decode(...)) wrapping the same strrev payload
        b64_inner = base64.b64encode(direct_payload.encode()).decode()
        b64_payload = f'eval(base64_decode("{b64_inner}"));'
        try:
            r = await http.post(url, data={param: b64_payload})
            if nonce in r.text:
                return (True, param)
        except Exception:
            pass

    return (False, "")


class MuPluginsDetector(BaseDetector):
    """
    Detects PHP webshells in wp-content/mu-plugins/ — deep mode only.

    In fast mode: returns [] immediately (no HTTP requests).
    In deep mode:
      1. Probes catch-all to detect dynamic 200s (CDN/WAF behaviour).
      2. GETs each name in MU_PLUGINS_NAMES; skips catch-all matches.
      3. For every GET 200 hit that passes the catch-all filter, sends POST
         probes (_confirm_china_chopper) to confirm remote code execution.
      4. Only emits PC-WSH-150 CRITICAL when POST probe returns the nonce.

    Must-Use plugins load automatically and are invisible in the WP admin panel.
    This is a primary vector for persistent WordPress backdoors (Sucuri 2024-2025).
    """

    name = "mu_plugins"
    requires_auth = False

    async def detect(
        self, ctx: ScanContext, http: PlecostHTTPClient
    ) -> list[Finding]:
        # AC-1: fast mode guard — no HTTP requests at all
        if not ctx.opts.deep:
            return []

        findings: list[Finding] = []
        sem = asyncio.Semaphore(ctx.opts.concurrency)

        # AC-10: catch-all logic preserved in deep mode
        catch_all_size = await self._detect_catch_all(
            http,
            ctx.url + _PROBE_A,
            ctx.url + _PROBE_B,
            tolerance=_TOLERANCE,
        )

        checked = [0]
        total = len(MU_PLUGINS_NAMES)

        async def _probe(name: str) -> None:
            async with sem:
                try:
                    url = ctx.url + _MU_PLUGINS_BASE + name
                    r = await http.get(url)
                    if r.status_code != 200:
                        return

                    # AC-10: apply catch-all size filter
                    if catch_all_size is not None:
                        hit_size = len(r.content)
                        max_s = max(hit_size, catch_all_size)
                        if max_s == 0 or abs(hit_size - catch_all_size) / max_s < _TOLERANCE:
                            return

                    # AC-3: run POST confirmation probe for every GET 200 hit
                    confirmed, probe_param = await _confirm_china_chopper(http, url)

                    # AC-5: skip silently if not confirmed
                    if not confirmed:
                        return

                    # AC-4 / AC-7 / AC-8: emit finding only on confirmed RCE
                    findings.append(Finding(
                        id="PC-WSH-150",
                        remediation_id="REM-WSH-150",
                        title="China Chopper webshell confirmed in wp-content/mu-plugins",
                        severity=Severity.CRITICAL,
                        description=(
                            f"China Chopper webshell confirmed at `{url}` — "
                            "remote code execution verified via POST probe. "
                            "Must-Use plugins load automatically on every WordPress request "
                            "and are hidden from the admin plugin list — making them a preferred "
                            "location for persistent backdoors."
                        ),
                        evidence={
                            "url": url,
                            "probe_param": probe_param,
                            "confirmed": True,
                        },
                        remediation=(
                            "Immediately remove the malicious file from wp-content/mu-plugins/. "
                            "Rotate all credentials, audit server logs, and consider a full "
                            "reinstallation. Legitimate must-use plugins are intentionally "
                            "installed by developers and should be documented."
                        ),
                        references=[
                            "https://blog.sucuri.net/2025/03/hidden-malware-strikes-again-mu-plugins-under-attack.html",
                            "https://www.bleepingcomputer.com/news/security/hackers-abuse-wordpress-mu-plugins-to-hide-malicious-code/",
                        ],
                        cvss_score=9.8,
                        module="webshells",
                    ))
                except Exception:
                    pass
                finally:
                    checked[0] += 1
                    ctx.report_progress("mu_plugins", checked[0], total)

        await asyncio.gather(*[_probe(name) for name in MU_PLUGINS_NAMES])
        return findings
