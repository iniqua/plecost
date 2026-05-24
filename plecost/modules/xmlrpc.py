from __future__ import annotations
import asyncio
import re
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule

# Regex to extract faultCode from WordPress XML-RPC fault responses.
# WordPress uses <int> or <i4> for faultCode values.
# faultCode=405 → method disabled via xmlrpc_enabled filter (application-level protection)
# faultCode=403 → wrong credentials but method is functional (no protection)
_FAULT_CODE_RE = re.compile(
    r'<name>faultCode</name>\s*<value>\s*<(?:int|i4)>\s*(-?\d+)',
    re.S
)

_LIST_METHODS_PAYLOAD = """<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>"""

_AUTH_TEST_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>plecost_dummy_user</string></value></param>
    <param><value><string>plecost_dummy_pass</string></value></param>
  </params>
</methodCall>"""


class XMLRPCModule(ScanModule):
    name = "xmlrpc"
    depends_on = ["fingerprint"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress and not ctx.opts.force:
            return

        xmlrpc_url = f"{ctx.url}/xmlrpc.php"

        # Check if accessible
        try:
            r = await http.get(xmlrpc_url)
            if r.status_code not in (200, 405):
                return
        except Exception:
            return

        ctx.xmlrpc_accessible = True
        ctx.add_finding(Finding(
            id="PC-XMLRPC-001", remediation_id="REM-XMLRPC-001",
            title="XML-RPC endpoint is accessible",
            severity=Severity.MEDIUM,
            description="The xmlrpc.php endpoint is publicly accessible.",
            evidence={"url": xmlrpc_url, "status_code": r.status_code},
            remediation="Disable XML-RPC if not needed.",
            references=["https://kinsta.com/blog/xmlrpc-php/"],
            cvss_score=5.3, module=self.name
        ))

        # ---------------------------------------------------------
        # ACTIVE GUARDRAIL TEST: Rate Limiting & Brute Force
        # ---------------------------------------------------------
        is_rate_limited = False
        blocked_status = None
        blocked_on_attempt = 0

        headers = {'Content-Type': 'application/xml'}

        for attempt in range(1, 6):
            try:
                r_auth = await http.post(xmlrpc_url, content=_AUTH_TEST_PAYLOAD, headers=headers)

                # If we get a WAF/Security block via HTTP status
                if r_auth.status_code in [403, 429, 406]:
                    is_rate_limited = True
                    blocked_status = r_auth.status_code
                    blocked_on_attempt = attempt
                    break

                # WordPress can disable authenticated methods via the xmlrpc_enabled filter.
                # In that case the server returns HTTP 200 (or 405) with a fault XML body
                # containing faultCode=405 — NOT a WAF block.
                # faultCode=405 → method disabled at application level → real protection
                # faultCode=403 → wrong credentials, method is functional → no protection
                if not is_rate_limited and "faultCode" in r_auth.text:
                    m = _FAULT_CODE_RE.search(r_auth.text)
                    if m:
                        fault_code = int(m.group(1))
                        if fault_code == 405:
                            is_rate_limited = True
                            blocked_status = fault_code
                            blocked_on_attempt = attempt
                            break

                # Small delay to simulate typical login attempts
                await asyncio.sleep(0.5)
            except Exception:
                # Connection dropped completely (often Fail2Ban behavior)
                is_rate_limited = True
                blocked_on_attempt = attempt
                break

        if not is_rate_limited:
            ctx.add_finding(Finding(
                id="PC-XMLRPC-005", remediation_id="REM-XMLRPC-005",
                title="XML-RPC Brute-Force Protection Missing",
                severity=Severity.HIGH,
                description="The xmlrpc.php endpoint is accessible and does not appear to enforce rate limiting on failed authentication attempts. It successfully processed 5 consecutive failed logins.",
                evidence={"url": xmlrpc_url, "test_attempts": 5, "status": "No block detected"},
                remediation="Implement rate limiting (e.g., Fail2Ban, WAF) or disable XML-RPC entirely.",
                references=["https://kinsta.com/blog/xmlrpc-php/#xmlrpc-brute-force-attacks"],
                cvss_score=7.5, module=self.name
            ))
        else:
            # Optional: Add an informational finding that guardrails ARE active
            if blocked_status == 405:
                protection_type = "WordPress application-level (methods disabled via xmlrpc_enabled filter)"
            else:
                protection_type = "WAF/Rate-limiter"
            ctx.add_finding(Finding(
                id="PC-XMLRPC-006", remediation_id="REM-XMLRPC-006",
                title="XML-RPC Guardrails Active",
                severity=Severity.INFO,
                description=f"The xmlrpc.php endpoint is accessible, but active defenses (WAF/Rate Limiting) blocked repeated authentication attempts on attempt {blocked_on_attempt}.",
                evidence={
                    "url": xmlrpc_url,
                    "blocked_on_attempt": blocked_on_attempt,
                    "status_code": blocked_status,
                    "protection_type": protection_type,
                },
                remediation="No immediate action required, but consider disabling XML-RPC if it is completely unused.",
                references=[], cvss_score=0.0, module=self.name
            ))

        # ---------------------------------------------------------
        # Standard Payload Tests (listMethods, pingback, multicall)
        # ---------------------------------------------------------
        try:
            r = await http.post(xmlrpc_url, content=_LIST_METHODS_PAYLOAD, headers=headers)
            if "methodResponse" in r.text:
                ctx.add_finding(Finding(
                    id="PC-XMLRPC-003", remediation_id="REM-XMLRPC-003",
                    title="XML-RPC system.listMethods exposed",
                    severity=Severity.LOW,
                    description="system.listMethods is enabled, exposing the full list of available XML-RPC methods.",
                    evidence={"url": xmlrpc_url},
                    remediation="Disable system.listMethods or restrict XML-RPC access entirely.",
                    references=[], cvss_score=3.1, module=self.name
                ))

                # Check for pingback.ping
                if "pingback.ping" in r.text:
                    ctx.add_finding(Finding(
                        id="PC-XMLRPC-002", remediation_id="REM-XMLRPC-002",
                        title="XML-RPC pingback.ping enabled (DoS amplification)",
                        severity=Severity.HIGH,
                        description="pingback.ping is enabled, allowing this server to be used as a DDoS amplification vector.",
                        evidence={"url": xmlrpc_url, "method": "pingback.ping"},
                        remediation="Disable pingbacks: add_filter('xmlrpc_methods', function($m){ unset($m['pingback.ping']); return $m; });",
                        references=["https://www.imperva.com/learn/ddos/wordpress-pingback-ddos/"],
                        cvss_score=7.5, module=self.name
                    ))

                # Check for system.multicall
                if "system.multicall" in r.text:
                    ctx.xmlrpc_multicall_available = True
                    ctx.add_finding(Finding(
                        id="PC-XMLRPC-004", remediation_id="REM-XMLRPC-004",
                        title="XML-RPC system.multicall enabled (Brute-force amplification)",
                        severity=Severity.HIGH,
                        description="The system.multicall method is enabled, allowing attackers to bypass rate limits by sending thousands of credentials in a single request.",
                        evidence={"url": xmlrpc_url, "method": "system.multicall"},
                        remediation="Disable system.multicall: add_filter('xmlrpc_methods', function($m){ unset($m['system.multicall']); return $m; });",
                        references=["https://kinsta.com/blog/xmlrpc-php/#xmlrpc-brute-force-attacks"],
                        cvss_score=7.5, module=self.name
                    ))

                # AC-6: PC-XMLRPC-007 — publishing methods exposed
                _PUBLISH_METHODS = {"wp.newPost", "metaWeblog.newPost", "blogger.newPost"}
                found_publish = [m for m in _PUBLISH_METHODS if m in r.text]
                if found_publish:
                    ctx.add_finding(Finding(
                        id="PC-XMLRPC-007", remediation_id="REM-XMLRPC-007",
                        title="XML-RPC publishing methods exposed",
                        severity=Severity.LOW,
                        description=(
                            "One or more XML-RPC publishing methods are exposed: "
                            + ", ".join(sorted(found_publish))
                            + ". These methods can be abused to publish content "
                            "as any user that can be authenticated."
                        ),
                        evidence={"url": xmlrpc_url, "methods": sorted(found_publish)},
                        remediation=(
                            "Disable XML-RPC publishing methods or restrict XML-RPC access entirely: "
                            "add_filter('xmlrpc_methods', function($m){ "
                            "unset($m['wp.newPost'], $m['metaWeblog.newPost'], $m['blogger.newPost']); "
                            "return $m; });"
                        ),
                        references=["https://kinsta.com/blog/xmlrpc-php/"],
                        cvss_score=3.1, module=self.name
                    ))
        except Exception:
            pass