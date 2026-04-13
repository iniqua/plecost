from __future__ import annotations
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule

_LIST_METHODS_PAYLOAD = """<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
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

        ctx.add_finding(Finding(
            id="PC-XMLRPC-001", remediation_id="REM-XMLRPC-001",
            title="XML-RPC endpoint is accessible",
            severity=Severity.MEDIUM,
            description="The xmlrpc.php endpoint is publicly accessible, enabling brute-force and DDoS amplification attacks.",
            evidence={"url": xmlrpc_url, "status_code": r.status_code},
            remediation="Disable XML-RPC if not needed. Add to .htaccess: <Files xmlrpc.php>\\nOrder Deny,Allow\\nDeny from all\\n</Files>",
            references=["https://www.wordfence.com/learn/xmlrpc-php/"],
            cvss_score=5.3, module=self.name
        ))

        # Check system.listMethods
        try:
            r = await http.post(
                xmlrpc_url,
                content=_LIST_METHODS_PAYLOAD,
                headers={"Content-Type": "text/xml"}
            )
            if r.status_code == 200 and "<methodResponse>" in r.text:
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
        except Exception:
            pass
