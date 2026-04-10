from __future__ import annotations
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule

_WAF_SIGNATURES: list[tuple[str, dict[str, str]]] = [
    ("Cloudflare",   {"server": "cloudflare", "cf-ray": ""}),
    ("Sucuri",       {"x-sucuri-id": ""}),
    ("Wordfence",    {"x-wf-sid": ""}),
    ("Imperva",      {"x-iinfo": ""}),
    ("AWS WAF",      {"x-amzn-requestid": "", "x-amz-cf-id": ""}),
    ("Akamai",       {"x-akamai-transformed": ""}),
    ("Fastly",       {"x-fastly-request-id": "", "fastly-restarts": ""}),
]


class WAFModule(ScanModule):
    name = "waf"
    depends_on: list[str] = []

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        try:
            r = await http.get(ctx.url + "/")
        except Exception:
            return
        headers = {k.lower(): v.lower() for k, v in r.headers.items()}
        for waf_name, sig in _WAF_SIGNATURES:
            # Check: all required header keys present (those with empty string value = just presence check)
            # OR all header values start with expected value (for non-empty values)
            presence_keys = [k for k, v in sig.items() if v == ""]
            value_keys = [(k, v) for k, v in sig.items() if v != ""]
            matched = (
                (len(presence_keys) > 0 and all(k in headers for k in presence_keys)) or
                (len(value_keys) > 0 and all(headers.get(k, "").startswith(v) for k, v in value_keys))
            )
            if matched:
                ctx.waf_detected = waf_name
                ctx.add_finding(Finding(
                    id="PC-WAF-001", remediation_id="REM-WAF-001",
                    title=f"WAF detected: {waf_name}",
                    severity=Severity.INFO,
                    description=f"{waf_name} WAF/CDN detected from response headers.",
                    evidence={"headers": dict(r.headers)},
                    remediation="WAF detected. Some checks may be blocked or return false negatives.",
                    references=[], cvss_score=None, module=self.name
                ))
                return
