from __future__ import annotations

import re

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule

_SKIMMER_RE = re.compile(r'(magecart|skimmer|cc-number|cardnumber)', re.IGNORECASE)
_IFRAME_RE = re.compile(r'<iframe[^>]+src=["\']https?://([^"\']+)["\']', re.IGNORECASE)
_SECRET_RE = re.compile(r'api[_-]?key\s*[=:]\s*["\'][A-Za-z0-9]{20,}', re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)

# Domains that are legitimate and should not trigger PC-CNT-002
_TRUSTED_IFRAME_DOMAINS = frozenset({
    "google.com", "www.google.com", "maps.google.com",
    "googletagmanager.com", "www.googletagmanager.com",
    "googleapis.com", "www.googleapis.com", "apis.google.com",
    "youtube.com", "www.youtube.com", "youtu.be", "youtube-nocookie.com",
    "vimeo.com", "player.vimeo.com",
    "facebook.com", "www.facebook.com",
    "twitter.com", "platform.twitter.com", "x.com",
    "linkedin.com", "www.linkedin.com",
    "instagram.com", "www.instagram.com",
    "recaptcha.net", "www.recaptcha.net",
    "open.spotify.com",
    "calendly.com",
    "typeform.com",
})


def _is_trusted_domain(domain: str) -> bool:
    return any(domain == t or domain.endswith("." + t) for t in _TRUSTED_IFRAME_DOMAINS)


class ContentAnalysisModule(ScanModule):
    name = "content_analysis"
    depends_on = ["fingerprint"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress and not ctx.opts.force:
            return
        try:
            r = await http.get(ctx.url + "/")
        except Exception:
            return

        # PC-CNT-001: Card skimming scripts
        for m in _SCRIPT_SRC_RE.finditer(r.text):
            src = m.group(1)
            if _SKIMMER_RE.search(src):
                ctx.add_finding(Finding(
                    id="PC-CNT-001", remediation_id="REM-CNT-001",
                    title="Potential card skimming script detected",
                    severity=Severity.HIGH,
                    description=f"Suspicious external script with card skimming patterns: {src}",
                    evidence={"url": ctx.url + "/", "script_src": src},
                    remediation="Immediately investigate and remove the suspicious script. Check for site compromise.",
                    references=["https://www.imperva.com/learn/application-security/magecart/"],
                    cvss_score=9.0, module=self.name
                ))
                break

        # PC-CNT-002: Suspicious iframes (skip trusted CDNs and analytics services)
        domain = re.sub(r'^https?://', '', ctx.url).split('/')[0]
        for m in _IFRAME_RE.finditer(r.text):
            iframe_domain = m.group(1).split('/')[0]
            if iframe_domain != domain and not iframe_domain.endswith(domain) and not _is_trusted_domain(iframe_domain):
                ctx.add_finding(Finding(
                    id="PC-CNT-002", remediation_id="REM-CNT-002",
                    title="Suspicious external iframe detected",
                    severity=Severity.MEDIUM,
                    description=f"External iframe from {iframe_domain} found on homepage.",
                    evidence={"url": ctx.url + "/", "iframe_domain": iframe_domain},
                    remediation="Review all external iframes. Remove unauthorized ones.",
                    references=[], cvss_score=None, module=self.name
                ))
                break

        # PC-CNT-003: Hardcoded secrets in JS
        if secret_match := _SECRET_RE.search(r.text):
            ctx.add_finding(Finding(
                id="PC-CNT-003", remediation_id="REM-CNT-003",
                title="Potential API key or secret hardcoded in page source",
                severity=Severity.MEDIUM,
                description="An API key pattern was found in the page source code.",
                evidence={"url": ctx.url + "/", "match": secret_match.group(0)[:50] + "..."},
                remediation="Move secrets to server-side configuration. Never expose API keys in client-side code.",
                references=[], cvss_score=5.3, module=self.name
            ))
