from __future__ import annotations
import asyncio
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.webshells.base import BaseDetector
from plecost.modules.webshells.wordlists import WEBSHELL_PATHS_FAST, WEBSHELL_PATHS_CORE, WEBSHELL_PATHS_EXTENDED

_ALLOWED_CONTENT_TYPES = {"text/html", "text/plain", "application/x-httpd-php"}
_PREFLIGHT_PATH = "/plecost-probe-nonexistent.php"


class KnownPathsDetector(BaseDetector):
    """
    Probes known webshell filenames in common WordPress directories.
    Uses --module-option webshells:wordlist=extended for the larger wordlist.
    """

    name = "known_paths"
    requires_auth = False

    async def detect(
        self, ctx: ScanContext, http: PlecostHTTPClient
    ) -> list[Finding]:
        # Preflight: detect catch-all sites (return 200 for everything)
        try:
            r = await http.get(ctx.url + _PREFLIGHT_PATH)
            if r.status_code == 200:
                return []  # catch-all — skip to avoid mass false positives
        except Exception:
            pass

        wordlist_tier = ctx.opts.module_options.get("webshells", {}).get("wordlist", "")
        if wordlist_tier == "extended":
            paths = WEBSHELL_PATHS_EXTENDED
        elif wordlist_tier == "core" or ctx.opts.deep:
            paths = WEBSHELL_PATHS_CORE
        else:
            paths = WEBSHELL_PATHS_FAST

        findings: list[Finding] = []
        sem = asyncio.Semaphore(ctx.opts.concurrency)
        total = len(paths)
        checked = [0]

        async def _probe(path: str) -> None:
            async with sem:
                try:
                    url = ctx.url + path
                    r = await http.get(url)
                    if r.status_code != 200:
                        return
                    ct = r.headers.get("content-type", "").split(";")[0].strip().lower()
                    if ct not in _ALLOWED_CONTENT_TYPES:
                        return
                    findings.append(Finding(
                        id="PC-WSH-001",
                        remediation_id="REM-WSH-001",
                        title="Known webshell path is accessible",
                        severity=Severity.CRITICAL,
                        description=(
                            f"A file matching a known webshell filename was found at `{url}`. "
                            "This strongly indicates the site has been compromised."
                        ),
                        evidence={"url": url, "status_code": str(r.status_code), "content_type": ct},
                        remediation=(
                            "Immediately remove the suspicious file. Audit all files in "
                            "wp-content/uploads, mu-plugins, and plugin directories. "
                            "Change all WordPress and database credentials."
                        ),
                        references=[
                            "https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF",
                            "https://github.com/nsacyber/Mitigating-Web-Shells",
                        ],
                        cvss_score=9.8,
                        module="webshells",
                    ))
                except Exception:
                    pass
                finally:
                    checked[0] += 1
                    ctx.report_progress("webshells", checked[0], total)

        await asyncio.gather(*[_probe(p) for p in paths])
        return findings
