from __future__ import annotations
import asyncio
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.webshells.base import BaseDetector
from plecost.modules.webshells.wordlists import UPLOADS_PROBE_PATHS, UPLOADS_PROBE_PATHS_FAST

_BASELINE_PATH = "/wp-content/uploads/__plecost_probe_xyz__.php"


class UploadsPhpDetector(BaseDetector):
    """
    Detects PHP files in wp-content/uploads/ returning HTTP 200.
    WordPress must never execute PHP from uploads — any 200 here is CRITICAL.
    """

    name = "uploads_php"
    requires_auth = False

    async def detect(
        self, ctx: ScanContext, http: PlecostHTTPClient
    ) -> list[Finding]:
        paths = UPLOADS_PROBE_PATHS if ctx.opts.deep else UPLOADS_PROBE_PATHS_FAST
        findings: list[Finding] = []
        sem = asyncio.Semaphore(ctx.opts.concurrency)
        total = len(paths)
        checked = [0]

        # Baseline probe: detect soft-200 environments where the server returns
        # HTTP 200 for any path (including non-existent files).
        baseline_body: str | None = None
        try:
            probe = await http.get(ctx.url + _BASELINE_PATH)
            if probe.status_code == 200:
                baseline_body = probe.text
        except Exception:
            pass

        async def _probe(path: str) -> None:
            async with sem:
                try:
                    url = ctx.url + path
                    r = await http.get(url)
                    if r.status_code != 200:
                        return
                    # In a soft-200 environment, skip if the response body is
                    # identical to the baseline (false positive).
                    if baseline_body is not None and r.text == baseline_body:
                        return
                    findings.append(Finding(
                        id="PC-WSH-100",
                        remediation_id="REM-WSH-100",
                        title="PHP file executable in wp-content/uploads",
                        severity=Severity.CRITICAL,
                        description=(
                            f"A PHP file was found accessible at `{url}`. "
                            "WordPress should never execute PHP files from the uploads directory. "
                            "This indicates a webshell or a critically misconfigured server."
                        ),
                        evidence={"url": url, "status_code": "200"},
                        remediation=(
                            "Remove the PHP file immediately. Add or restore the .htaccess file "
                            "in wp-content/uploads/ to deny PHP execution:\n\n"
                            "<Files *.php>\n  deny from all\n</Files>"
                        ),
                        references=[
                            "https://blog.sucuri.net/2021/04/wordpress-file-upload-vulnerability.html",
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
