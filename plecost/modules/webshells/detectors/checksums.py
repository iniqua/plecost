from __future__ import annotations
import asyncio
import hashlib
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.webshells.base import BaseDetector
from plecost.modules.webshells.wordlists import WP_CORE_FILES_TO_CHECK

_CHECKSUMS_API = "https://api.wordpress.org/core/checksums/1.0/?version={version}&locale={locale}"


class ChecksumsDetector(BaseDetector):
    """
    Verifies WordPress core file integrity using the official WordPress checksums API.
    Requires WordPress admin credentials and a detected WP version.
    """

    name = "checksums"
    requires_auth = True

    async def detect(
        self, ctx: ScanContext, http: PlecostHTTPClient
    ) -> list[Finding]:
        if not ctx.opts.credentials:
            return []
        if not ctx.wordpress_version:
            return []

        locale = getattr(ctx, "wordpress_locale", "en_US") or "en_US"
        api_url = _CHECKSUMS_API.format(version=ctx.wordpress_version, locale=locale)

        try:
            r = await http.get(api_url)
            if r.status_code != 200:
                return []
            data = r.json()
            checksums: dict[str, str] = data.get("checksums", {})
            if not checksums:
                return []
        except Exception:
            return []

        findings: list[Finding] = []
        sem = asyncio.Semaphore(ctx.opts.concurrency)

        async def _check(file_path: str) -> None:
            expected_md5 = checksums.get(file_path)
            if not expected_md5:
                return
            async with sem:
                try:
                    url = ctx.url + "/" + file_path
                    r = await http.get(url)
                    if r.status_code != 200:
                        return
                    actual_md5 = hashlib.md5(r.content).hexdigest()
                    if actual_md5 == expected_md5:
                        return
                    findings.append(Finding(
                        id="PC-WSH-250",
                        remediation_id="REM-WSH-250",
                        title=f"WordPress core file modified: {file_path}",
                        severity=Severity.HIGH,
                        description=(
                            f"The core file `{file_path}` has been modified. "
                            f"Expected MD5: `{expected_md5}`, actual: `{actual_md5}`. "
                            "Modified core files can indicate a backdoor or unauthorized customization."
                        ),
                        evidence={
                            "file": file_path,
                            "expected_md5": expected_md5,
                            "actual_md5": actual_md5,
                            "url": url,
                        },
                        remediation=(
                            "Verify whether this modification is authorized. "
                            "If not, restore the original file from a clean WordPress installation "
                            f"(version {ctx.wordpress_version})."
                        ),
                        references=[
                            "https://developer.wordpress.org/reference/functions/get_core_checksums/",
                        ],
                        cvss_score=7.5,
                        module="webshells",
                    ))
                except Exception:
                    pass

        await asyncio.gather(*[_check(f) for f in WP_CORE_FILES_TO_CHECK])
        return findings
