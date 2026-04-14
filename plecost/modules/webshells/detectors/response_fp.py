from __future__ import annotations
import asyncio
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.webshells.base import BaseDetector
from plecost.modules.webshells.wordlists import WEBSHELL_PATHS_FAST, WEBSHELL_PATHS_CORE, WEBSHELL_PATHS_EXTENDED

_PREFLIGHT_PATH = "/plecost-probe-nonexistent.php"
_ALLOWED_CONTENT_TYPES = {"text/html", "text/plain", "application/x-httpd-php"}

# Image magic bytes (polyglot detection)
_MAGIC_GIF = b"GIF89a"
_MAGIC_JPEG = b"\xff\xd8\xff"
_MAGIC_PNG = b"\x89PNG"
_PHP_OPEN_TAG = b"<?php"

# WSO parameter fingerprint — all 3 must be present
_WSO_PARAMS = [b'name="a"', b'name="c"', b'name="charset"']


def _fingerprint(body: bytes) -> str | None:
    """Return family name if body matches a known webshell fingerprint, else None."""
    # China Chopper: empty body (0 bytes)
    if len(body) == 0:
        return "china_chopper"

    # Godzilla/Behinder response markers
    if b"->|" in body or b"|<-" in body:
        return "godzilla_behinder"

    # WSO/FilesMan: form with a, c, charset parameters
    if all(p in body for p in _WSO_PARAMS):
        return "wso_filesman"

    # b374k: contains 'b374k' string
    if b"b374k" in body.lower():
        return "b374k"

    # c99shell: contains 'c99shell'
    if b"c99shell" in body.lower():
        return "c99shell"

    # Polyglot image/PHP: starts with image magic bytes but contains PHP
    for magic in (_MAGIC_GIF, _MAGIC_JPEG, _MAGIC_PNG):
        if body.startswith(magic) and _PHP_OPEN_TAG in body:
            return "polyglot_image_php"

    return None


class ResponseFingerprintDetector(BaseDetector):
    """
    Probes known webshell paths and fingerprints the response body
    against known webshell family signatures.
    Only reports when a fingerprint matches — higher confidence than path-only.
    """

    name = "response_fp"
    requires_auth = False

    async def detect(
        self, ctx: ScanContext, http: PlecostHTTPClient
    ) -> list[Finding]:
        # Preflight: detect catch-all sites
        try:
            r = await http.get(ctx.url + _PREFLIGHT_PATH)
            if r.status_code == 200:
                return []
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
                    family = _fingerprint(r.content)
                    if family is None:
                        return
                    findings.append(Finding(
                        id="PC-WSH-200",
                        remediation_id="REM-WSH-200",
                        title=f"Webshell fingerprint matched: {family}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"A response from `{url}` matches the fingerprint of the "
                            f"'{family}' webshell family. The server is almost certainly compromised."
                        ),
                        evidence={"url": url, "family": family, "status_code": "200"},
                        remediation=(
                            "The site is compromised. Immediately take the site offline, "
                            "remove the webshell, audit all files for additional backdoors, "
                            "and rotate all credentials (WordPress, database, FTP, hosting)."
                        ),
                        references=[
                            "https://www.recordedfuture.com/blog/web-shell-analysis-part-1",
                            "https://github.com/nsacyber/Mitigating-Web-Shells",
                        ],
                        cvss_score=10.0,
                        module="webshells",
                    ))
                except Exception:
                    pass
                finally:
                    checked[0] += 1
                    ctx.report_progress("webshells", checked[0], total)

        await asyncio.gather(*[_probe(p) for p in paths])
        return findings
