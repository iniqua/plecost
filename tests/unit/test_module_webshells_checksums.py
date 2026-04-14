import hashlib
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Severity
from plecost.modules.webshells.detectors.checksums import ChecksumsDetector


def _make_ctx_with_creds(version: str = "6.4.2") -> ScanContext:
    opts = ScanOptions(url="https://example.com", credentials=("admin", "secret"))
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    ctx.wordpress_version = version
    return ctx


async def test_reports_modified_core_file():
    """A core file with a different MD5 hash must emit PC-WSH-250."""
    ctx = _make_ctx_with_creds()
    original_content = b"<?php // original wp-login.php content"
    modified_content = b"<?php @eval($_POST['x']); // original wp-login.php content"
    expected_md5 = hashlib.md5(original_content).hexdigest()
    checksums_json = {"checksums": {"wp-login.php": expected_md5}}

    async with respx.mock:
        respx.get(
            "https://api.wordpress.org/core/checksums/1.0/?version=6.4.2&locale=en_US"
        ).mock(return_value=httpx.Response(200, json=checksums_json))
        respx.get("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(200, content=modified_content)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await ChecksumsDetector().detect(ctx, http)
    assert any(f.id == "PC-WSH-250" for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


async def test_no_finding_when_hash_matches():
    """No finding if the downloaded file matches the official MD5."""
    ctx = _make_ctx_with_creds()
    content = b"<?php // official wp-login.php"
    expected_md5 = hashlib.md5(content).hexdigest()
    checksums_json = {"checksums": {"wp-login.php": expected_md5}}

    async with respx.mock:
        respx.get(
            "https://api.wordpress.org/core/checksums/1.0/?version=6.4.2&locale=en_US"
        ).mock(return_value=httpx.Response(200, json=checksums_json))
        respx.get("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(200, content=content)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await ChecksumsDetector().detect(ctx, http)
    assert findings == []


async def test_skips_when_version_unknown():
    """If wordpress_version is None, detector must skip gracefully."""
    opts = ScanOptions(url="https://example.com", credentials=("admin", "secret"))
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    ctx.wordpress_version = None  # version not detected

    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await ChecksumsDetector().detect(ctx, http)
    assert findings == []


async def test_skips_when_no_credentials():
    """Without credentials, the detector must not run."""
    opts = ScanOptions(url="https://example.com")  # no credentials
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    ctx.wordpress_version = "6.4.2"

    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await ChecksumsDetector().detect(ctx, http)
    assert findings == []
