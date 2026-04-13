import respx
import httpx
from plecost import Scanner, ScanOptions
from plecost.models import Finding

WP_HOMEPAGE = '''
<html>
<head>
<meta name="generator" content="WordPress 6.4.2"/>
</head>
<body></body>
</html>
'''

NOT_WP_HOMEPAGE = '''
<html>
<head><title>Some website</title></head>
<body>Hello world</body>
</html>
'''


async def test_scanner_fires_on_module_start_callback():
    called_with: list[str] = []

    def on_start(name: str) -> None:
        called_with.append(name)

    opts = ScanOptions(url="https://example.com", modules=["fingerprint"])
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=WP_HOMEPAGE))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404, text="Not Found"))
        scanner = Scanner(opts, on_module_start=on_start)
        await scanner.run()

    assert len(called_with) >= 1
    assert all(isinstance(name, str) for name in called_with)


async def test_scanner_fires_on_finding_callback():
    findings_received: list[Finding] = []

    def on_finding(f: Finding) -> None:
        findings_received.append(f)

    opts = ScanOptions(url="https://example.com", modules=["fingerprint"])
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=WP_HOMEPAGE))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404, text="Not Found"))
        scanner = Scanner(opts, on_finding=on_finding)
        result = await scanner.run()

    # PC-FP-001 is the fingerprint finding — at least one finding should have been forwarded
    assert len(findings_received) >= 1
    assert all(isinstance(f, Finding) for f in findings_received)
    # Findings delivered via callback must match those in the result
    result_ids = {f.id for f in result.findings}
    callback_ids = {f.id for f in findings_received}
    assert callback_ids.issubset(result_ids)


async def test_scanner_run_many_scans_all_urls():
    opts = ScanOptions(
        url="https://example.com",  # template URL, overridden per target
        modules=["fingerprint"],
    )
    async with respx.mock:
        respx.get("https://site1.com/").mock(return_value=httpx.Response(200, text=WP_HOMEPAGE))
        respx.get("https://site2.com/").mock(return_value=httpx.Response(200, text=WP_HOMEPAGE))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404, text="Not Found"))
        scanner = Scanner(opts)
        results = await scanner.run_many(["https://site1.com", "https://site2.com"])

    assert len(results) == 2
    assert results[0].url == "https://site1.com"
    assert results[1].url == "https://site2.com"


async def test_scanner_force_flag_runs_modules_without_wordpress():
    opts = ScanOptions(url="https://example.com", modules=["fingerprint", "misconfigs"], force=True)
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=NOT_WP_HOMEPAGE))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404, text="Not Found"))
        scanner = Scanner(opts)
        result = await scanner.run()

    assert result.blocked is False
    assert result.is_wordpress is False


async def test_scanner_blocked_skips_modules():
    opts = ScanOptions(url="https://example.com", modules=["fingerprint", "misconfigs"])
    async with respx.mock:
        respx.get("https://example.com/").mock(return_value=httpx.Response(403, text="Forbidden"))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404, text="Not Found"))
        scanner = Scanner(opts)
        result = await scanner.run()

    assert result.blocked is True
    assert any(f.id == "PC-PRE-001" for f in result.findings)
    # Only the pre-flight finding should be present
    assert all(f.id == "PC-PRE-001" for f in result.findings)
