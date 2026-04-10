import pytest
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Severity
from plecost.modules.misconfigs import MisconfigsModule


@pytest.fixture
def ctx():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    return ctx


@pytest.mark.asyncio
async def test_detects_wp_config_exposed(ctx):
    async with respx.mock:
        respx.get("https://example.com/wp-config.php").mock(
            return_value=httpx.Response(200, text="<?php define('DB_PASSWORD', 'secret');")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await MisconfigsModule().run(ctx, http)
    assert any(f.id == "PC-MCFG-001" for f in ctx.findings)
    assert any(f.severity == Severity.CRITICAL for f in ctx.findings)


@pytest.mark.asyncio
async def test_detects_env_file(ctx):
    async with respx.mock:
        respx.get("https://example.com/.env").mock(
            return_value=httpx.Response(200, text="DB_PASSWORD=secret")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await MisconfigsModule().run(ctx, http)
    assert any(f.id == "PC-MCFG-003" for f in ctx.findings)


@pytest.mark.asyncio
async def test_no_findings_if_all_404(ctx):
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await MisconfigsModule().run(ctx, http)
    misconfig_findings = [f for f in ctx.findings if f.id.startswith("PC-MCFG")]
    assert len(misconfig_findings) == 0
