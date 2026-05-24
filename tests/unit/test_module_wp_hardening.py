"""Unit tests for wp_hardening module (AC-10)."""
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Severity
from plecost.modules.wp_hardening import WPHardeningModule, KNOWN_LATEST_VERSION


def _make_ctx(version: str | None = None, module_options: dict | None = None) -> ScanContext:
    opts = ScanOptions(
        url="https://example.com",
        module_options=module_options or {}
    )
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    ctx.wordpress_version = version
    return ctx


async def test_pc_wph_001_outdated_version():
    """AC-10: version < KNOWN_LATEST_VERSION → PC-WPH-001 MEDIUM."""
    ctx = _make_ctx("6.5.0")
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPHardeningModule().run(ctx, http)
    assert len(ctx.findings) == 1
    f = ctx.findings[0]
    assert f.id == "PC-WPH-001"
    assert f.severity == Severity.MEDIUM


async def test_no_finding_for_latest_version():
    """AC-10: version == KNOWN_LATEST_VERSION → no finding."""
    ctx = _make_ctx(KNOWN_LATEST_VERSION)
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPHardeningModule().run(ctx, http)
    assert ctx.findings == []


async def test_no_finding_for_newer_version():
    """AC-10: version > KNOWN_LATEST_VERSION → no finding."""
    ctx = _make_ctx("7.0.0")
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPHardeningModule().run(ctx, http)
    assert ctx.findings == []


async def test_no_finding_when_no_version():
    """AC-10: no version detected → no finding."""
    ctx = _make_ctx(None)
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPHardeningModule().run(ctx, http)
    assert ctx.findings == []


async def test_overridable_latest_version_via_module_options():
    """AC-10: latest_version overridable via module_options.hardening.latest_version."""
    # Set latest_version to 6.0.0 via module_options, detected version is 5.9.0
    ctx = _make_ctx("5.9.0", module_options={"hardening": {"latest_version": "6.0.0"}})
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPHardeningModule().run(ctx, http)
    assert len(ctx.findings) == 1
    assert ctx.findings[0].id == "PC-WPH-001"
    assert ctx.findings[0].evidence["latest_known_version"] == "6.0.0"


async def test_skips_when_not_wordpress():
    """AC-10: not WordPress → skip."""
    ctx = _make_ctx("5.0.0")
    ctx.is_wordpress = False
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPHardeningModule().run(ctx, http)
    assert ctx.findings == []


async def test_evidence_contains_versions():
    """AC-10: evidence contains detected_version and latest_known_version."""
    ctx = _make_ctx("6.0.0")
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPHardeningModule().run(ctx, http)
    assert len(ctx.findings) == 1
    f = ctx.findings[0]
    assert f.evidence["detected_version"] == "6.0.0"
    assert f.evidence["latest_known_version"] == KNOWN_LATEST_VERSION


# -----------------------------------------------------------------------
# AC-10c: explicit mandatory test name from PASO 4
# -----------------------------------------------------------------------

async def test_wp_hardening_respects_module_options_override():
    """AC-10c: module_options override takes effect; no finding when version equals override."""
    # Override latest_version to the currently detected version → no finding expected
    ctx = _make_ctx("5.9.0", module_options={"hardening": {"latest_version": "5.9.0"}})
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPHardeningModule().run(ctx, http)
    # 5.9.0 is NOT < 5.9.0 → no finding
    assert ctx.findings == [], (
        "When module_options override makes detected == latest, no finding should be emitted"
    )


async def test_wp_hardening_override_triggers_finding_for_older_version():
    """AC-10c: module_options override is used as reference; older version triggers finding."""
    # Override latest_version to 5.9.0; detected is 5.8.0 → finding expected
    ctx = _make_ctx("5.8.0", module_options={"hardening": {"latest_version": "5.9.0"}})
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await WPHardeningModule().run(ctx, http)
    assert len(ctx.findings) == 1
    f = ctx.findings[0]
    assert f.id == "PC-WPH-001"
    assert f.evidence["latest_known_version"] == "5.9.0"
