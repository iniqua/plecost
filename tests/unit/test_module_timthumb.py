"""Unit tests for timthumb module (AC-7)."""
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Plugin, Severity
from plecost.modules.timthumb import TimThumbModule


def _make_ctx() -> ScanContext:
    opts = ScanOptions(url="https://example.com")
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    return ctx


async def test_pc_tth_001_detected_at_root():
    """AC-7: timthumb.php at /timthumb.php with signature → PC-TTH-001."""
    ctx = _make_ctx()
    async with respx.mock:
        respx.get("https://example.com/timthumb.php").mock(
            return_value=httpx.Response(200, text="TimThumb v2.8.14 image resizer")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await TimThumbModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-TTH-001" in ids


async def test_pc_tth_001_detected_in_wp_content():
    """AC-7: timthumb.php at /wp-content/timthumb.php → PC-TTH-001."""
    ctx = _make_ctx()
    async with respx.mock:
        respx.get("https://example.com/wp-content/timthumb.php").mock(
            return_value=httpx.Response(200, text="Not a valid src — TimThumb")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await TimThumbModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-TTH-001" in ids


async def test_pc_tth_002_vulnerable_version():
    """AC-7: version < 2.8.14 → PC-TTH-002 CRITICAL."""
    ctx = _make_ctx()
    async with respx.mock:
        respx.get("https://example.com/timthumb.php").mock(
            return_value=httpx.Response(200, text="TimThumb v2.8.0 image resizer")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await TimThumbModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-TTH-001" in ids
    assert "PC-TTH-002" in ids
    tth2 = next(f for f in ctx.findings if f.id == "PC-TTH-002")
    assert tth2.severity == Severity.CRITICAL


async def test_pc_tth_002_not_emitted_for_patched_version():
    """AC-7: version >= 2.8.14 → no PC-TTH-002."""
    ctx = _make_ctx()
    async with respx.mock:
        respx.get("https://example.com/timthumb.php").mock(
            return_value=httpx.Response(200, text="TimThumb v2.8.14 stable")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await TimThumbModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-TTH-001" in ids
    assert "PC-TTH-002" not in ids


async def test_pc_tth_003_in_plugin_directory():
    """AC-7: timthumb.php inside plugin directory → PC-TTH-003 HIGH."""
    ctx = _make_ctx()
    ctx.add_plugin(Plugin(
        slug="my-gallery",
        version="1.0",
        latest_version="1.0",
        url="https://example.com/wp-content/plugins/my-gallery/"
    ))
    async with respx.mock:
        respx.get("https://example.com/wp-content/plugins/my-gallery/timthumb.php").mock(
            return_value=httpx.Response(200, text="TimThumb image resizer library")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await TimThumbModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-TTH-001" in ids
    assert "PC-TTH-003" in ids
    tth3 = next(f for f in ctx.findings if f.id == "PC-TTH-003")
    assert tth3.severity == Severity.HIGH


async def test_no_finding_without_signature():
    """AC-7: 200 response without TimThumb signature → no findings."""
    ctx = _make_ctx()
    async with respx.mock:
        respx.get("https://example.com/timthumb.php").mock(
            return_value=httpx.Response(200, text="<html>404 Not Found</html>")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await TimThumbModule().run(ctx, http)
    assert ctx.findings == []


async def test_skips_when_not_wordpress():
    """AC-7: not WordPress + not force → skip."""
    ctx = _make_ctx()
    ctx.is_wordpress = False
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(200, text="TimThumb"))
        async with PlecostHTTPClient(ctx.opts) as http:
            await TimThumbModule().run(ctx, http)
    assert ctx.findings == []


# -----------------------------------------------------------------------
# AC-7b: explicit name for PASO 4 mandatory test
# -----------------------------------------------------------------------

async def test_timthumb_no_crit_when_version_current():
    """AC-7b: timthumb >= 2.8.14 → PC-TTH-001 emitted but PC-TTH-002 NOT emitted."""
    ctx = _make_ctx()
    async with respx.mock:
        respx.get("https://example.com/timthumb.php").mock(
            return_value=httpx.Response(200, text="TimThumb v2.8.14 — the last patched release")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await TimThumbModule().run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-TTH-001" in ids, "PC-TTH-001 must be emitted when timthumb signature is present"
    assert "PC-TTH-002" not in ids, "PC-TTH-002 must NOT be emitted when version >= 2.8.14"


# -----------------------------------------------------------------------
# AC-7c negative: timthumb at root/wp-content does NOT emit PC-TTH-003
# -----------------------------------------------------------------------

async def test_pc_tth_003_not_emitted_for_non_plugin_location():
    """AC-7c: timthumb.php found at /timthumb.php (not plugin dir) → no PC-TTH-003."""
    ctx = _make_ctx()
    async with respx.mock:
        respx.get("https://example.com/timthumb.php").mock(
            return_value=httpx.Response(200, text="TimThumb v2.8.0 image resizer")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await TimThumbModule().run(ctx, http)
    # PC-TTH-001 and PC-TTH-002 are expected, but NOT PC-TTH-003
    ids = [f.id for f in ctx.findings]
    assert "PC-TTH-001" in ids
    assert "PC-TTH-003" not in ids, "PC-TTH-003 must only emit when timthumb is inside a plugin directory"
