import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Severity
from plecost.modules.webshells.detectors.mu_plugins import MuPluginsDetector


async def test_reports_php_in_mu_plugins():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            return_value=httpx.Response(200, text="<?php eval($_POST['x']); ?>")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    assert any(f.id == "PC-WSH-150" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


async def test_no_finding_when_all_mu_plugins_404():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    assert findings == []


async def test_no_finding_on_403():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.route(url__regex=r".*/mu-plugins/.*").mock(return_value=httpx.Response(403))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    assert findings == []


async def test_no_finding_cloudflare_catch_all():
    """Catch-all dinámico: probe_a y probe_b devuelven 200 con tamaños similares."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_a__.php"
        ).mock(return_value=httpx.Response(200, content=b"x" * 18125))
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_b__.php"
        ).mock(return_value=httpx.Response(200, content=b"x" * 18131))
        respx.route(url__regex=r".*").mock(
            return_value=httpx.Response(200, content=b"x" * 18128)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    assert findings == []


async def test_reports_php_despite_catch_all_when_size_differs():
    """Catch-all activo pero un path devuelve respuesta de tamaño muy distinto."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    webshell_body = b"<?php eval($_POST['x']); ?>"  # ~26 bytes, muy distinto de 18125
    async with respx.mock:
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_a__.php"
        ).mock(return_value=httpx.Response(200, content=b"x" * 18125))
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_b__.php"
        ).mock(return_value=httpx.Response(200, content=b"x" * 18131))
        respx.get("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            return_value=httpx.Response(200, content=webshell_body)
        )
        respx.route(url__regex=r".*").mock(
            return_value=httpx.Response(200, content=b"x" * 18128)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    assert any(f.id == "PC-WSH-150" for f in findings)
    hit_urls = [f.evidence["url"] for f in findings if f.id == "PC-WSH-150"]
    assert any("redirect.php" in u for u in hit_urls)


# -----------------------------------------------------------------------
# SPEC LOCK tests — AC-1
# These tests would FAIL if the implementation had the bugs they guard against.
# -----------------------------------------------------------------------

# AC-1: body=0 bytes, catch_all_size=None (no catch-all) → CRITICAL, description has
#        "empty response" and "China Chopper"
async def test_ac1_empty_body_no_catch_all_emits_critical_with_china_chopper():
    """AC-1: body=0 bytes, no catch-all → PC-WSH-150 CRITICAL with China Chopper in description."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        # Probe requests return 404 → catch_all_size = None
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_a__.php"
        ).mock(return_value=httpx.Response(404))
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_b__.php"
        ).mock(return_value=httpx.Response(404))
        # redirect.php returns 200 with empty body
        respx.get("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            return_value=httpx.Response(200, content=b"")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    wsh150 = [f for f in findings if f.id == "PC-WSH-150"]
    assert wsh150, "AC-1: expected PC-WSH-150 when body=0 and catch_all_size=None"
    f = wsh150[0]
    assert f.severity == Severity.CRITICAL, "AC-1: severity must be CRITICAL"
    assert "empty response" in f.description.lower() or "empty" in f.description.lower(), (
        "AC-1: description must mention empty response"
    )
    assert "china chopper" in f.description.lower(), (
        "AC-1: description must mention China Chopper for empty-body case"
    )


# AC-1: body>0 bytes, catch_all_size=None → CRITICAL, description does NOT mention
#        "empty response" or "China Chopper"
async def test_ac1_nonempty_body_no_catch_all_emits_critical_without_china_chopper():
    """AC-1: body>0 bytes, no catch-all → PC-WSH-150 CRITICAL without China Chopper mention."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_a__.php"
        ).mock(return_value=httpx.Response(404))
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_b__.php"
        ).mock(return_value=httpx.Response(404))
        respx.get("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            return_value=httpx.Response(200, content=b"<?php echo 'hello'; ?>")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    wsh150 = [f for f in findings if f.id == "PC-WSH-150"]
    assert wsh150, "AC-1: expected PC-WSH-150 when body>0 and catch_all_size=None"
    f = wsh150[0]
    assert f.severity == Severity.CRITICAL, "AC-1: severity must be CRITICAL"
    assert "china chopper" not in f.description.lower(), (
        "AC-1: non-empty body must NOT mention China Chopper in description"
    )
    assert "empty response" not in f.description.lower(), (
        "AC-1: non-empty body description must NOT mention empty response"
    )


# AC-1: catch_all_size=0 (catch-all returns empty body too) + real file also returns 200
#        with 0 bytes → ambiguous → NO finding
async def test_ac1_catch_all_size_zero_suppresses_finding():
    """AC-1: catch_all_size=0 means server returns empty body for any path → ambiguous → NO finding."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    async with respx.mock:
        # Both probes return 200 + empty body → catch_all_size = 0
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_a__.php"
        ).mock(return_value=httpx.Response(200, content=b""))
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_b__.php"
        ).mock(return_value=httpx.Response(200, content=b""))
        # All mu-plugin files also return 200 + empty body
        respx.route(url__regex=r".*/mu-plugins/.*").mock(
            return_value=httpx.Response(200, content=b"")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    wsh150 = [f for f in findings if f.id == "PC-WSH-150"]
    assert wsh150 == [], (
        "AC-1: when catch_all_size=0 and file body=0, result is ambiguous → must NOT emit finding"
    )
