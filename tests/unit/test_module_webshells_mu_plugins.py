import base64 as _base64
import re as _re
import urllib.parse as _urlparse
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, Severity
from plecost.modules.webshells.detectors.mu_plugins import MuPluginsDetector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _echo_nonce(request: httpx.Request) -> httpx.Response:
    """respx side_effect: simulate a PHP webshell executing strrev() and returning the forward nonce.

    httpx sends form data as URL-encoded bytes, so we decode first, then search
    for the nonce pattern inside any parameter value.

    Handles two payload forms:
      Payload 1 (direct): param=printf(strrev("REVERSED_NONCE"));
                          → PHP executes strrev → returns forward nonce
      Payload 2 (b64):    param=eval(base64_decode("BASE64..."));
                          → decode the base64 content, find the inner strrev payload, return forward nonce.
    """
    try:
        body = request.content.decode()
        # URL-decode the body to get readable values
        decoded_body = _urlparse.unquote_plus(body)
        # Payload 1: param=printf(strrev("REVERSED_NONCE"));
        m = _re.search(r'printf\(strrev\("([0-9a-f]{16})"\)\)', decoded_body)
        if m:
            reversed_nonce = m.group(1)
            forward_nonce = reversed_nonce[::-1]
            return httpx.Response(200, text=forward_nonce)
        # Payload 2: eval(base64_decode("BASE64...")) — decode and extract reversed_nonce from inner strrev call
        m2 = _re.search(r'base64_decode\("([A-Za-z0-9+/=]+)"\)', decoded_body)
        if m2:
            inner = _base64.b64decode(m2.group(1)).decode()
            m3 = _re.search(r'printf\(strrev\("([0-9a-f]{16})"\)\)', inner)
            if m3:
                reversed_nonce = m3.group(1)
                forward_nonce = reversed_nonce[::-1]
                return httpx.Response(200, text=forward_nonce)
    except Exception:
        pass
    return httpx.Response(200, text="")


def _echo_nonce_only_b64(request: httpx.Request) -> httpx.Response:
    """respx side_effect: only responds to Payload 2 (eval/base64_decode), ignores Payload 1.

    Used to test that b64 confirmation works when direct printf(strrev(...)) probe returns empty.
    """
    try:
        body = request.content.decode()
        decoded_body = _urlparse.unquote_plus(body)
        # Ignore Payload 1 (direct printf(strrev(...)))
        if _re.search(r'printf\(strrev\("([0-9a-f]{16})"\)\)', decoded_body):
            return httpx.Response(200, text="")
        # Payload 2: eval(base64_decode(...)) — decode and extract reversed_nonce from inner strrev call
        m2 = _re.search(r'base64_decode\("([A-Za-z0-9+/=]+)"\)', decoded_body)
        if m2:
            inner = _base64.b64decode(m2.group(1)).decode()
            m3 = _re.search(r'printf\(strrev\("([0-9a-f]{16})"\)\)', inner)
            if m3:
                reversed_nonce = m3.group(1)
                forward_nonce = reversed_nonce[::-1]
                return httpx.Response(200, text=forward_nonce)
    except Exception:
        pass
    return httpx.Response(200, text="")


# ---------------------------------------------------------------------------
# Core detection tests
# ---------------------------------------------------------------------------

async def test_reports_php_in_mu_plugins():
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            return_value=httpx.Response(200, text="<?php eval($_POST['x']); ?>")
        )
        respx.post("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            side_effect=_echo_nonce
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    assert any(f.id == "PC-WSH-150" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


async def test_no_finding_when_all_mu_plugins_404():
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    assert findings == []


async def test_no_finding_on_403():
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.route(url__regex=r".*/mu-plugins/.*").mock(return_value=httpx.Response(403))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    assert findings == []


async def test_no_finding_cloudflare_catch_all():
    """Catch-all dinámico: probe_a y probe_b devuelven 200 con tamaños similares."""
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
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
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
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
        respx.post("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            side_effect=_echo_nonce
        )
        respx.route(url__regex=r".*").mock(
            return_value=httpx.Response(200, content=b"x" * 18128)
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    assert any(f.id == "PC-WSH-150" for f in findings)
    hit_urls = [f.evidence["url"] for f in findings if f.id == "PC-WSH-150"]
    assert any("redirect.php" in u for u in hit_urls)


# ---------------------------------------------------------------------------
# AC-1 fast mode guard
# ---------------------------------------------------------------------------

async def test_fast_mode_returns_empty_immediately():
    """AC-1: deep=False → detect() returns [] without any HTTP requests."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))  # deep=False by default
    ctx.is_wordpress = True
    async with respx.mock:
        # No routes registered — any HTTP request would raise respx.NetworkError
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    assert findings == [], "AC-1: fast mode must return [] without HTTP requests"


# ---------------------------------------------------------------------------
# AC-1 legacy tests — updated to deep=True with POST probe mocks
# ---------------------------------------------------------------------------

async def test_ac1_empty_body_confirmed_emits_critical_with_china_chopper():
    """AC-1/AC-4: body=0 bytes, POST probe confirms → PC-WSH-150 CRITICAL with China Chopper in title."""
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
    ctx.is_wordpress = True
    async with respx.mock:
        # Probe requests return 404 → catch_all_size = None
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_a__.php"
        ).mock(return_value=httpx.Response(404))
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_b__.php"
        ).mock(return_value=httpx.Response(404))
        # redirect.php returns 200 with empty body (China Chopper characteristic)
        respx.get("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            return_value=httpx.Response(200, content=b"")
        )
        # POST probe echoes the nonce → confirmed
        respx.post("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            side_effect=_echo_nonce
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    wsh150 = [f for f in findings if f.id == "PC-WSH-150"]
    assert wsh150, "AC-1/AC-4: expected PC-WSH-150 when POST probe confirms"
    f = wsh150[0]
    assert f.severity == Severity.CRITICAL, "AC-1: severity must be CRITICAL"
    assert "china chopper" in f.title.lower(), (
        "AC-8: title must contain 'China Chopper' for confirmed finding"
    )
    assert "confirmed" in f.title.lower(), (
        "AC-8: title must contain 'confirmed' for confirmed finding"
    )
    assert f.evidence.get("confirmed") is True, "AC-7: evidence must have confirmed=True (bool)"
    assert "probe_param" in f.evidence, "AC-7: evidence must include probe_param"


async def test_ac1_nonempty_body_confirmed_emits_china_chopper():
    """AC-1/AC-4: body>0 bytes, POST probe confirms → PC-WSH-150 CRITICAL with China Chopper in title."""
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
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
        # POST probe confirms — non-empty body files are still checked
        respx.post("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            side_effect=_echo_nonce
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    wsh150 = [f for f in findings if f.id == "PC-WSH-150"]
    assert wsh150, "AC-4: expected PC-WSH-150 when POST probe confirms non-empty body"
    f = wsh150[0]
    assert f.severity == Severity.CRITICAL
    assert "china chopper" in f.title.lower(), "AC-8: title must contain 'China Chopper'"


async def test_ac1_no_finding_when_post_probe_does_not_confirm():
    """AC-5: GET 200 hit but POST probe returns no nonce → no finding emitted."""
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
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
        # POST probe returns empty body — does NOT confirm
        respx.post("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            return_value=httpx.Response(200, text="")
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    wsh150 = [f for f in findings if f.id == "PC-WSH-150"]
    assert wsh150 == [], "AC-5: no finding when POST probe does not confirm RCE"


async def test_ac1_catch_all_size_zero_suppresses_finding():
    """AC-1: catch_all_size=0 means server returns empty body for any path → ambiguous → NO finding."""
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
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


# ---------------------------------------------------------------------------
# AC-6 / AC-7 evidence tests
# ---------------------------------------------------------------------------

async def test_ac6_probe_param_included_in_evidence():
    """AC-6/AC-7: confirmed finding evidence contains probe_param and confirmed='true'."""
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_a__.php"
        ).mock(return_value=httpx.Response(404))
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_b__.php"
        ).mock(return_value=httpx.Response(404))
        respx.get("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            return_value=httpx.Response(200, content=b"")
        )
        respx.post("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            side_effect=_echo_nonce
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    wsh150 = [f for f in findings if f.id == "PC-WSH-150"]
    assert wsh150, "expected PC-WSH-150"
    f = wsh150[0]
    assert f.evidence.get("confirmed") is True, "AC-7: evidence.confirmed must be True (bool)"
    assert "probe_param" in f.evidence, "AC-7: evidence must include probe_param"
    assert f.evidence.get("url", "").endswith("redirect.php"), "AC-7: evidence must include url"
    assert f.evidence["probe_param"] in ["password", "cmd", "c", "pass", "p", "key"], (
        "AC-6: probe_param must be one of the candidate parameters"
    )


# ---------------------------------------------------------------------------
# AC-6: b64 confirmation path
# ---------------------------------------------------------------------------

async def test_ac6_b64_payload_confirms_china_chopper():
    """AC-6: eval(base64_decode(...)) variant confirms RCE when direct printf returns empty."""
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_a__.php"
        ).mock(return_value=httpx.Response(404))
        respx.get(
            "https://example.com/wp-content/mu-plugins/__plecost_probe_b__.php"
        ).mock(return_value=httpx.Response(404))
        respx.get("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            return_value=httpx.Response(200, content=b"")
        )
        # Only the b64 payload echoes the nonce; direct printf returns empty
        respx.post("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            side_effect=_echo_nonce_only_b64
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    wsh150 = [f for f in findings if f.id == "PC-WSH-150"]
    assert wsh150, "AC-6: PC-WSH-150 must be emitted when b64 payload confirms RCE"
    f = wsh150[0]
    assert f.severity == Severity.CRITICAL, "severity must be CRITICAL"
    assert f.evidence.get("confirmed") is True, "AC-7: evidence.confirmed must be True (bool)"
    assert f.evidence["probe_param"] in ["password", "cmd", "c", "pass", "p", "key"], (
        "AC-6: probe_param must be one of the candidate parameters — b64 path"
    )


# ---------------------------------------------------------------------------
# AC-2: deep mode probes multiple names from MU_PLUGINS_NAMES wordlist
# ---------------------------------------------------------------------------

async def test_ac2_deep_mode_probes_multiple_wordlist_names():
    """AC-2: In deep mode, detect() sends GET requests for EVERY filename in MU_PLUGINS_NAMES.

    This test verifies the full wordlist scan is executed: all names are probed,
    no extra names are probed, and the catch-all probe sentinel names are not counted.
    If the implementation only probed a hardcoded subset, the missing-names assertion
    would fail.
    """
    from plecost.modules.webshells.wordlists import MU_PLUGINS_NAMES
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
    ctx.is_wordpress = True

    probed_names: list[str] = []

    def _record_and_404(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/wp-content/mu-plugins/"):
            filename = path.split("/wp-content/mu-plugins/")[-1]
            if not filename.startswith("__plecost_probe"):
                probed_names.append(filename)
        return httpx.Response(404)

    async with respx.mock:
        respx.route(url__regex=r".*").mock(side_effect=_record_and_404)
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)

    assert findings == [], "AC-2: no findings expected when all paths return 404"

    # Every name in the wordlist must have been probed exactly once
    probed_set = set(probed_names)
    expected_set = set(MU_PLUGINS_NAMES)
    missing = expected_set - probed_set
    unexpected = probed_set - expected_set
    assert not missing, (
        f"AC-2: these wordlist names were NOT probed in deep mode: {sorted(missing)}"
    )
    assert not unexpected, (
        f"AC-2: these names were probed but are NOT in MU_PLUGINS_NAMES: {sorted(unexpected)}"
    )
    assert len(probed_names) == len(MU_PLUGINS_NAMES), (
        f"AC-2: expected exactly {len(MU_PLUGINS_NAMES)} probes, got {len(probed_names)} "
        f"(duplicates indicate a bug)"
    )


# ---------------------------------------------------------------------------
# AC-3: GET 404 must NOT trigger POST probe
# ---------------------------------------------------------------------------

async def test_ac3_get_404_does_not_trigger_post_probe():
    """AC-3: Files that return GET 404 must never result in a POST confirmation probe.

    The POST probe is expensive and invasive — it must only fire for GET 200 hits
    that pass the catch-all filter. Any 404 response must be silently skipped.
    """
    post_probe_called = [False]

    def _fail_if_post(_request: httpx.Request) -> httpx.Response:
        post_probe_called[0] = True
        return httpx.Response(200, text="should-not-be-called")

    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
    ctx.is_wordpress = True
    async with respx.mock:
        # All GETs return 404 (including probe_a, probe_b, and all wordlist names)
        respx.get(url__regex=r".*").mock(return_value=httpx.Response(404))
        # Any POST request would indicate a bug — the probe must not be called
        respx.post(url__regex=r".*").mock(side_effect=_fail_if_post)
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)

    assert findings == [], "AC-3: no findings expected when all GETs return 404"
    assert not post_probe_called[0], (
        "AC-3: POST probe must NOT be called when GET returns 404"
    )


# ---------------------------------------------------------------------------
# AC-6: each candidate parameter tried individually when it is the working one
# ---------------------------------------------------------------------------

def _make_single_param_responder(winning_param: str):
    """Factory: returns a side_effect that only echoes the nonce for one specific param."""
    import re as _re_inner
    import base64 as _b64_inner

    def _side_effect(request: httpx.Request) -> httpx.Response:
        try:
            body = _urlparse.unquote_plus(request.content.decode())
            # Only respond if the winning param name is present as a form key
            if f"{winning_param}=" not in body:
                return httpx.Response(200, text="")
            # Payload 1: direct printf(strrev(...))
            m = _re_inner.search(r'printf\(strrev\("([0-9a-f]{16})"\)\)', body)
            if m:
                reversed_nonce = m.group(1)
                return httpx.Response(200, text=reversed_nonce[::-1])
            # Payload 2: eval(base64_decode(...))
            m2 = _re_inner.search(r'base64_decode\("([A-Za-z0-9+/=]+)"\)', body)
            if m2:
                inner = _b64_inner.b64decode(m2.group(1)).decode()
                m3 = _re_inner.search(r'printf\(strrev\("([0-9a-f]{16})"\)\)', inner)
                if m3:
                    return httpx.Response(200, text=m3.group(1)[::-1])
        except Exception:
            pass
        return httpx.Response(200, text="")
    return _side_effect


async def test_ac6_param_password_confirms():
    """AC-6: 'password' parameter — when only 'password' responds, finding emitted with probe_param='password'."""
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get("https://example.com/wp-content/mu-plugins/__plecost_probe_a__.php").mock(
            return_value=httpx.Response(404))
        respx.get("https://example.com/wp-content/mu-plugins/__plecost_probe_b__.php").mock(
            return_value=httpx.Response(404))
        respx.get("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            return_value=httpx.Response(200, content=b""))
        respx.post("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            side_effect=_make_single_param_responder("password"))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    wsh150 = [f for f in findings if f.id == "PC-WSH-150"]
    assert wsh150, "AC-6: PC-WSH-150 must be emitted when 'password' param confirms"
    assert wsh150[0].evidence["probe_param"] == "password", (
        "AC-6: probe_param must be 'password' when that param confirmed execution"
    )


async def test_ac6_param_cmd_confirms():
    """AC-6: 'cmd' parameter — when only 'cmd' responds, finding emitted with probe_param='cmd'."""
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get("https://example.com/wp-content/mu-plugins/__plecost_probe_a__.php").mock(
            return_value=httpx.Response(404))
        respx.get("https://example.com/wp-content/mu-plugins/__plecost_probe_b__.php").mock(
            return_value=httpx.Response(404))
        respx.get("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            return_value=httpx.Response(200, content=b""))
        respx.post("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            side_effect=_make_single_param_responder("cmd"))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    wsh150 = [f for f in findings if f.id == "PC-WSH-150"]
    assert wsh150, "AC-6: PC-WSH-150 must be emitted when 'cmd' param confirms"
    assert wsh150[0].evidence["probe_param"] == "cmd", (
        "AC-6: probe_param must be 'cmd' when that param confirmed execution"
    )


async def test_ac6_param_c_confirms():
    """AC-6: 'c' parameter — when only 'c' responds, finding emitted with probe_param='c'."""
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get("https://example.com/wp-content/mu-plugins/__plecost_probe_a__.php").mock(
            return_value=httpx.Response(404))
        respx.get("https://example.com/wp-content/mu-plugins/__plecost_probe_b__.php").mock(
            return_value=httpx.Response(404))
        respx.get("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            return_value=httpx.Response(200, content=b""))
        respx.post("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            side_effect=_make_single_param_responder("c"))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    wsh150 = [f for f in findings if f.id == "PC-WSH-150"]
    assert wsh150, "AC-6: PC-WSH-150 must be emitted when 'c' param confirms"
    assert wsh150[0].evidence["probe_param"] == "c", (
        "AC-6: probe_param must be 'c' when that param confirmed execution"
    )


async def test_ac6_param_pass_confirms():
    """AC-6: 'pass' parameter — when only 'pass' responds, finding emitted with probe_param='pass'."""
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get("https://example.com/wp-content/mu-plugins/__plecost_probe_a__.php").mock(
            return_value=httpx.Response(404))
        respx.get("https://example.com/wp-content/mu-plugins/__plecost_probe_b__.php").mock(
            return_value=httpx.Response(404))
        respx.get("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            return_value=httpx.Response(200, content=b""))
        respx.post("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            side_effect=_make_single_param_responder("pass"))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    wsh150 = [f for f in findings if f.id == "PC-WSH-150"]
    assert wsh150, "AC-6: PC-WSH-150 must be emitted when 'pass' param confirms"
    assert wsh150[0].evidence["probe_param"] == "pass", (
        "AC-6: probe_param must be 'pass' when that param confirmed execution"
    )


async def test_ac6_param_p_confirms():
    """AC-6: 'p' parameter — when only 'p' responds, finding emitted with probe_param='p'."""
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get("https://example.com/wp-content/mu-plugins/__plecost_probe_a__.php").mock(
            return_value=httpx.Response(404))
        respx.get("https://example.com/wp-content/mu-plugins/__plecost_probe_b__.php").mock(
            return_value=httpx.Response(404))
        respx.get("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            return_value=httpx.Response(200, content=b""))
        respx.post("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            side_effect=_make_single_param_responder("p"))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    wsh150 = [f for f in findings if f.id == "PC-WSH-150"]
    assert wsh150, "AC-6: PC-WSH-150 must be emitted when 'p' param confirms"
    assert wsh150[0].evidence["probe_param"] == "p", (
        "AC-6: probe_param must be 'p' when that param confirmed execution"
    )


async def test_ac6_param_key_confirms():
    """AC-6: 'key' parameter — when only 'key' responds, finding emitted with probe_param='key'."""
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
    ctx.is_wordpress = True
    async with respx.mock:
        respx.get("https://example.com/wp-content/mu-plugins/__plecost_probe_a__.php").mock(
            return_value=httpx.Response(404))
        respx.get("https://example.com/wp-content/mu-plugins/__plecost_probe_b__.php").mock(
            return_value=httpx.Response(404))
        respx.get("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            return_value=httpx.Response(200, content=b""))
        respx.post("https://example.com/wp-content/mu-plugins/redirect.php").mock(
            side_effect=_make_single_param_responder("key"))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            findings = await MuPluginsDetector().detect(ctx, http)
    wsh150 = [f for f in findings if f.id == "PC-WSH-150"]
    assert wsh150, "AC-6: PC-WSH-150 must be emitted when 'key' param confirms"
    assert wsh150[0].evidence["probe_param"] == "key", (
        "AC-6: probe_param must be 'key' when that param confirmed execution"
    )


# ---------------------------------------------------------------------------
# AC-9: CLI emits warning when --deep is active
# ---------------------------------------------------------------------------

def test_ac9_cli_emits_deep_mode_warning():
    """AC-9: Running 'plecost scan --deep' must print a warning that:
      - mentions 'mu-plugins' (the specific probe target)
      - mentions that POST requests are sent
      - mentions authorization (explicit authorization requirement)

    The warning must NOT appear when --deep is absent.
    Uses typer.testing.CliRunner with respx mocking all HTTP to 404 so the scanner
    completes without real network I/O.
    """
    from typer.testing import CliRunner
    from plecost.cli import app

    _runner = CliRunner()

    # --- deep mode: warning MUST appear ---
    with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        result_deep = _runner.invoke(
            app,
            ["scan", "https://example.com", "--deep", "--modules", "fingerprint"],
        )

    deep_output = result_deep.output or ""
    assert "mu-plugins" in deep_output, (
        f"AC-9: CLI must mention 'mu-plugins' in deep-mode warning. Got: {deep_output!r}"
    )
    assert "POST" in deep_output, (
        f"AC-9: CLI must mention 'POST' (requests) in deep-mode warning. Got: {deep_output!r}"
    )
    assert "authorization" in deep_output.lower(), (
        f"AC-9: CLI must mention 'authorization' in deep-mode warning. Got: {deep_output!r}"
    )

    # --- fast mode (no --deep): warning must NOT appear ---
    with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        result_fast = _runner.invoke(
            app,
            ["scan", "https://example.com", "--modules", "fingerprint"],
        )

    fast_output = result_fast.output or ""
    assert "mu-plugins PHP probe" not in fast_output, (
        f"AC-9: deep-mode warning must NOT appear in fast mode. Got: {fast_output!r}"
    )
