"""Unit tests for MagecartModule."""
from __future__ import annotations
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest
import respx

from plecost.models import ScanOptions, WooCommerceInfo, WPECommerceInfo
from plecost.engine.context import ScanContext
from plecost.modules.magecart import MagecartModule


def _make_ctx(
    url: str = "https://example.com",
    woocommerce: bool = False,
    wp_ecommerce: bool = False,
) -> ScanContext:
    opts = ScanOptions(url=url)
    ctx = ScanContext(opts)
    if woocommerce:
        ctx.woocommerce = WooCommerceInfo(
            detected=True, version="8.0.0", active_plugins=["core"], api_namespaces=[]
        )
    if wp_ecommerce:
        ctx.wp_ecommerce = WPECommerceInfo(
            detected=True, version="3.14.0", active_gateways=[], checks_run=[]
        )
    return ctx


def _make_store(matches: list | None = None) -> MagicMock:
    """Return a mock store whose get_magecart_domains returns matches."""
    store = MagicMock()
    store.get_magecart_domains = AsyncMock(return_value=matches or [])
    return store


def _make_domain_row(domain: str, category: str = "magecart", source: str = "test") -> MagicMock:
    row = MagicMock()
    row.domain = domain
    row.category = category
    row.source = source
    row.is_active = True
    return row


# ---------------------------------------------------------------------------
# _should_run
# ---------------------------------------------------------------------------

async def test_skips_if_no_ecommerce_detected():
    """Module must skip entirely if neither WooCommerce nor WP eCommerce is detected."""
    ctx = _make_ctx()
    mod = MagecartModule(store=_make_store())
    with respx.mock:
        from plecost.engine.http_client import PlecostHTTPClient
        async with PlecostHTTPClient(ctx.opts) as http:
            await mod.run(ctx, http)
    assert not ctx.findings   # PC-MGC-000 not emitted when module doesn't run


async def test_skips_if_only_woocommerce_detected_but_run_called_with_none():
    """When store is None, module still runs and emits PC-MGC-000."""
    ctx = _make_ctx(woocommerce=True)
    mod = MagecartModule(store=None)
    with respx.mock:
        respx.get("https://example.com/checkout").mock(
            return_value=httpx.Response(200, text="<html><body>checkout</body></html>")
        )
        respx.get("https://example.com/cart").mock(
            return_value=httpx.Response(200, text="<html><body>cart</body></html>")
        )
        from plecost.engine.http_client import PlecostHTTPClient
        async with PlecostHTTPClient(ctx.opts) as http:
            await mod.run(ctx, http)
    ids = [f.id for f in ctx.findings]
    assert "PC-MGC-000" in ids


# ---------------------------------------------------------------------------
# Checkout URL generation
# ---------------------------------------------------------------------------

def test_checkout_urls_woocommerce():
    mod = MagecartModule()
    ctx = _make_ctx(woocommerce=True)
    urls = mod._get_checkout_urls(ctx)
    assert "https://example.com/checkout" in urls
    assert "https://example.com/cart" in urls


def test_checkout_urls_wp_ecommerce():
    mod = MagecartModule()
    ctx = _make_ctx(wp_ecommerce=True)
    urls = mod._get_checkout_urls(ctx)
    assert "https://example.com/?pagename=checkout" in urls
    assert "https://example.com/?pagename=cart" in urls


def test_checkout_urls_both_plugins_no_duplicates():
    mod = MagecartModule()
    ctx = _make_ctx(woocommerce=True, wp_ecommerce=True)
    urls = mod._get_checkout_urls(ctx)
    assert len(urls) == len(set(urls))
    assert len(urls) == 4  # /checkout, /cart, /?pagename=checkout, /?pagename=cart


# ---------------------------------------------------------------------------
# Detection findings
# ---------------------------------------------------------------------------

@respx.mock
async def test_detects_magecart_script_on_checkout():
    """magecart category on checkout → PC-MGC-001 CRITICAL."""
    ctx = _make_ctx(woocommerce=True)
    evil_domain = "analytics-cdn.ru"
    html = f'<script src="https://{evil_domain}/track.js"></script>'
    respx.get("https://example.com/checkout").mock(return_value=httpx.Response(200, text=html))
    respx.get("https://example.com/cart").mock(return_value=httpx.Response(200, text="<html></html>"))

    store = _make_store([_make_domain_row(evil_domain, category="magecart")])
    mod = MagecartModule(store=store)

    from plecost.engine.http_client import PlecostHTTPClient
    async with PlecostHTTPClient(ctx.opts) as http:
        await mod.run(ctx, http)

    ids = [f.id for f in ctx.findings]
    assert "PC-MGC-001" in ids
    f = next(f for f in ctx.findings if f.id == "PC-MGC-001")
    assert f.severity.value == "CRITICAL"
    assert f.cvss_score == 9.8


@respx.mock
async def test_detects_dropper_on_checkout():
    """dropper category on checkout → PC-MGC-002 CRITICAL."""
    ctx = _make_ctx(woocommerce=True)
    evil_domain = "dropper-evil.com"
    html = f'<script src="https://{evil_domain}/load.js"></script>'
    respx.get("https://example.com/checkout").mock(return_value=httpx.Response(200, text=html))
    respx.get("https://example.com/cart").mock(return_value=httpx.Response(200, text=""))

    store = _make_store([_make_domain_row(evil_domain, category="dropper")])
    mod = MagecartModule(store=store)

    from plecost.engine.http_client import PlecostHTTPClient
    async with PlecostHTTPClient(ctx.opts) as http:
        await mod.run(ctx, http)

    ids = [f.id for f in ctx.findings]
    assert "PC-MGC-002" in ids


@respx.mock
async def test_detects_exfiltrator_on_checkout():
    """exfiltrator category on checkout → PC-MGC-003 HIGH."""
    ctx = _make_ctx(woocommerce=True)
    evil_domain = "exfil-evil.net"
    html = f'<script src="https://{evil_domain}/send.js"></script>'
    respx.get("https://example.com/checkout").mock(return_value=httpx.Response(200, text=html))
    respx.get("https://example.com/cart").mock(return_value=httpx.Response(200, text=""))

    store = _make_store([_make_domain_row(evil_domain, category="exfiltrator")])
    mod = MagecartModule(store=store)

    from plecost.engine.http_client import PlecostHTTPClient
    async with PlecostHTTPClient(ctx.opts) as http:
        await mod.run(ctx, http)

    ids = [f.id for f in ctx.findings]
    assert "PC-MGC-003" in ids
    f = next(f for f in ctx.findings if f.id == "PC-MGC-003")
    assert f.severity.value == "HIGH"
    assert f.cvss_score == 8.1


@respx.mock
async def test_lower_severity_outside_checkout():
    """Any category on non-checkout page → PC-MGC-004 MEDIUM."""
    ctx = _make_ctx(woocommerce=True)
    evil_domain = "analytics-cdn.ru"
    # Non-checkout URL — we'll test _scan_page directly with a synthetic URL
    html = f'<script src="https://{evil_domain}/track.js"></script>'

    store = _make_store([_make_domain_row(evil_domain, category="magecart")])
    mod = MagecartModule(store=store)

    pages: list[str] = []
    counter: list[int] = [0]
    malicious: list[str] = []

    respx.get("https://example.com/about").mock(return_value=httpx.Response(200, text=html))

    from plecost.engine.http_client import PlecostHTTPClient
    async with PlecostHTTPClient(ctx.opts) as http:
        await mod._scan_page(ctx, http, "https://example.com/about", pages, counter, malicious)

    ids = [f.id for f in ctx.findings]
    assert "PC-MGC-004" in ids
    f = next(f for f in ctx.findings if f.id == "PC-MGC-004")
    assert f.severity.value == "MEDIUM"


@respx.mock
async def test_clean_site_no_findings():
    """Scripts from unlisted domains produce no findings (except PC-MGC-000 summary)."""
    ctx = _make_ctx(woocommerce=True)
    html = '<script src="https://cdn.legit.com/jquery.js"></script>'
    respx.get("https://example.com/checkout").mock(return_value=httpx.Response(200, text=html))
    respx.get("https://example.com/cart").mock(return_value=httpx.Response(200, text=""))

    store = _make_store([])  # empty result → no matches
    mod = MagecartModule(store=store)

    from plecost.engine.http_client import PlecostHTTPClient
    async with PlecostHTTPClient(ctx.opts) as http:
        await mod.run(ctx, http)

    ids = [f.id for f in ctx.findings]
    assert "PC-MGC-000" in ids
    assert "PC-MGC-001" not in ids
    assert "PC-MGC-002" not in ids


@respx.mock
async def test_summary_always_emitted():
    """PC-MGC-000 is always emitted when the module runs."""
    ctx = _make_ctx(woocommerce=True)
    respx.get("https://example.com/checkout").mock(return_value=httpx.Response(200, text=""))
    respx.get("https://example.com/cart").mock(return_value=httpx.Response(200, text=""))

    mod = MagecartModule(store=_make_store([]))

    from plecost.engine.http_client import PlecostHTTPClient
    async with PlecostHTTPClient(ctx.opts) as http:
        await mod.run(ctx, http)

    assert any(f.id == "PC-MGC-000" for f in ctx.findings)


@respx.mock
async def test_ctx_magecart_populated():
    """ctx.magecart is populated with correct malicious_domains after run."""
    ctx = _make_ctx(woocommerce=True)
    evil_domain = "skimmer.ru"
    html = f'<script src="https://{evil_domain}/x.js"></script>'
    respx.get("https://example.com/checkout").mock(return_value=httpx.Response(200, text=html))
    respx.get("https://example.com/cart").mock(return_value=httpx.Response(200, text=""))

    store = _make_store([_make_domain_row(evil_domain, category="magecart")])
    mod = MagecartModule(store=store)

    from plecost.engine.http_client import PlecostHTTPClient
    async with PlecostHTTPClient(ctx.opts) as http:
        await mod.run(ctx, http)

    assert ctx.magecart is not None
    assert ctx.magecart.detected is True
    assert evil_domain in ctx.magecart.malicious_domains


@respx.mock
async def test_page_404_skipped_gracefully():
    """Non-200 responses are silently skipped — no crash, no findings."""
    ctx = _make_ctx(woocommerce=True)
    respx.get("https://example.com/checkout").mock(return_value=httpx.Response(404, text="Not Found"))
    respx.get("https://example.com/cart").mock(return_value=httpx.Response(404, text="Not Found"))

    mod = MagecartModule(store=_make_store([]))

    from plecost.engine.http_client import PlecostHTTPClient
    async with PlecostHTTPClient(ctx.opts) as http:
        await mod.run(ctx, http)  # must not raise

    ids = [f.id for f in ctx.findings]
    assert "PC-MGC-001" not in ids


@respx.mock
async def test_inline_scripts_ignored():
    """Scripts without a src attribute are not analyzed."""
    ctx = _make_ctx(woocommerce=True)
    html = "<script>alert('xss')</script>"
    respx.get("https://example.com/checkout").mock(return_value=httpx.Response(200, text=html))
    respx.get("https://example.com/cart").mock(return_value=httpx.Response(200, text=""))

    store = _make_store()
    mod = MagecartModule(store=store)

    from plecost.engine.http_client import PlecostHTTPClient
    async with PlecostHTTPClient(ctx.opts) as http:
        await mod.run(ctx, http)

    # get_magecart_domains should not be called with any domains
    store.get_magecart_domains.assert_not_called()


@respx.mock
async def test_same_domain_script_ignored():
    """Scripts from the same domain as the target are not analyzed."""
    ctx = _make_ctx(url="https://example.com", woocommerce=True)
    html = '<script src="https://example.com/wp-content/themes/mytheme/js/main.js"></script>'
    respx.get("https://example.com/checkout").mock(return_value=httpx.Response(200, text=html))
    respx.get("https://example.com/cart").mock(return_value=httpx.Response(200, text=""))

    store = _make_store()
    mod = MagecartModule(store=store)

    from plecost.engine.http_client import PlecostHTTPClient
    async with PlecostHTTPClient(ctx.opts) as http:
        await mod.run(ctx, http)

    store.get_magecart_domains.assert_not_called()


@respx.mock
async def test_multiple_malicious_scripts():
    """Two matching domains produce two separate findings."""
    ctx = _make_ctx(woocommerce=True)
    evil1 = "evil1.ru"
    evil2 = "evil2.ru"
    html = (
        f'<script src="https://{evil1}/a.js"></script>'
        f'<script src="https://{evil2}/b.js"></script>'
    )
    respx.get("https://example.com/checkout").mock(return_value=httpx.Response(200, text=html))
    respx.get("https://example.com/cart").mock(return_value=httpx.Response(200, text=""))

    store = _make_store([
        _make_domain_row(evil1, category="magecart"),
        _make_domain_row(evil2, category="dropper"),
    ])
    mod = MagecartModule(store=store)

    from plecost.engine.http_client import PlecostHTTPClient
    async with PlecostHTTPClient(ctx.opts) as http:
        await mod.run(ctx, http)

    ids = [f.id for f in ctx.findings]
    assert ids.count("PC-MGC-001") >= 1
    assert ids.count("PC-MGC-002") >= 1


@respx.mock
async def test_db_store_called_with_correct_domains():
    """Verifies that get_magecart_domains is called with the extracted external domains."""
    ctx = _make_ctx(woocommerce=True)
    html = '<script src="https://cdn.evil.ru/track.js"></script>'
    respx.get("https://example.com/checkout").mock(return_value=httpx.Response(200, text=html))
    respx.get("https://example.com/cart").mock(return_value=httpx.Response(200, text=""))

    store = _make_store([])
    mod = MagecartModule(store=store)

    from plecost.engine.http_client import PlecostHTTPClient
    async with PlecostHTTPClient(ctx.opts) as http:
        await mod.run(ctx, http)

    # get_magecart_domains must be called with a list containing the evil domain
    calls = store.get_magecart_domains.call_args_list
    assert len(calls) >= 1
    called_domains = calls[0][0][0]
    assert "cdn.evil.ru" in called_domains
