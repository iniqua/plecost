"""
Tests for _sync_active_installs (G-017):
Populate active_installs from WP.org API in update-db.

AC-1: active_installs are updated from WP.org API mock after call
AC-2: pagination works across multiple pages
AC-3: get_plugins_wordlist(N) returns top-N by active_installs DESC
AC-4: WP.org API failure → function returns without crashing
AC-5: only updates slugs that exist in DB, does not insert new ones
"""
from __future__ import annotations

import pytest
import httpx
import respx
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from plecost.database.models import Base, PluginsWordlist, ThemesWordlist
from plecost.database.store import CVEStore
from plecost.cli import _sync_active_installs


# ---------------------------------------------------------------------------
# Helpers / Fixtures
# ---------------------------------------------------------------------------

PLUGIN_API_BASE = "https://api.wordpress.org/plugins/info/1.2/"
THEME_API_BASE = "https://api.wordpress.org/themes/info/1.1/"


def _plugin_api_url(page: int = 1, per_page: int = 100) -> str:
    return (
        f"{PLUGIN_API_BASE}"
        f"?action=query_plugins"
        f"&request[fields][active_installs]=1"
        f"&request[per_page]={per_page}"
        f"&request[page]={page}"
    )


def _theme_api_url(page: int = 1, per_page: int = 100) -> str:
    return (
        f"{THEME_API_BASE}"
        f"?action=query_themes"
        f"&request[fields][active_installs]=1"
        f"&request[per_page]={per_page}"
        f"&request[page]={page}"
    )


@pytest.fixture
async def memory_sf():
    """In-memory SQLite database with schema created."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    yield sf
    await engine.dispose()


@pytest.fixture
async def populated_sf(memory_sf):
    """DB with plugin and theme slugs pre-inserted (active_installs=0)."""
    async with memory_sf() as session:
        session.add_all([
            PluginsWordlist(slug="woocommerce", active_installs=0),
            PluginsWordlist(slug="jetpack", active_installs=0),
            PluginsWordlist(slug="contact-form-7", active_installs=0),
        ])
        session.add_all([
            ThemesWordlist(slug="twentytwentyfour", active_installs=0),
            ThemesWordlist(slug="astra", active_installs=0),
        ])
        await session.commit()
    return memory_sf


# ---------------------------------------------------------------------------
# AC-1: active_installs updated from WP.org API
# ---------------------------------------------------------------------------

@respx.mock
async def test_ac1_active_installs_updated_from_api(populated_sf):
    """After _sync_active_installs, DB records reflect values from the WP.org API."""
    # Mock plugin API — single page, fewer than 100 items → last page
    respx.get(_plugin_api_url(page=1)).mock(return_value=httpx.Response(200, json={
        "plugins": [
            {"slug": "woocommerce", "active_installs": 5000000},
            {"slug": "jetpack", "active_installs": 3000000},
            {"slug": "contact-form-7", "active_installs": 2000000},
        ]
    }))
    # Mock theme API — single page
    respx.get(_theme_api_url(page=1)).mock(return_value=httpx.Response(200, json={
        "themes": [
            {"slug": "twentytwentyfour", "active_installs": 1000000},
            {"slug": "astra", "active_installs": 800000},
        ]
    }))

    await _sync_active_installs(populated_sf)

    # Verify plugin active_installs updated
    store = CVEStore(populated_sf)
    plugins = await store.get_plugins_wordlist()
    assert plugins[0] == "woocommerce"   # highest installs first
    assert plugins[1] == "jetpack"
    assert plugins[2] == "contact-form-7"

    # Verify theme active_installs updated
    themes = await store.get_themes_wordlist()
    assert themes[0] == "twentytwentyfour"
    assert themes[1] == "astra"


# ---------------------------------------------------------------------------
# AC-2: Pagination — multiple pages fetched
# ---------------------------------------------------------------------------

@respx.mock
async def test_ac2_pagination_multiple_pages(memory_sf):
    """_sync_active_installs paginates across multiple pages to collect all data."""
    # Insert slugs that will appear across pages
    async with memory_sf() as session:
        session.add_all([
            PluginsWordlist(slug="plugin-page1", active_installs=0),
            PluginsWordlist(slug="plugin-page2", active_installs=0),
        ])
        await session.commit()

    # Page 1: full (100 items) — include our target slug
    page1_items = [{"slug": "plugin-page1", "active_installs": 9000}]
    page1_items += [{"slug": f"other-{i}", "active_installs": 100} for i in range(99)]
    assert len(page1_items) == 100

    # Page 2: partial (fewer than 100) — include second target slug
    page2_items = [{"slug": "plugin-page2", "active_installs": 7000}]

    respx.get(_plugin_api_url(page=1)).mock(return_value=httpx.Response(200, json={"plugins": page1_items}))
    respx.get(_plugin_api_url(page=2)).mock(return_value=httpx.Response(200, json={"plugins": page2_items}))

    # Theme API: empty to stop immediately
    respx.get(_theme_api_url(page=1)).mock(return_value=httpx.Response(200, json={"themes": []}))

    await _sync_active_installs(memory_sf)

    store = CVEStore(memory_sf)
    slugs = await store.get_plugins_wordlist()
    assert slugs[0] == "plugin-page1"   # 9000 installs — most popular
    assert slugs[1] == "plugin-page2"   # 7000 installs


# ---------------------------------------------------------------------------
# AC-3: get_plugins_wordlist returns top-N by active_installs DESC
# ---------------------------------------------------------------------------

@respx.mock
async def test_ac3_top_n_by_popularity(populated_sf):
    """get_plugins_wordlist(N) returns exactly top-N slugs ordered by active_installs DESC."""
    respx.get(_plugin_api_url(page=1)).mock(return_value=httpx.Response(200, json={
        "plugins": [
            {"slug": "woocommerce", "active_installs": 5000000},
            {"slug": "jetpack", "active_installs": 3000000},
            {"slug": "contact-form-7", "active_installs": 2000000},
        ]
    }))
    respx.get(_theme_api_url(page=1)).mock(return_value=httpx.Response(200, json={"themes": []}))

    await _sync_active_installs(populated_sf)

    store = CVEStore(populated_sf)
    # Request top 2 only
    top2 = await store.get_plugins_wordlist(top_n=2)
    assert len(top2) == 2
    assert top2[0] == "woocommerce"
    assert top2[1] == "jetpack"
    # contact-form-7 excluded since we only asked for top 2


# ---------------------------------------------------------------------------
# AC-4: WP.org API unavailable → no crash, function returns gracefully
# ---------------------------------------------------------------------------

@respx.mock
async def test_ac4_api_failure_no_crash(populated_sf):
    """If the WP.org API is unreachable, _sync_active_installs returns without raising."""
    # Simulate network error for all requests
    respx.get(_plugin_api_url(page=1)).mock(side_effect=httpx.ConnectError("Network unreachable"))
    respx.get(_theme_api_url(page=1)).mock(side_effect=httpx.ConnectError("Network unreachable"))

    # Must NOT raise any exception
    await _sync_active_installs(populated_sf)

    # DB records should remain at 0 (unchanged)
    store = CVEStore(populated_sf)
    plugins = await store.get_plugins_wordlist()
    assert "woocommerce" in plugins  # still present, order may vary (all 0)


@respx.mock
async def test_ac4_api_http_error_no_crash(populated_sf):
    """If the WP.org API returns a server error, _sync_active_installs returns without raising."""
    respx.get(_plugin_api_url(page=1)).mock(return_value=httpx.Response(503))
    respx.get(_theme_api_url(page=1)).mock(return_value=httpx.Response(503))

    # Must NOT raise any exception
    await _sync_active_installs(populated_sf)

    # DB records unchanged
    store = CVEStore(populated_sf)
    plugins = await store.get_plugins_wordlist()
    assert len(plugins) == 3  # woocommerce, jetpack, contact-form-7


# ---------------------------------------------------------------------------
# AC-5: Only updates existing slugs, does not insert new ones
# ---------------------------------------------------------------------------

@respx.mock
async def test_ac5_only_updates_existing_slugs(memory_sf):
    """_sync_active_installs must not insert new slugs returned by the API."""
    async with memory_sf() as session:
        session.add(PluginsWordlist(slug="existing-plugin", active_installs=0))
        await session.commit()

    # API returns "existing-plugin" AND "unknown-plugin" (not in DB)
    respx.get(_plugin_api_url(page=1)).mock(return_value=httpx.Response(200, json={
        "plugins": [
            {"slug": "existing-plugin", "active_installs": 10000},
            {"slug": "unknown-plugin", "active_installs": 99999},  # NOT in DB
        ]
    }))
    respx.get(_theme_api_url(page=1)).mock(return_value=httpx.Response(200, json={"themes": []}))

    await _sync_active_installs(memory_sf)

    store = CVEStore(memory_sf)
    plugins = await store.get_plugins_wordlist()

    # Only existing-plugin should be in the list
    assert "existing-plugin" in plugins
    assert "unknown-plugin" not in plugins
    # Exactly 1 plugin (no new row inserted)
    assert len(plugins) == 1


@respx.mock
async def test_ac5_active_installs_value_correctly_set(memory_sf):
    """Verify the actual active_installs value is written, not just presence of slug."""
    from sqlalchemy import select
    from plecost.database.models import PluginsWordlist

    async with memory_sf() as session:
        session.add(PluginsWordlist(slug="my-plugin", active_installs=0))
        await session.commit()

    respx.get(_plugin_api_url(page=1)).mock(return_value=httpx.Response(200, json={
        "plugins": [{"slug": "my-plugin", "active_installs": 42000}]
    }))
    respx.get(_theme_api_url(page=1)).mock(return_value=httpx.Response(200, json={"themes": []}))

    await _sync_active_installs(memory_sf)

    # Check the raw DB value — not just the ordering
    async with memory_sf() as session:
        result = await session.execute(
            select(PluginsWordlist).where(PluginsWordlist.slug == "my-plugin")
        )
        row = result.scalar_one()
        assert row.active_installs == 42000
