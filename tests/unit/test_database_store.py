import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from plecost.database.models import Base, NormalizedVuln, RejectedCve, PluginsWordlist, ThemesWordlist
from plecost.database.store import CVEStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_vuln_row(**kwargs) -> NormalizedVuln:
    """Build a NormalizedVuln with sensible defaults, overridable via kwargs."""
    defaults = dict(
        cve_id="CVE-2024-1234",
        software_type="plugin",
        slug="woocommerce",
        cpe_vendor="woocommerce",
        cpe_product="woocommerce",
        match_confidence=1.0,
        version_start_incl=None,
        version_start_excl=None,
        version_end_incl=None,
        version_end_excl=None,
        cvss_score=8.1,
        severity="HIGH",
        title="SQL Injection in WooCommerce",
        description="SQL injection via order param",
        remediation="Update to 8.3.1",
        references_json='["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"]',
        has_exploit=True,
        published_at="2024-01-15",
    )
    defaults.update(kwargs)
    return NormalizedVuln(**defaults)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def store(tmp_path):
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    engine = create_async_engine(db_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    # Insert test data: woocommerce 8.0.0–8.3.0 (inclusive)
    async with sf() as session:
        session.add(_make_vuln_row(
            version_start_incl="8.0.0",
            version_end_incl="8.3.0",
        ))
        await session.commit()
    return CVEStore(sf)


# ---------------------------------------------------------------------------
# Original tests (unchanged)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_find_plugin_vulnerabilities(store):
    vulns = await store.find("plugin", "woocommerce", "8.1.0")
    assert len(vulns) == 1
    assert vulns[0].cve_id == "CVE-2024-1234"
    assert vulns[0].severity == "HIGH"
    assert vulns[0].has_exploit is True


@pytest.mark.asyncio
async def test_no_vulns_for_patched_version(store):
    vulns = await store.find("plugin", "woocommerce", "8.4.0")
    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_no_vulns_for_different_plugin(store):
    vulns = await store.find("plugin", "akismet", "5.0.0")
    assert len(vulns) == 0


# ---------------------------------------------------------------------------
# AC-16 (G-035): _is_affected() branches tested via find()
# ---------------------------------------------------------------------------

@pytest.fixture
async def store_start_incl(tmp_path):
    """Store with a CVE using version_start_incl only (no end range)."""
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    engine = create_async_engine(db_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    async with sf() as session:
        session.add(_make_vuln_row(version_start_incl="5.0.0", version_end_incl="6.0.0"))
        await session.commit()
    return CVEStore(sf)


@pytest.fixture
async def store_start_excl(tmp_path):
    """Store with a CVE using version_start_excl only."""
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    engine = create_async_engine(db_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    async with sf() as session:
        session.add(_make_vuln_row(version_start_excl="5.0.0", version_end_incl="6.0.0"))
        await session.commit()
    return CVEStore(sf)


@pytest.fixture
async def store_end_excl(tmp_path):
    """Store with a CVE using version_end_excl."""
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    engine = create_async_engine(db_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    async with sf() as session:
        session.add(_make_vuln_row(version_start_incl="5.0.0", version_end_excl="6.0.0"))
        await session.commit()
    return CVEStore(sf)


@pytest.fixture
async def store_all_none(tmp_path):
    """Store with a CVE where all version range fields are None."""
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    engine = create_async_engine(db_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    async with sf() as session:
        session.add(_make_vuln_row())  # all version range fields default to None
        await session.commit()
    return CVEStore(sf)


@pytest.fixture
async def store_invalid_range(tmp_path):
    """Store with a CVE that has an unparseable version string in a range field."""
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    engine = create_async_engine(db_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    async with sf() as session:
        session.add(_make_vuln_row(version_start_incl="not-a-version", version_end_incl="6.0.0"))
        await session.commit()
    return CVEStore(sf)


@pytest.mark.asyncio
async def test_is_affected_below_version_start_incl(store_start_incl):
    """AC-16: version below version_start_incl → not affected."""
    vulns = await store_start_incl.find("plugin", "woocommerce", "4.9.9")
    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_is_affected_at_version_start_excl(store_start_excl):
    """AC-16: version equal to version_start_excl (exclusive) → not affected."""
    vulns = await store_start_excl.find("plugin", "woocommerce", "5.0.0")
    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_is_affected_above_version_end_incl(store_start_incl):
    """AC-16: version above version_end_incl → not affected."""
    vulns = await store_start_incl.find("plugin", "woocommerce", "6.0.1")
    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_is_affected_at_version_end_excl(store_end_excl):
    """AC-16: version equal to version_end_excl (exclusive) → not affected."""
    vulns = await store_end_excl.find("plugin", "woocommerce", "6.0.0")
    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_is_affected_all_none_returns_false(store_all_none):
    """AC-16: all version range fields None → not affected (suppresses historical CVEs)."""
    vulns = await store_all_none.find("plugin", "woocommerce", "5.5.0")
    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_is_affected_invalid_version_in_range_field(store_invalid_range):
    """AC-16: invalid version string in range field → not affected, no crash."""
    vulns = await store_invalid_range.find("plugin", "woocommerce", "5.5.0")
    assert len(vulns) == 0


# ---------------------------------------------------------------------------
# AC-17 (G-036): RejectedCve filtering in find()
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_find_excludes_rejected_cves(store):
    """AC-17: a CVE in rejected_cves is not returned by find()."""
    # Access the internal session factory to insert a rejected entry
    sf = store._sf
    async with sf() as session:
        session.add(RejectedCve(cve_id="CVE-2024-1234", reason="deleted", rejected_at="2026-04-12"))
        await session.commit()

    vulns = await store.find("plugin", "woocommerce", "8.1.0")
    assert len(vulns) == 0, "Rejected CVE must not be returned by find()"


# ---------------------------------------------------------------------------
# AC-18 (G-037): find_all_by_slug()
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_find_all_by_slug_returns_all(store):
    """AC-18: find_all_by_slug returns all CVEs for the given slug regardless of version."""
    vulns = await store.find_all_by_slug("plugin", "woocommerce")
    assert len(vulns) == 1
    assert vulns[0].cve_id == "CVE-2024-1234"


@pytest.mark.asyncio
async def test_find_all_by_slug_excludes_rejected(store):
    """AC-18: find_all_by_slug excludes rejected CVEs."""
    sf = store._sf
    async with sf() as session:
        session.add(RejectedCve(cve_id="CVE-2024-1234", reason="deleted", rejected_at="2026-04-12"))
        await session.commit()

    vulns = await store.find_all_by_slug("plugin", "woocommerce")
    assert len(vulns) == 0, "Rejected CVE must not be returned by find_all_by_slug()"


@pytest.mark.asyncio
async def test_find_all_by_slug_unknown_slug_returns_empty(store):
    """AC-18: find_all_by_slug returns empty list for an unknown slug."""
    vulns = await store.find_all_by_slug("plugin", "unknown-plugin-xyz")
    assert vulns == []


# ---------------------------------------------------------------------------
# AC-19 (G-038): get_plugins_wordlist() and get_themes_wordlist()
# ---------------------------------------------------------------------------

@pytest.fixture
async def wordlist_store(tmp_path):
    """Store pre-populated with PluginsWordlist and ThemesWordlist entries."""
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'wordlist.db'}"
    engine = create_async_engine(db_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    async with sf() as session:
        session.add(PluginsWordlist(slug="woocommerce", active_installs=5_000_000))
        session.add(PluginsWordlist(slug="akismet", active_installs=10_000_000))
        session.add(PluginsWordlist(slug="jetpack", active_installs=3_000_000))
        session.add(ThemesWordlist(slug="twentytwentyfour", active_installs=2_000_000))
        session.add(ThemesWordlist(slug="astra", active_installs=1_000_000))
        await session.commit()
    return CVEStore(sf)


@pytest.mark.asyncio
async def test_get_plugins_wordlist_ordered_by_popularity(wordlist_store):
    """AC-19: get_plugins_wordlist returns slugs ordered by active_installs DESC."""
    slugs = await wordlist_store.get_plugins_wordlist()
    assert slugs[0] == "akismet", "Most-installed plugin should be first"
    assert slugs[1] == "woocommerce"
    assert slugs[2] == "jetpack"


@pytest.mark.asyncio
async def test_get_plugins_wordlist_top_n(wordlist_store):
    """AC-19: get_plugins_wordlist with top_n limits the number of results."""
    slugs = await wordlist_store.get_plugins_wordlist(top_n=2)
    assert len(slugs) == 2
    assert slugs[0] == "akismet"  # highest installs first


@pytest.mark.asyncio
async def test_get_themes_wordlist(wordlist_store):
    """AC-19: get_themes_wordlist returns theme slugs ordered by active_installs DESC."""
    slugs = await wordlist_store.get_themes_wordlist()
    assert len(slugs) == 2
    assert slugs[0] == "twentytwentyfour"  # higher installs first


# ---------------------------------------------------------------------------
# AC-7 (G-001): CVEStore.from_url(":memory:") does not raise FileNotFoundError
# ---------------------------------------------------------------------------

def test_from_url_memory_does_not_raise():
    """AC-7: CVEStore.from_url(':memory:') must not raise FileNotFoundError,
    and the returned store must have a working session factory."""
    # FileNotFoundError must not be raised for in-memory databases
    store_obj = CVEStore.from_url("sqlite+aiosqlite:///:memory:")
    # The store must be a fully-constructed CVEStore, not a stub
    assert isinstance(store_obj, CVEStore)
    # The session factory must be callable (not None)
    assert store_obj._sf is not None
    assert callable(store_obj._sf)


# ---------------------------------------------------------------------------
# AC-16 positive case: version within exclusive range IS affected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_is_affected_version_within_exclusive_range(tmp_path):
    """AC-16: version strictly within (start_excl, end_excl) range IS affected."""
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'excl.db'}"
    engine = create_async_engine(db_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    async with sf() as session:
        session.add(NormalizedVuln(
            cve_id="CVE-EXCL-001",
            software_type="plugin",
            slug="myplugin",
            match_confidence=1.0,
            version_start_excl="5.0.0",  # exclusive: 5.0.0 NOT affected
            version_end_excl="6.0.0",    # exclusive: 6.0.0 NOT affected
            severity="HIGH",
            title="Test CVE",
            description="desc",
            remediation="update",
            references_json="[]",
            has_exploit=False,
            published_at="2024-01-01",
        ))
        await session.commit()
    store = CVEStore(sf)

    # 5.0.1 is within (5.0.0, 6.0.0) exclusive → SHOULD be affected
    vulns = await store.find("plugin", "myplugin", "5.0.1")
    assert len(vulns) == 1, "Version 5.0.1 within exclusive range should be affected"
    assert vulns[0].cve_id == "CVE-EXCL-001"

    await engine.dispose()
