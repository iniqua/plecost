"""Tests for _clean_low_confidence_records migration utility."""
import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import select
from plecost.database.models import Base, NormalizedVuln, PluginsWordlist, ThemesWordlist
from plecost.cli import _clean_low_confidence_records


@pytest.fixture
async def db_sf():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    yield sf
    await engine.dispose()


def _make_vuln(cve_id: str, slug: str, confidence: float) -> NormalizedVuln:
    return NormalizedVuln(
        cve_id=cve_id,
        software_type="plugin",
        slug=slug,
        cpe_vendor="vendor",
        cpe_product=slug,
        match_confidence=confidence,
        severity="MEDIUM",
        title=f"{cve_id} title",
        description="desc",
        remediation="rem",
        references_json="[]",
        has_exploit=False,
        published_at="2024-01-01",
    )


async def test_deletes_low_confidence_not_in_wordlist(db_sf):
    """conf=0.5 records whose slug is NOT in wordlists must be deleted."""
    async with db_sf() as session:
        session.add(_make_vuln("CVE-2024-0001", "nonexistent_plugin_slug", 0.5))
        await session.commit()

    deleted = await _clean_low_confidence_records(db_sf)

    assert deleted == 1
    async with db_sf() as session:
        rows = (await session.execute(select(NormalizedVuln))).scalars().all()
    assert len(rows) == 0


async def test_preserves_low_confidence_in_wordlist(db_sf):
    """conf=0.5 records whose slug IS in plugins wordlist must NOT be deleted."""
    async with db_sf() as session:
        session.add(PluginsWordlist(
            slug="contact-form-7",
            active_installs=10_000_000,
            last_updated="2024-01-01",
        ))
        session.add(_make_vuln("CVE-2024-0002", "contact-form-7", 0.5))
        await session.commit()

    deleted = await _clean_low_confidence_records(db_sf)

    assert deleted == 0
    async with db_sf() as session:
        rows = (await session.execute(select(NormalizedVuln))).scalars().all()
    assert len(rows) == 1


async def test_preserves_low_confidence_in_themes_wordlist(db_sf):
    """conf=0.5 records whose slug IS in themes wordlist must NOT be deleted."""
    async with db_sf() as session:
        session.add(ThemesWordlist(
            slug="twentytwentyfour",
            active_installs=500_000,
            last_updated="2024-01-01",
        ))
        session.add(_make_vuln("CVE-2024-0005", "twentytwentyfour", 0.5))
        await session.commit()

    deleted = await _clean_low_confidence_records(db_sf)

    assert deleted == 0
    async with db_sf() as session:
        rows = (await session.execute(select(NormalizedVuln))).scalars().all()
    assert len(rows) == 1


async def test_preserves_high_confidence_records(db_sf):
    """Records with conf != 0.5 must never be deleted."""
    async with db_sf() as session:
        session.add(_make_vuln("CVE-2024-0003", "random_slug", 0.95))
        await session.commit()

    deleted = await _clean_low_confidence_records(db_sf)

    assert deleted == 0
    async with db_sf() as session:
        rows = (await session.execute(select(NormalizedVuln))).scalars().all()
    assert len(rows) == 1


async def test_idempotent(db_sf):
    """Running twice must not delete more records on second run."""
    async with db_sf() as session:
        session.add(_make_vuln("CVE-2024-0004", "ghost_slug", 0.5))
        await session.commit()

    await _clean_low_confidence_records(db_sf)
    deleted_second = await _clean_low_confidence_records(db_sf)

    assert deleted_second == 0


async def test_empty_db_returns_zero(db_sf):
    """With no records in DB, function returns 0 and does not crash."""
    deleted = await _clean_low_confidence_records(db_sf)
    assert deleted == 0


async def test_mixed_records_only_deletes_orphaned(db_sf):
    """Only conf=0.5 records with no wordlist entry are deleted; others survive."""
    async with db_sf() as session:
        # This plugin IS in the wordlist → keep
        session.add(PluginsWordlist(slug="woocommerce", active_installs=5_000_000, last_updated="2024-01-01"))
        session.add(_make_vuln("CVE-2024-0010", "woocommerce", 0.5))
        # This slug is NOT in any wordlist → delete
        session.add(_make_vuln("CVE-2024-0011", "made-up-slug", 0.5))
        # High confidence record with unknown slug → keep
        session.add(_make_vuln("CVE-2024-0012", "also-unknown", 0.95))
        await session.commit()

    deleted = await _clean_low_confidence_records(db_sf)

    assert deleted == 1
    async with db_sf() as session:
        rows = (await session.execute(select(NormalizedVuln))).scalars().all()
    assert len(rows) == 2
    slugs = {r.slug for r in rows}
    assert "woocommerce" in slugs
    assert "also-unknown" in slugs
    assert "made-up-slug" not in slugs
