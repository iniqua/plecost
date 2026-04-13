"""Unit tests for MagecartDomain store queries."""
from __future__ import annotations
import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from plecost.database.models import Base, MagecartDomain
from plecost.database.store import CVEStore


@pytest.fixture
async def store(tmp_path):
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'test_magecart.db'}"
    engine = create_async_engine(db_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    async with sf() as session:
        session.add(MagecartDomain(
            domain="evil-cdn.ru",
            category="magecart",
            source="groups123",
            added_date="2026-04-14",
            is_active=True,
        ))
        session.add(MagecartDomain(
            domain="dropper.net",
            category="dropper",
            source="feodotracker",
            added_date="2026-04-14",
            is_active=True,
        ))
        session.add(MagecartDomain(
            domain="inactive.ru",
            category="magecart",
            source="test",
            added_date="2026-01-01",
            is_active=False,  # soft-deleted
        ))
        await session.commit()
    return CVEStore(sf)


async def test_get_magecart_domains_returns_matches(store):
    """Active domains in the query list are returned."""
    results = await store.get_magecart_domains(["evil-cdn.ru", "dropper.net"])
    domains = {r.domain for r in results}
    assert "evil-cdn.ru" in domains
    assert "dropper.net" in domains


async def test_get_magecart_domains_empty_db():
    """Empty domain list returns empty result without error."""
    import aiosqlite  # noqa: F401 — needed for aiosqlite dialect
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    store = CVEStore(sf)
    results = await store.get_magecart_domains([])
    assert results == []


async def test_get_magecart_domains_inactive_excluded(store):
    """Soft-deleted (is_active=False) domains are NOT returned."""
    results = await store.get_magecart_domains(["inactive.ru"])
    assert results == []
