from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from plecost.database.engine import make_engine, make_session_factory
from plecost.database.models import Base


def test_make_engine_sqlite():
    engine = make_engine("sqlite+aiosqlite:///:memory:")
    assert isinstance(engine, AsyncEngine)


async def test_make_session_factory():
    engine = make_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    sf = make_session_factory(engine)
    async with sf() as session:
        assert isinstance(session, AsyncSession)

    await engine.dispose()


async def test_engine_creates_tables(tmp_path):
    db_path = tmp_path / "test.db"
    engine = make_engine(f"sqlite+aiosqlite:///{db_path}")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Verify the normalized_vulns table exists by inspecting metadata
    from sqlalchemy import inspect, text

    async with engine.connect() as conn:
        result = await conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='normalized_vulns'")
        )
        row = result.fetchone()
        assert row is not None
        assert row[0] == "normalized_vulns"

    await engine.dispose()
