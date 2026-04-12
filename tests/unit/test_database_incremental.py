from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from plecost.database.incremental import IncrementalUpdater, NVD_CVE_API
from plecost.database.models import Base, DbMetadata

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_nvd_response(cve_ids: list[str] | None = None) -> dict:
    """Return a minimal NVD API response with zero or more CVE items."""
    if not cve_ids:
        return {"totalResults": 0, "vulnerabilities": []}

    vulns = []
    for cve_id in cve_ids:
        vulns.append({
            "cve": {
                "id": cve_id,
                "descriptions": [{"lang": "en", "value": "Test"}],
                "metrics": {},
                "references": [],
                "published": "2024-01-01T00:00:00.000",
                "configurations": [],
            }
        })
    return {"totalResults": len(vulns), "vulnerabilities": vulns}


async def _make_db_sf(*, last_sync: str | None = None):
    """Create an in-memory SQLite DB, optionally seeding last_nvd_sync."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    if last_sync:
        async with sf() as session:
            session.add(DbMetadata(key="last_nvd_sync", value=last_sync))
            await session.commit()
    return engine, sf


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@respx.mock
async def test_incremental_reads_last_sync_date(tmp_path):
    """IncrementalUpdater sends lastModStartDate matching the stored last_nvd_sync."""
    last_sync = "2024-06-01T00:00:00.000"

    engine, sf = await _make_db_sf(last_sync=last_sync)
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"

    # We need a real DB file to pass db_url to IncrementalUpdater
    # Pre-populate the DB file with last_nvd_sync
    file_engine = create_async_engine(db_url)
    async with file_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    file_sf = async_sessionmaker(file_engine, expire_on_commit=False)
    async with file_sf() as session:
        session.add(DbMetadata(key="last_nvd_sync", value=last_sync))
        await session.commit()
    await file_engine.dispose()

    # Mock NVD API — capture request params
    nvd_route = respx.get(NVD_CVE_API).mock(
        return_value=httpx.Response(200, json=_make_nvd_response())
    )

    updater = IncrementalUpdater(db_url=db_url)
    await updater.run()

    # Verify lastModStartDate was sent with the stored sync date
    assert nvd_route.called
    request = nvd_route.calls[0].request
    url_str = str(request.url)
    assert "lastModStartDate" in url_str
    assert "2024-06-01" in url_str


@respx.mock
async def test_incremental_updates_sync_date(tmp_path):
    """After run(), last_nvd_sync in DB is updated to (approximately) now."""
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    old_sync = "2024-01-01T00:00:00.000"

    # Seed the DB
    seed_engine = create_async_engine(db_url)
    async with seed_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    seed_sf = async_sessionmaker(seed_engine, expire_on_commit=False)
    async with seed_sf() as session:
        session.add(DbMetadata(key="last_nvd_sync", value=old_sync))
        await session.commit()
    await seed_engine.dispose()

    respx.get(NVD_CVE_API).mock(
        return_value=httpx.Response(200, json=_make_nvd_response())
    )

    before = datetime.now(timezone.utc).replace(microsecond=0)
    updater = IncrementalUpdater(db_url=db_url)
    await updater.run()
    after = datetime.now(timezone.utc).replace(microsecond=0)

    # Read updated value
    read_engine = create_async_engine(db_url)
    read_sf = async_sessionmaker(read_engine, expire_on_commit=False)
    async with read_sf() as session:
        row = await session.get(DbMetadata, "last_nvd_sync")

    assert row is not None
    new_sync = row.value
    assert new_sync != old_sync

    # Parse the new sync date and check it is within [before, after]
    new_dt = datetime.strptime(new_sync, "%Y-%m-%dT%H:%M:%S.000").replace(tzinfo=timezone.utc)
    assert before <= new_dt <= after + timedelta(seconds=2)

    await read_engine.dispose()


@respx.mock
async def test_incremental_no_prior_sync(tmp_path):
    """If no last_nvd_sync row exists, a fallback date (≈2 days ago) is used."""
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"

    # Create the DB without any last_nvd_sync
    init_engine = create_async_engine(db_url)
    async with init_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await init_engine.dispose()

    nvd_route = respx.get(NVD_CVE_API).mock(
        return_value=httpx.Response(200, json=_make_nvd_response())
    )

    before_run = datetime.now(timezone.utc)
    updater = IncrementalUpdater(db_url=db_url)
    await updater.run()

    assert nvd_route.called
    request = nvd_route.calls[0].request
    url_str = str(request.url)

    # The lastModStartDate should be in the URL and be a date ~2 days before now
    assert "lastModStartDate" in url_str

    # Extract the date from URL params
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(url_str)
    params = parse_qs(parsed.query)
    start_date_str = params.get("lastModStartDate", [None])[0]
    assert start_date_str is not None

    start_dt = datetime.strptime(start_date_str, "%Y-%m-%dT%H:%M:%S.000").replace(tzinfo=timezone.utc)
    expected_fallback = before_run - timedelta(days=3)  # generous lower bound
    assert start_dt >= expected_fallback
    # And it should not be in the future
    assert start_dt <= before_run
