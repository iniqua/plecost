"""Tests for plecost.database.local_patches — local CVE mapping corrections.

AC-1: apply_local_corrections() removes (CVE-2024-1733, wordfence)
AC-2: apply_local_corrections() adds (CVE-2024-1733, word-replacer-ultra) with correct data
AC-3: apply_local_corrections() removes (CVE-2022-1546, woocommerce-products-filter)
AC-4: apply_local_corrections() is idempotent (safe to run multiple times)
AC-5: _delete_by_cve_slug does not raise if the record does not exist
"""
from __future__ import annotations

import json
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from plecost.database.local_patches import apply_local_corrections, _delete_by_cve_slug
from plecost.database.models import Base, NormalizedVuln


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def sf() -> AsyncGenerator[async_sessionmaker[AsyncSession], None]:
    """In-memory SQLite session factory — isolated per test."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    yield factory
    await engine.dispose()


def _make_vuln(cve_id: str, slug: str, **kwargs: object) -> NormalizedVuln:
    """Helper to build a minimal NormalizedVuln row."""
    return NormalizedVuln(
        cve_id=cve_id,
        software_type=kwargs.get("software_type", "plugin"),  # type: ignore[arg-type]
        slug=slug,
        cpe_vendor=kwargs.get("cpe_vendor", "test_vendor"),  # type: ignore[arg-type]
        cpe_product=kwargs.get("cpe_product", "test_product"),  # type: ignore[arg-type]
        match_confidence=kwargs.get("match_confidence", 0.85),  # type: ignore[arg-type]
        cvss_score=kwargs.get("cvss_score", 5.0),  # type: ignore[arg-type]
        severity=kwargs.get("severity", "MEDIUM"),  # type: ignore[arg-type]
        title=kwargs.get("title", f"{slug}: {cve_id}"),  # type: ignore[arg-type]
        description=kwargs.get("description", "test description"),  # type: ignore[arg-type]
        remediation=kwargs.get("remediation", "Update plugin."),  # type: ignore[arg-type]
        references_json="[]",
        has_exploit=False,
        published_at="2024-01-01T00:00:00",
    )


# ---------------------------------------------------------------------------
# AC-1: apply_local_corrections removes (CVE-2024-1733, wordfence)
# ---------------------------------------------------------------------------

async def test_correction_removes_wrong_wordfence_mapping(sf: async_sessionmaker[AsyncSession]) -> None:
    """AC-1: The wrong (CVE-2024-1733, wordfence) mapping is deleted."""
    # Seed: insert the wrong row that existed in the upstream DB
    async with sf() as session:
        session.add(_make_vuln("CVE-2024-1733", "wordfence"))
        await session.commit()

    await apply_local_corrections(sf)

    async with sf() as session:
        result = await session.execute(
            select(NormalizedVuln).where(
                NormalizedVuln.cve_id == "CVE-2024-1733",
                NormalizedVuln.slug == "wordfence",
            )
        )
        row = result.scalar_one_or_none()

    assert row is None, "Wrong (CVE-2024-1733, wordfence) mapping must be removed"


# ---------------------------------------------------------------------------
# AC-2: apply_local_corrections adds (CVE-2024-1733, word-replacer-ultra)
# ---------------------------------------------------------------------------

async def test_correction_adds_correct_word_replacer_mapping(sf: async_sessionmaker[AsyncSession]) -> None:
    """AC-2: The correct (CVE-2024-1733, word-replacer-ultra) mapping is inserted."""
    await apply_local_corrections(sf)

    async with sf() as session:
        result = await session.execute(
            select(NormalizedVuln).where(
                NormalizedVuln.cve_id == "CVE-2024-1733",
                NormalizedVuln.slug == "word-replacer-ultra",
            )
        )
        row = result.scalar_one_or_none()

    assert row is not None, "Correct (CVE-2024-1733, word-replacer-ultra) mapping must be present"
    assert row.cpe_vendor == "charlestsmith"
    assert row.cpe_product == "word_replacer_pro"
    assert row.cvss_score == 5.3
    assert row.severity == "MEDIUM"
    assert row.match_confidence == 1.0
    refs = json.loads(row.references_json)
    assert any("word-replacer-ultra" in r for r in refs), "References must mention word-replacer-ultra"


# ---------------------------------------------------------------------------
# AC-3: apply_local_corrections removes (CVE-2022-1546, woocommerce-products-filter)
# ---------------------------------------------------------------------------

async def test_correction_removes_wrong_woocommerce_filter_mapping(sf: async_sessionmaker[AsyncSession]) -> None:
    """AC-3: The wrong (CVE-2022-1546, woocommerce-products-filter) mapping is deleted."""
    async with sf() as session:
        session.add(_make_vuln("CVE-2022-1546", "woocommerce-products-filter"))
        await session.commit()

    await apply_local_corrections(sf)

    async with sf() as session:
        result = await session.execute(
            select(NormalizedVuln).where(
                NormalizedVuln.cve_id == "CVE-2022-1546",
                NormalizedVuln.slug == "woocommerce-products-filter",
            )
        )
        row = result.scalar_one_or_none()

    assert row is None, "Wrong (CVE-2022-1546, woocommerce-products-filter) mapping must be removed"


# ---------------------------------------------------------------------------
# AC-4: apply_local_corrections is idempotent
# ---------------------------------------------------------------------------

async def test_corrections_are_idempotent(sf: async_sessionmaker[AsyncSession]) -> None:
    """AC-4: Running apply_local_corrections twice does not raise or corrupt data."""
    # Seed wrong rows
    async with sf() as session:
        session.add(_make_vuln("CVE-2024-1733", "wordfence"))
        session.add(_make_vuln("CVE-2022-1546", "woocommerce-products-filter"))
        await session.commit()

    # First run
    upserted1, deleted1 = await apply_local_corrections(sf)

    # Second run — must not fail and counts must be consistent
    upserted2, deleted2 = await apply_local_corrections(sf)

    # The upsert count is always 1 (one upsert action in corrections.json)
    assert upserted2 == 1

    # After the second run the correct row must still be there
    async with sf() as session:
        result = await session.execute(
            select(NormalizedVuln).where(
                NormalizedVuln.cve_id == "CVE-2024-1733",
                NormalizedVuln.slug == "word-replacer-ultra",
            )
        )
        assert result.scalar_one_or_none() is not None, "Correct mapping must survive second run"

    # Wrong rows must still be absent
    async with sf() as session:
        result = await session.execute(
            select(NormalizedVuln).where(
                NormalizedVuln.cve_id == "CVE-2024-1733",
                NormalizedVuln.slug == "wordfence",
            )
        )
        assert result.scalar_one_or_none() is None

        result2 = await session.execute(
            select(NormalizedVuln).where(
                NormalizedVuln.cve_id == "CVE-2022-1546",
                NormalizedVuln.slug == "woocommerce-products-filter",
            )
        )
        assert result2.scalar_one_or_none() is None


# ---------------------------------------------------------------------------
# AC-5: _delete_by_cve_slug does not fail when row does not exist
# ---------------------------------------------------------------------------

async def test_delete_nonexistent_cve_slug_is_safe(sf: async_sessionmaker[AsyncSession]) -> None:
    """AC-5: Deleting a non-existent (cve_id, slug) pair returns 0 and does not raise."""
    async with sf() as session:
        count = await _delete_by_cve_slug(session, "CVE-9999-9999", "no-such-plugin")
        await session.commit()

    assert count == 0, "Deleting non-existent row must return rowcount 0"
