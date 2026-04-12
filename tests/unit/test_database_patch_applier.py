from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from plecost.database.models import Base, NormalizedVuln, RejectedCve
from plecost.database.patch_applier import apply_patch, get_last_patch_date

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def sf() -> AsyncGenerator[async_sessionmaker[AsyncSession], None]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    yield factory
    await engine.dispose()


# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

VALID_PATCH: dict[str, Any] = {
    "date": "2026-04-11",
    "source": "nvd",
    "upsert": [
        {
            "cve_id": "CVE-2024-1234",
            "software_type": "plugin",
            "slug": "woocommerce",
            "cpe_vendor": "automattic",
            "cpe_product": "woocommerce",
            "match_confidence": 1.0,
            "version_start_incl": None,
            "version_start_excl": None,
            "version_end_incl": None,
            "version_end_excl": "8.5.0",
            "cvss_score": 7.5,
            "severity": "HIGH",
            "title": "WooCommerce XSS",
            "description": "Cross-site scripting vulnerability",
            "remediation": "Update to 8.5.0+",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
            "has_exploit": False,
            "published_at": "2024-03-15",
        }
    ],
    "delete": [],
}

SECOND_UPSERT: dict[str, Any] = {
    "cve_id": "CVE-2024-5678",
    "software_type": "theme",
    "slug": "twentytwentyfour",
    "cpe_vendor": "wordpress",
    "cpe_product": "twentytwentyfour",
    "match_confidence": 0.9,
    "version_start_incl": None,
    "version_start_excl": None,
    "version_end_incl": None,
    "version_end_excl": "1.2.0",
    "cvss_score": 5.3,
    "severity": "MEDIUM",
    "title": "TwentyTwentyFour CSRF",
    "description": "Cross-site request forgery",
    "remediation": "Update to 1.2.0+",
    "references": [],
    "has_exploit": False,
    "published_at": "2024-06-01",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_apply_patch_upserts_new_records(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """A patch with 2 upserts inserts 2 records into normalized_vulns."""
    patch: dict[str, Any] = {**VALID_PATCH, "upsert": [VALID_PATCH["upsert"][0], SECOND_UPSERT]}
    await apply_patch(patch, sf)

    async with sf() as session:
        result = await session.execute(select(NormalizedVuln))
        rows = result.scalars().all()

    assert len(rows) == 2
    cve_ids = {r.cve_id for r in rows}
    assert cve_ids == {"CVE-2024-1234", "CVE-2024-5678"}


async def test_apply_patch_returns_correct_counts(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """apply_patch returns (2, 0) for a patch with 2 upserts and 0 deletes."""
    patch: dict[str, Any] = {**VALID_PATCH, "upsert": [VALID_PATCH["upsert"][0], SECOND_UPSERT]}
    upserted, deleted = await apply_patch(patch, sf)

    assert upserted == 2
    assert deleted == 0


async def test_apply_patch_updates_existing_record(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """Applying the same CVE twice updates the record instead of duplicating it."""
    await apply_patch(VALID_PATCH, sf)

    first_upsert: dict[str, Any] = VALID_PATCH["upsert"][0]
    updated_patch: dict[str, Any] = {
        **VALID_PATCH,
        "upsert": [
            {
                **first_upsert,
                "title": "WooCommerce XSS — Updated",
                "cvss_score": 9.0,
                "severity": "CRITICAL",
            }
        ],
    }
    await apply_patch(updated_patch, sf)

    async with sf() as session:
        result = await session.execute(select(NormalizedVuln))
        rows = result.scalars().all()

    assert len(rows) == 1
    assert rows[0].title == "WooCommerce XSS — Updated"
    assert rows[0].cvss_score == 9.0
    assert rows[0].severity == "CRITICAL"


async def test_apply_patch_idempotent(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """Applying the same patch twice produces the same number of rows (no duplicates)."""
    await apply_patch(VALID_PATCH, sf)
    await apply_patch(VALID_PATCH, sf)

    async with sf() as session:
        result = await session.execute(select(NormalizedVuln))
        rows = result.scalars().all()

    assert len(rows) == 1


async def test_apply_patch_deletes_move_to_rejected(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """A delete operation moves the CVE to rejected_cves and removes it from normalized_vulns."""
    await apply_patch(VALID_PATCH, sf)

    delete_patch: dict[str, Any] = {
        "date": "2026-04-12",
        "source": "nvd",
        "upsert": [],
        "delete": ["CVE-2024-1234"],
    }
    await apply_patch(delete_patch, sf)

    async with sf() as session:
        vuln_result = await session.execute(
            select(NormalizedVuln).where(NormalizedVuln.cve_id == "CVE-2024-1234")
        )
        vuln_row = vuln_result.scalar_one_or_none()
        rejected = await session.get(RejectedCve, "CVE-2024-1234")

    assert vuln_row is None
    assert rejected is not None
    assert rejected.cve_id == "CVE-2024-1234"
    assert rejected.reason == "deleted"


async def test_apply_patch_delete_nonexistent_cve(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """Deleting a CVE that does not exist does not raise and inserts into rejected_cves."""
    delete_patch: dict[str, Any] = {
        "date": "2026-04-12",
        "source": "nvd",
        "upsert": [],
        "delete": ["CVE-9999-9999"],
    }
    upserted, deleted = await apply_patch(delete_patch, sf)

    assert deleted == 1

    async with sf() as session:
        rejected = await session.get(RejectedCve, "CVE-9999-9999")

    assert rejected is not None
    assert rejected.cve_id == "CVE-9999-9999"


async def test_validate_patch_missing_cve_id(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """_validate_patch raises ValueError when cve_id is missing."""
    bad_patch: dict[str, Any] = {
        "date": "2026-04-11",
        "upsert": [
            {
                "software_type": "plugin",
                "slug": "woocommerce",
            }
        ],
        "delete": [],
    }
    with pytest.raises(ValueError, match="cve_id"):
        await apply_patch(bad_patch, sf)


async def test_validate_patch_missing_software_type(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """_validate_patch raises ValueError when software_type is missing."""
    bad_patch: dict[str, Any] = {
        "date": "2026-04-11",
        "upsert": [
            {
                "cve_id": "CVE-2024-1234",
                "slug": "woocommerce",
            }
        ],
        "delete": [],
    }
    with pytest.raises(ValueError, match="software_type"):
        await apply_patch(bad_patch, sf)


async def test_validate_patch_missing_slug(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """_validate_patch raises ValueError when slug is missing."""
    bad_patch: dict[str, Any] = {
        "date": "2026-04-11",
        "upsert": [
            {
                "cve_id": "CVE-2024-1234",
                "software_type": "plugin",
            }
        ],
        "delete": [],
    }
    with pytest.raises(ValueError, match="slug"):
        await apply_patch(bad_patch, sf)


async def test_update_last_patch_date_only_advances(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """If the new patch date is earlier than the stored date, the stored date is not updated."""
    newer_patch: dict[str, Any] = {**VALID_PATCH, "date": "2026-04-11"}
    await apply_patch(newer_patch, sf)

    older_patch: dict[str, Any] = {**VALID_PATCH, "date": "2026-01-01", "upsert": []}
    await apply_patch(older_patch, sf)

    last_date = await get_last_patch_date(sf)
    assert last_date == "2026-04-11"


async def test_get_last_patch_date_none_on_empty_db(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """get_last_patch_date returns None when no patches have been applied."""
    last_date = await get_last_patch_date(sf)
    assert last_date is None


async def test_get_last_patch_date_after_apply(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """get_last_patch_date returns the date of the last applied patch."""
    await apply_patch(VALID_PATCH, sf)

    last_date = await get_last_patch_date(sf)
    assert last_date == "2026-04-11"


async def test_apply_patch_references_stored_as_json(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """References list is stored as a JSON string in references_json column."""
    await apply_patch(VALID_PATCH, sf)

    async with sf() as session:
        result = await session.execute(
            select(NormalizedVuln).where(NormalizedVuln.cve_id == "CVE-2024-1234")
        )
        row = result.scalar_one()

    parsed = json.loads(row.references_json)
    assert isinstance(parsed, list)
    assert parsed == ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"]
