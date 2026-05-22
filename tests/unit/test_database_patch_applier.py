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
    """Deleting a CVE that was never in normalized_vulns is a no-op (AC-6).
    We do NOT add it to rejected_cves to avoid blacklisting CVEs that were
    never actually ingested."""
    delete_patch: dict[str, Any] = {
        "date": "2026-04-12",
        "source": "nvd",
        "upsert": [],
        "delete": ["CVE-9999-9999"],
    }
    upserted, deleted = await apply_patch(delete_patch, sf)

    assert upserted == 0
    assert deleted == 0  # AC-6: CVE not in normalized_vulns → skip

    async with sf() as session:
        rejected = await session.get(RejectedCve, "CVE-9999-9999")

    assert rejected is None  # AC-6: must not appear in rejected_cves either


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


# ---------------------------------------------------------------------------
# New tests — AC-1/AC-27, AC-2/AC-26, AC-3, AC-4, AC-5, AC-23
# ---------------------------------------------------------------------------


async def test_reupsert_after_delete_removes_from_rejected(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """AC-1/AC-27 (G2-028): re-upsert of a deleted CVE removes it from rejected_cves
    and makes it visible again in normalized_vulns."""
    # Step 1: Insert the CVE
    await apply_patch(VALID_PATCH, sf)

    # Step 2: Delete it — moves to rejected_cves
    delete_patch: dict[str, Any] = {
        "date": "2026-04-12",
        "source": "nvd",
        "upsert": [],
        "delete": ["CVE-2024-1234"],
    }
    await apply_patch(delete_patch, sf)

    # Confirm it is in rejected_cves
    async with sf() as session:
        rejected_before = await session.get(RejectedCve, "CVE-2024-1234")
    assert rejected_before is not None, "CVE should be in rejected_cves after delete"

    # Step 3: Re-upsert the same CVE
    re_upsert_patch: dict[str, Any] = {
        "date": "2026-04-13",
        "source": "nvd",
        "upsert": [VALID_PATCH["upsert"][0]],
        "delete": [],
    }
    await apply_patch(re_upsert_patch, sf)

    # Verify rejected_cves no longer contains the cve_id
    async with sf() as session:
        rejected_after = await session.get(RejectedCve, "CVE-2024-1234")
        vuln_result = await session.execute(
            select(NormalizedVuln).where(NormalizedVuln.cve_id == "CVE-2024-1234")
        )
        vuln_row = vuln_result.scalar_one_or_none()

    assert rejected_after is None, "CVE must be removed from rejected_cves after re-upsert"
    assert vuln_row is not None, "CVE must appear in normalized_vulns after re-upsert"


async def test_upsert_wins_over_delete_in_same_patch(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """AC-2/AC-26 (G2-027): when the same cve_id appears in both upsert[] and delete[]
    of the same patch, the upsert wins and the CVE must NOT be added to rejected_cves."""
    patch: dict[str, Any] = {
        "date": "2026-04-11",
        "source": "nvd",
        "upsert": [VALID_PATCH["upsert"][0]],
        "delete": ["CVE-2024-1234"],  # same cve_id as the upsert above
    }
    await apply_patch(patch, sf)

    async with sf() as session:
        vuln_result = await session.execute(
            select(NormalizedVuln).where(NormalizedVuln.cve_id == "CVE-2024-1234")
        )
        vuln_row = vuln_result.scalar_one_or_none()
        rejected = await session.get(RejectedCve, "CVE-2024-1234")

    assert vuln_row is not None, "Upsert wins: CVE must appear in normalized_vulns"
    assert rejected is None, "Upsert wins: CVE must NOT appear in rejected_cves"


async def test_non_iso_date_does_not_update_last_patch_date(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """AC-3: a non-ISO date in a patch does not overwrite the stored last_patch_date."""
    # Apply a valid dated patch first
    valid_dated_patch: dict[str, Any] = {**VALID_PATCH, "date": "2026-04-11"}
    await apply_patch(valid_dated_patch, sf)

    # Apply a patch with an invalid date string
    bad_date_patch: dict[str, Any] = {
        "date": "not-a-date",
        "source": "nvd",
        "upsert": [],
        "delete": [],
    }
    await apply_patch(bad_date_patch, sf)

    last_date = await get_last_patch_date(sf)
    assert last_date == "2026-04-11", (
        f"last_patch_date must remain '2026-04-11', got {last_date!r}"
    )


async def test_duplicate_cve_slug_in_batch_last_wins(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """AC-4: duplicate (cve_id, slug) in the same upsert batch — last record wins."""
    first_record: dict[str, Any] = {**VALID_PATCH["upsert"][0], "title": "First Title"}
    second_record: dict[str, Any] = {**VALID_PATCH["upsert"][0], "title": "Second Title"}

    patch: dict[str, Any] = {
        "date": "2026-04-11",
        "source": "nvd",
        "upsert": [first_record, second_record],
        "delete": [],
    }
    await apply_patch(patch, sf)

    async with sf() as session:
        result = await session.execute(select(NormalizedVuln))
        rows = result.scalars().all()

    assert len(rows) == 1, "Duplicate (cve_id, slug) must produce only one row"
    assert rows[0].title == "Second Title", "Last record in the batch must win"


async def test_validate_patch_empty_slug_raises(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """AC-5a: a patch record with an empty slug raises ValueError."""
    bad_patch: dict[str, Any] = {
        "date": "2026-04-11",
        "upsert": [
            {
                "cve_id": "CVE-2024-1234",
                "software_type": "plugin",
                "slug": "",
            }
        ],
        "delete": [],
    }
    with pytest.raises(ValueError, match="slug"):
        await apply_patch(bad_patch, sf)


async def test_validate_patch_invalid_severity_raises(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """AC-5b: a patch record with an invalid severity value raises ValueError."""
    bad_patch: dict[str, Any] = {
        "date": "2026-04-11",
        "upsert": [
            {
                **VALID_PATCH["upsert"][0],
                "severity": "CATASTROPHIC",  # not a valid severity
            }
        ],
        "delete": [],
    }
    with pytest.raises(ValueError, match="severity"):
        await apply_patch(bad_patch, sf)


async def test_apply_deletes_multi_slug_removes_all(
    sf: async_sessionmaker[AsyncSession],
) -> None:
    """AC-23 (G-043): deleting a CVE that maps to multiple slugs removes all slug rows
    from normalized_vulns and records one entry in rejected_cves."""
    # Insert same cve_id with two different slugs
    multi_slug_patch: dict[str, Any] = {
        "date": "2026-04-11",
        "source": "nvd",
        "upsert": [
            {**VALID_PATCH["upsert"][0], "slug": "plugin-a"},
            {**VALID_PATCH["upsert"][0], "slug": "plugin-b"},
        ],
        "delete": [],
    }
    await apply_patch(multi_slug_patch, sf)

    # Confirm both rows exist
    async with sf() as session:
        result = await session.execute(
            select(NormalizedVuln).where(NormalizedVuln.cve_id == "CVE-2024-1234")
        )
        rows_before = result.scalars().all()
    assert len(rows_before) == 2, "Both slug rows must be present before delete"

    # Delete the CVE
    delete_patch: dict[str, Any] = {
        "date": "2026-04-12",
        "source": "nvd",
        "upsert": [],
        "delete": ["CVE-2024-1234"],
    }
    await apply_patch(delete_patch, sf)

    async with sf() as session:
        result = await session.execute(
            select(NormalizedVuln).where(NormalizedVuln.cve_id == "CVE-2024-1234")
        )
        rows_after = result.scalars().all()
        rejected = await session.get(RejectedCve, "CVE-2024-1234")

    assert len(rows_after) == 0, "All slug rows must be removed from normalized_vulns after delete"
    assert rejected is not None, "cve_id must appear in rejected_cves after delete"
    assert rejected.reason == "deleted"
