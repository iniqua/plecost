from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import cast
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from plecost.database.models import NormalizedVuln, RejectedCve, DbMetadata

METADATA_KEY_LAST_PATCH = "last_patch_date"


async def apply_patch(patch_data: dict[str, object], sf: async_sessionmaker[AsyncSession]) -> tuple[int, int]:
    """
    Apply a single JSON patch to the local database.
    Returns (upserted_count, deleted_count).
    Two-phase: validate first, then single transaction.
    """
    upserts = cast(list[dict[str, object]], patch_data.get("upsert", []))
    deletes = cast(list[str], patch_data.get("delete", []))
    patch_date = cast(str, patch_data.get("date", ""))

    # Phase 1: validate (before touching DB)
    _validate_patch(upserts)

    # Phase 2: single transaction
    async with sf() as session:
        upserted = await _apply_upserts(session, upserts)
        deleted = await _apply_deletes(session, deletes, patch_date)
        if patch_date:
            await _update_last_patch_date(session, patch_date)
        await session.commit()

    return upserted, deleted


def _validate_patch(upserts: list[dict[str, object]]) -> None:
    """Validate upsert records have required fields. Raises ValueError on failure."""
    required = {"cve_id", "software_type", "slug"}
    for i, record in enumerate(upserts):
        missing = required - set(record.keys())
        if missing:
            raise ValueError(f"Patch record {i} missing fields: {missing}")


async def _apply_upserts(session: AsyncSession, upserts: list[dict[str, object]]) -> int:
    """Upsert CVE records. Remote is source of truth (overwrites local)."""
    count = 0
    for record in upserts:
        # Find existing by (cve_id, slug) — portable across SQLite and PostgreSQL
        result = await session.execute(
            select(NormalizedVuln).where(
                NormalizedVuln.cve_id == record["cve_id"],
                NormalizedVuln.slug == record["slug"],
            )
        )
        existing = result.scalar_one_or_none()

        values = dict(
            cve_id=record["cve_id"],
            software_type=record["software_type"],
            slug=record["slug"],
            cpe_vendor=record.get("cpe_vendor", ""),
            cpe_product=record.get("cpe_product", ""),
            match_confidence=record.get("match_confidence", 1.0),
            version_start_incl=record.get("version_start_incl"),
            version_start_excl=record.get("version_start_excl"),
            version_end_incl=record.get("version_end_incl"),
            version_end_excl=record.get("version_end_excl"),
            cvss_score=record.get("cvss_score"),
            severity=record.get("severity", "MEDIUM"),
            title=record.get("title", ""),
            description=record.get("description", ""),
            remediation=record.get("remediation", ""),
            references_json=json.dumps(record.get("references", [])),
            has_exploit=record.get("has_exploit", False),
            published_at=record.get("published_at", ""),
        )

        if existing:
            for k, v in values.items():
                setattr(existing, k, v)
        else:
            session.add(NormalizedVuln(**values))
        count += 1
    return count


async def _apply_deletes(session: AsyncSession, cve_ids: list[str], patch_date: str) -> int:
    """Move deleted CVEs to rejected_cves table instead of physical delete."""
    count = 0
    now = patch_date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for cve_id in cve_ids:
        # Check if already in rejected
        existing = await session.get(RejectedCve, cve_id)
        if not existing:
            session.add(RejectedCve(cve_id=cve_id, reason="deleted", rejected_at=now))
        # Remove from normalized_vulns
        await session.execute(delete(NormalizedVuln).where(NormalizedVuln.cve_id == cve_id))
        count += 1
    return count


async def _update_last_patch_date(session: AsyncSession, date: str) -> None:
    row = await session.get(DbMetadata, METADATA_KEY_LAST_PATCH)
    if row:
        # Only update if new date is more recent
        if date > row.value:
            row.value = date
    else:
        session.add(DbMetadata(key=METADATA_KEY_LAST_PATCH, value=date))


async def get_last_patch_date(sf: async_sessionmaker[AsyncSession]) -> str | None:
    """Returns the date of the last applied patch, or None if no patches applied yet."""
    async with sf() as session:
        row = await session.get(DbMetadata, METADATA_KEY_LAST_PATCH)
        return str(row.value) if row else None
