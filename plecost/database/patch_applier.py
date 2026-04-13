from __future__ import annotations
import json
import logging
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from plecost.database.models import NormalizedVuln, RejectedCve, DbMetadata, MagecartDomain

METADATA_KEY_LAST_PATCH = "last_patch_date"
UPSERT_BATCH_SIZE = 2_000

logger = logging.getLogger(__name__)


async def apply_magecart_patch(
    patch_data: dict[str, Any], sf: async_sessionmaker[AsyncSession]
) -> tuple[int, int]:
    """
    Apply a magecart-domains.json patch to the local database.
    Returns (upserted_count, deleted_count).
    Patch format: {"upserts": [...], "deletes": []}
    """
    upserts: list[dict[str, Any]] = patch_data.get("upserts", [])
    deletes: list[str] = patch_data.get("deletes", [])

    async with sf() as session:
        # Upserts
        upserted = 0
        for record in upserts:
            existing = await session.get(MagecartDomain, record["domain"])
            if existing:
                existing.category = record.get("category", existing.category)
                existing.source = record.get("source", existing.source)
                existing.added_date = record.get("added_date", existing.added_date)
                existing.is_active = record.get("is_active", existing.is_active)
            else:
                session.add(MagecartDomain(
                    domain=record["domain"],
                    category=record.get("category", "magecart"),
                    source=record.get("source", ""),
                    added_date=record.get("added_date", ""),
                    is_active=record.get("is_active", True),
                ))
            upserted += 1

        # Soft-deletes: set is_active=False
        deleted = 0
        for domain in deletes:
            row = await session.get(MagecartDomain, domain)
            if row:
                row.is_active = False
                deleted += 1

        await session.commit()

    logger.info("Magecart patch applied: %d upserted, %d soft-deleted", upserted, deleted)
    return upserted, deleted


async def apply_patch(patch_data: dict[str, Any], sf: async_sessionmaker[AsyncSession]) -> tuple[int, int]:
    """
    Apply a single JSON patch to the local database.
    Returns (upserted_count, deleted_count).
    Two-phase: validate first, then single transaction.
    """
    upserts: list[dict[str, Any]] = patch_data.get("upsert", [])
    deletes: list[str] = patch_data.get("delete", [])
    patch_date: str = patch_data.get("date", "")

    # Phase 1: validate (before touching DB)
    _validate_patch(upserts)

    logger.info(
        "Applying patch date=%s: %d upserts, %d deletes",
        patch_date,
        len(upserts),
        len(deletes),
    )

    # Phase 2: single transaction
    async with sf() as session:
        upserted = await _apply_upserts(session, upserts)
        deleted = await _apply_deletes(session, deletes, patch_date)
        if patch_date:
            await _update_last_patch_date(session, patch_date)
        await session.commit()

    logger.info("Patch applied: %d upserted, %d soft-deleted", upserted, deleted)
    return upserted, deleted


def _validate_patch(upserts: list[dict[str, Any]]) -> None:
    """Validate upsert records have required fields. Raises ValueError on failure."""
    required = {"cve_id", "software_type", "slug"}
    for i, record in enumerate(upserts):
        missing = required - set(record.keys())
        if missing:
            raise ValueError(f"Patch record {i} missing fields: {missing}")


def _build_values(record: dict[str, Any]) -> dict[str, Any]:
    """Build a values dict from a patch record for use in upserts."""
    return dict(
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


async def _apply_upserts(session: AsyncSession, upserts: list[dict[str, Any]]) -> int:
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
        values = _build_values(record)
        if existing:
            for k, v in values.items():
                setattr(existing, k, v)
        else:
            session.add(NormalizedVuln(**values))
        count += 1
        # Flush every UPSERT_BATCH_SIZE to avoid holding too many objects in memory
        if count % UPSERT_BATCH_SIZE == 0:
            logger.debug("Flushed batch at %d records", count)
            await session.flush()
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
