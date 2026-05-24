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

    # AC-2: upsert wins over delete when same cve_id appears in both arrays
    upserted_ids = {r["cve_id"] for r in upserts}

    # Phase 2: single transaction
    async with sf() as session:
        upserted = await _apply_upserts(session, upserts)
        deleted = await _apply_deletes(session, deletes, patch_date, upserted_ids)
        if patch_date:
            await _update_last_patch_date(session, patch_date)
        # AC-4: commit only if something was processed or the upserts list was empty
        # (a patch with only deletes or only a date update still needs to commit)
        if upserted > 0 or not upserts:
            await session.commit()

    logger.info("Patch applied: %d upserted, %d soft-deleted", upserted, deleted)
    return upserted, deleted


def _validate_patch(upserts: list[dict[str, Any]]) -> None:
    """Validate upsert records have required fields. Raises ValueError on failure."""
    required = {"cve_id", "software_type", "slug"}
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    for i, record in enumerate(upserts):
        missing = required - set(record.keys())
        if missing:
            raise ValueError(f"Patch record {i} missing fields: {missing}")
        # AC-5: reject empty slug
        if record.get("slug", None) == "":
            raise ValueError(f"Patch record {i} has empty slug")
        # AC-5: validate severity if present
        severity = record.get("severity")
        if severity is not None and severity not in valid_severities:
            raise ValueError(
                f"Patch record {i} has invalid severity {severity!r}; "
                f"must be one of {sorted(valid_severities)}"
            )


def _build_values(record: dict[str, Any]) -> dict[str, Any]:
    """Build a values dict from a patch record for use in upserts."""
    # AC-5: coerce None → False for has_exploit; None → [] for references
    has_exploit = record.get("has_exploit")
    if has_exploit is None:
        has_exploit = False
    references = record.get("references")
    if references is None:
        references = []
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
        references_json=json.dumps(references),
        has_exploit=has_exploit,
        published_at=record.get("published_at", ""),
    )


async def _apply_upserts(session: AsyncSession, upserts: list[dict[str, Any]]) -> int:
    """Upsert CVE records. Remote is source of truth (overwrites local)."""
    # AC-4: deduplicate by (cve_id, slug) — last record in the batch wins
    deduped: dict[tuple[str, str], dict[str, Any]] = {}
    for record in upserts:
        deduped[(record["cve_id"], record["slug"])] = record
    deduped_records = list(deduped.values())

    count = 0
    failed = 0
    for record in deduped_records:
        # AC-1: remove from rejected_cves before reinserting into normalized_vulns
        await session.execute(
            delete(RejectedCve).where(RejectedCve.cve_id == record["cve_id"])
        )

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
            # AC-1/AC-2: protect each periodic flush with a SAVEPOINT so a
            # constraint violation or data-truncation error only rolls back
            # the current batch, not the entire session.
            async with session.begin_nested() as sp:
                try:
                    await session.flush()
                except Exception as exc:
                    await sp.rollback()
                    # AC-3: subtract the records that were lost in this batch
                    failed += UPSERT_BATCH_SIZE
                    logger.warning(
                        "Batch flush failed at %d records: %s — batch rolled back, continuing",
                        count,
                        exc,
                    )
    # AC-3: return only the count of records that were successfully staged
    return count - failed


async def _apply_deletes(
    session: AsyncSession,
    cve_ids: list[str],
    patch_date: str,
    upserted_ids: set[str] | None = None,
) -> int:
    """Move deleted CVEs to rejected_cves table instead of physical delete."""
    count = 0
    now = patch_date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    skip = upserted_ids or set()
    for cve_id in cve_ids:
        # AC-2: skip cve_ids that were also upserted in this patch (upsert wins)
        if cve_id in skip:
            continue
        # AC-6: only add to rejected_cves if the cve_id currently exists in normalized_vulns
        # Use a minimal existence query (loads only cve_id column, not full ORM object)
        in_vulns = await session.execute(
            select(NormalizedVuln.cve_id).where(NormalizedVuln.cve_id == cve_id).limit(1)
        )
        if in_vulns.scalar_one_or_none() is None:
            continue
        # Check if already in rejected
        existing = await session.get(RejectedCve, cve_id)
        if not existing:
            session.add(RejectedCve(cve_id=cve_id, reason="deleted", rejected_at=now))
        # Remove from normalized_vulns
        await session.execute(delete(NormalizedVuln).where(NormalizedVuln.cve_id == cve_id))
        count += 1
    return count


async def _update_last_patch_date(session: AsyncSession, date: str) -> None:
    # AC-3: validate ISO 8601 format (YYYY-MM-DD) before comparing/storing
    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        logger.warning("_update_last_patch_date: invalid date %r — skipping update", date)
        return
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
