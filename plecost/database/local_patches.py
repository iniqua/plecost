"""Apply local corrections to known wrong CVE mappings in the upstream database."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from plecost.database.models import NormalizedVuln

logger = logging.getLogger(__name__)

_CORRECTIONS_FILE = Path(__file__).parent / "corrections.json"


async def apply_local_corrections(
    sf: async_sessionmaker[AsyncSession],
) -> tuple[int, int]:
    """Apply known corrections to wrong CVE mappings.

    Loads corrections from corrections.json (bundled with the package) and
    applies them to the database. Safe to run multiple times (idempotent).

    Returns:
        (upserted, deleted): counts of records upserted and deleted.
    """
    corrections = _load_corrections()
    upserted = 0
    deleted = 0
    async with sf() as session:
        for entry in corrections:
            action = entry.get("action")
            if action == "delete_by_cve_slug":
                deleted += await _delete_by_cve_slug(
                    session, entry["cve_id"], entry["slug"]
                )
            elif action == "upsert":
                await _upsert_entry(session, entry)
                upserted += 1
        await session.commit()
    logger.info(
        "Local corrections applied: %d upserted, %d deleted", upserted, deleted
    )
    return upserted, deleted


def _load_corrections() -> list[dict[str, Any]]:
    """Load correction entries from the bundled corrections.json file."""
    try:
        data: dict[str, Any] = json.loads(_CORRECTIONS_FILE.read_text(encoding="utf-8"))
        corrections: list[dict[str, Any]] = data.get("corrections", [])
        return corrections
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to load corrections.json: %s", e)
        return []


async def _delete_by_cve_slug(
    session: AsyncSession, cve_id: str, slug: str
) -> int:
    """Delete a single (cve_id, slug) row. Returns number of rows deleted (0 or 1)."""
    result = await session.execute(
        select(NormalizedVuln).where(
            NormalizedVuln.cve_id == cve_id,
            NormalizedVuln.slug == slug,
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        return 0
    await session.execute(
        delete(NormalizedVuln).where(
            NormalizedVuln.cve_id == cve_id,
            NormalizedVuln.slug == slug,
        )
    )
    return 1


async def _upsert_entry(session: AsyncSession, entry: dict[str, Any]) -> None:
    """Insert or update a NormalizedVuln row from a correction entry."""
    result = await session.execute(
        select(NormalizedVuln).where(
            NormalizedVuln.cve_id == entry["cve_id"],
            NormalizedVuln.slug == entry["slug"],
        )
    )
    existing = result.scalar_one_or_none()
    values: dict[str, Any] = {
        "cve_id": entry["cve_id"],
        "software_type": entry["software_type"],
        "slug": entry["slug"],
        "cpe_vendor": entry.get("cpe_vendor", ""),
        "cpe_product": entry.get("cpe_product", ""),
        "match_confidence": entry.get("match_confidence", 1.0),
        "version_start_incl": entry.get("version_start_incl"),
        "version_start_excl": entry.get("version_start_excl"),
        "version_end_incl": entry.get("version_end_incl"),
        "version_end_excl": entry.get("version_end_excl"),
        "cvss_score": entry.get("cvss_score"),
        "severity": entry.get("severity", "MEDIUM"),
        "title": entry.get("title", ""),
        "description": entry.get("description", ""),
        "remediation": entry.get("remediation", ""),
        "references_json": json.dumps(entry.get("references", [])),
        "has_exploit": entry.get("has_exploit", False),
        "published_at": entry.get("published_at", ""),
    }
    if existing:
        for k, v in values.items():
            setattr(existing, k, v)
    else:
        session.add(NormalizedVuln(**values))
