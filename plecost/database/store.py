from __future__ import annotations
import json
from dataclasses import dataclass

from packaging.version import Version, InvalidVersion
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from plecost.database.models import NormalizedVuln, PluginsWordlist, RejectedCve, ThemesWordlist


@dataclass
class VulnerabilityRecord:
    cve_id: str
    software_type: str
    software_slug: str
    version_start_incl: str | None
    version_start_excl: str | None
    version_end_incl: str | None
    version_end_excl: str | None
    cvss_score: float | None
    severity: str
    title: str
    description: str
    remediation: str
    references: list[str]
    has_exploit: bool
    published_at: str
    match_confidence: float


class CVEStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sf = session_factory

    @classmethod
    def from_url(cls, db_url: str) -> "CVEStore":
        import os
        from plecost.database.engine import make_engine, make_session_factory
        if db_url.startswith("sqlite"):
            # Extract path from sqlite+aiosqlite:///path or sqlite:///path
            path = db_url.split("///", 1)[-1]
            if path and not os.path.exists(path):
                raise FileNotFoundError(
                    f"CVE database not found at {path}. Run 'plecost update-db' to download it."
                )
        engine = make_engine(db_url)
        return cls(make_session_factory(engine))

    async def find(
        self, software_type: str, slug: str, installed_version: str
    ) -> list[VulnerabilityRecord]:
        async with self._sf() as session:
            # Get rejected CVE IDs to filter them out
            rejected_result = await session.execute(
                select(RejectedCve.cve_id)
            )
            rejected_ids = set(rejected_result.scalars().all())

            result = await session.execute(
                select(NormalizedVuln).where(
                    NormalizedVuln.software_type == software_type,
                    NormalizedVuln.slug == slug,
                )
            )
            rows = result.scalars().all()

        try:
            iv = Version(installed_version)
        except InvalidVersion:
            return []

        return [
            self._to_record(row) for row in rows
            if self._is_affected(iv, row) and row.cve_id not in rejected_ids
        ]

    def _is_affected(self, iv: Version, row: NormalizedVuln) -> bool:
        try:
            start_i = Version(row.version_start_incl) if row.version_start_incl else None
            start_e = Version(row.version_start_excl) if row.version_start_excl else None
            end_i = Version(row.version_end_incl) if row.version_end_incl else None
            end_e = Version(row.version_end_excl) if row.version_end_excl else None

            if start_i and iv < start_i:
                return False
            if start_e and iv <= start_e:
                return False
            if end_i and iv > end_i:
                return False
            if end_e and iv >= end_e:
                return False
            # If no ranges are defined, assume affected (rare but possible)
            return True
        except InvalidVersion:
            return False

    def _to_record(self, row: NormalizedVuln) -> VulnerabilityRecord:
        return VulnerabilityRecord(
            cve_id=row.cve_id,
            software_type=row.software_type,
            software_slug=row.slug,
            version_start_incl=row.version_start_incl,
            version_start_excl=row.version_start_excl,
            version_end_incl=row.version_end_incl,
            version_end_excl=row.version_end_excl,
            cvss_score=row.cvss_score,
            severity=row.severity,
            title=row.title,
            description=row.description,
            remediation=row.remediation,
            references=json.loads(row.references_json or "[]"),
            has_exploit=row.has_exploit,
            published_at=row.published_at,
            match_confidence=row.match_confidence,
        )

    async def find_all_by_slug(
        self, software_type: str, slug: str
    ) -> list[VulnerabilityRecord]:
        """Return all known CVEs for a slug, regardless of installed version."""
        async with self._sf() as session:
            rejected_result = await session.execute(select(RejectedCve.cve_id))
            rejected_ids = set(rejected_result.scalars().all())

            conditions = [
                NormalizedVuln.software_type == software_type,
                NormalizedVuln.slug == slug,
            ]
            if rejected_ids:
                conditions.append(NormalizedVuln.cve_id.not_in(rejected_ids))

            result = await session.execute(select(NormalizedVuln).where(*conditions))
            rows = result.scalars().all()

        return [self._to_record(row) for row in rows]

    async def get_plugins_wordlist(self) -> list[str]:
        async with self._sf() as session:
            result = await session.execute(select(PluginsWordlist.slug))
            return list(result.scalars().all())

    async def get_themes_wordlist(self) -> list[str]:
        async with self._sf() as session:
            result = await session.execute(select(ThemesWordlist.slug))
            return list(result.scalars().all())
