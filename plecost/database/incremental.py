from __future__ import annotations
import asyncio
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from plecost.database.engine import make_engine, make_session_factory
from plecost.database.models import Base, DbMetadata, PluginsWordlist, ThemesWordlist
from plecost.database.updater import process_nvd_batch

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
METADATA_KEY_LAST_SYNC = "last_nvd_sync"


class IncrementalUpdater:
    """
    Aplica solo los CVEs modificados/publicados desde la última sincronización.
    Requiere una DB existente con db_metadata.last_nvd_sync.
    """

    def __init__(self, db_url: str, nvd_api_key: str | None = None) -> None:
        self._db_url = db_url
        self._api_key = nvd_api_key

    async def run(self) -> int:
        """Devuelve el número de CVEs procesados."""
        engine = make_engine(self._db_url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        sf = make_session_factory(engine)

        last_sync = await self._get_last_sync(sf)
        now = datetime.now(timezone.utc)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%S.000")

        headers: dict[str, str] = {
            "User-Agent": "Plecost/4.0 (security research; github.com/iniqua/plecost)"
        }
        if self._api_key:
            headers["apiKey"] = self._api_key

        # Obtener slugs conocidos para fuzzy matching
        plugin_slugs, theme_slugs = await self._get_slugs(sf)

        total = 0
        async with httpx.AsyncClient(timeout=60, headers=headers) as client:
            total = await self._fetch_modified(
                client, sf, last_sync, now_str, plugin_slugs, theme_slugs
            )

        # Actualizar last_sync
        await self._set_last_sync(sf, now_str)
        await engine.dispose()
        return total

    async def _get_last_sync(self, sf: async_sessionmaker) -> str:  # type: ignore[type-arg]
        async with sf() as session:
            row = await session.get(DbMetadata, METADATA_KEY_LAST_SYNC)
            if row:
                return row.value
            # Si no hay last_sync, usar hace 2 días como fallback seguro
            fallback = datetime.now(timezone.utc) - timedelta(days=2)
            return fallback.strftime("%Y-%m-%dT%H:%M:%S.000")

    async def _set_last_sync(self, sf: async_sessionmaker, value: str) -> None:  # type: ignore[type-arg]
        async with sf() as session:
            row = await session.get(DbMetadata, METADATA_KEY_LAST_SYNC)
            if row:
                row.value = value
            else:
                session.add(DbMetadata(key=METADATA_KEY_LAST_SYNC, value=value))
            await session.commit()

    async def _get_slugs(self, sf: async_sessionmaker) -> tuple[list[str], list[str]]:  # type: ignore[type-arg]
        async with sf() as session:
            plugins = (await session.execute(select(PluginsWordlist.slug))).scalars().all()
            themes = (await session.execute(select(ThemesWordlist.slug))).scalars().all()
        return list(plugins), list(themes)

    async def _fetch_modified(
        self,
        client: httpx.AsyncClient,
        sf: async_sessionmaker,  # type: ignore[type-arg]
        last_sync: str,
        end_date: str,
        plugin_slugs: list[str],
        theme_slugs: list[str],
    ) -> int:
        start_index = 0
        total_processed = 0

        while True:
            params: dict[str, str | int] = {
                "keywordSearch": "wordpress",
                "lastModStartDate": last_sync,
                "lastModEndDate": end_date,
                "resultsPerPage": 2000,
                "startIndex": start_index,
            }
            try:
                r = await client.get(NVD_CVE_API, params=params, timeout=60)
                r.raise_for_status()
                data = r.json()
            except Exception:
                break

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            await process_nvd_batch(vulns, sf, plugin_slugs, theme_slugs)
            total_processed += len(vulns)

            total = data.get("totalResults", 0)
            start_index += len(vulns)
            if start_index >= total:
                break

            # Rate limiting: 5 req/30s sin API key, 50/30s con key
            await asyncio.sleep(6 if not self._api_key else 0.6)

        return total_processed
