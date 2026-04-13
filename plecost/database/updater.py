from __future__ import annotations
import asyncio
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from plecost.database.engine import make_engine, make_session_factory
from plecost.database.models import Base, DbMetadata, NormalizedVuln, PluginsWordlist, ThemesWordlist

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WP_PLUGINS_API = "https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[per_page]=250&request[page]={page}"
WP_THEMES_API = "https://api.wordpress.org/themes/info/1.2/?action=query_themes&request[per_page]=100&request[page]={page}"


def _normalize(s: str) -> str:
    """Normalize for comparison: remove separators, lowercase."""
    return re.sub(r'[-_\s]', '', s).lower()


def _jaro_winkler(s1: str, s2: str) -> float:
    """
    Inline implementation of Jaro-Winkler to avoid an extra dependency.
    Returns similarity between 0.0 and 1.0.
    """
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0
    match_dist = max(len1, len2) // 2 - 1
    if match_dist < 0:
        match_dist = 0
    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0
    transpositions = 0
    for i in range(len1):
        start = max(0, i - match_dist)
        end = min(i + match_dist + 1, len2)
        for j in range(start, end):
            if s2_matches[j] or s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break
    if matches == 0:
        return 0.0
    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1
    jaro = (matches / len1 + matches / len2 + (matches - transpositions / 2) / matches) / 3
    # Winkler prefix bonus (unchanged)
    prefix = 0
    for i in range(min(4, len1, len2)):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break
    return jaro + prefix * 0.1 * (1 - jaro)


def _parse_cpe(cpe_uri: str) -> tuple[str, str, str]:
    """
    Parse CPE 2.3: cpe:2.3:a:{vendor}:{product}:{version}:..:{target_sw}:..
    Returns (vendor, product, target_sw). target_sw is at position 10 (0-indexed from 'cpe').
    """
    parts = cpe_uri.split(':')
    if len(parts) < 13:
        return '', '', ''
    vendor = parts[3]
    product = parts[4]
    target_sw = parts[10]
    return vendor, product, target_sw


def _is_wp_plugin_cpe(target_sw: str) -> bool:
    return target_sw.lower() in ('wordpress', 'wordpress_plugin', '*')


def _match_slug(cpe_product: str, known_slugs: list[str], threshold: float = 0.82) -> tuple[str | None, float]:
    """
    Try to map cpe_product to a known slug.
    1. Normalized exact match
    2. Jaro-Winkler fuzzy match
    Returns (slug, confidence) or (None, 0.0)
    """
    norm_product = _normalize(cpe_product)
    # Exact match
    for slug in known_slugs:
        if _normalize(slug) == norm_product:
            return slug, 1.0
    # Fuzzy
    best_slug = None
    best_score = 0.0
    for slug in known_slugs:
        score = _jaro_winkler(norm_product, _normalize(slug))
        if score > best_score:
            best_score = score
            best_slug = slug
    if best_score >= threshold and best_slug:
        return best_slug, best_score
    return None, 0.0


async def _upsert_vuln_free(session: AsyncSession, vuln: NormalizedVuln) -> None:
    from sqlalchemy import select
    existing = (await session.execute(
        select(NormalizedVuln).where(
            NormalizedVuln.cve_id == vuln.cve_id,
            NormalizedVuln.slug == vuln.slug,
        )
    )).scalar_one_or_none()
    if existing:
        if vuln.match_confidence > existing.match_confidence:
            for attr in ["cpe_vendor", "cpe_product", "match_confidence",
                         "version_start_incl", "version_start_excl",
                         "version_end_incl", "version_end_excl",
                         "cvss_score", "severity", "description", "references_json"]:
                setattr(existing, attr, getattr(vuln, attr))
    else:
        session.add(vuln)


async def process_nvd_batch(
    vulns: list[Any], sf: async_sessionmaker[AsyncSession],
    plugin_slugs: list[str], theme_slugs: list[str],
    collected: list[dict[str, Any]] | None = None,
) -> None:
    """Free reusable function called from both updater and incremental.

    If *collected* is provided, each processed vulnerability record (as a dict
    matching the daily-patch JSON schema) is appended to it in addition to
    being persisted to the database.
    """
    async with sf() as session:
        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                ""
            )
            metrics = cve.get("metrics", {})
            cvss_score: float | None = None
            severity = "MEDIUM"
            if v31 := metrics.get("cvssMetricV31"):
                cvss_score = v31[0]["cvssData"]["baseScore"]
                severity = v31[0]["cvssData"]["baseSeverity"]
            elif v30 := metrics.get("cvssMetricV30"):
                cvss_score = v30[0]["cvssData"]["baseScore"]
                severity = v30[0]["cvssData"]["baseSeverity"]

            refs_list = [r2["url"] for r2 in cve.get("references", [])]
            refs = json.dumps(refs_list)
            published = cve.get("published", "")
            # Normalise published to a date-only string for the patch format
            published_date = published[:10] if published else ""

            # Extraer CPEs de configurations
            found_any = False
            configurations = cve.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if not cpe_match.get("vulnerable", False):
                            continue
                        cpe_uri = cpe_match.get("criteria", "")
                        vendor, product, target_sw = _parse_cpe(cpe_uri)
                        if not product:
                            continue

                        v_start_i = cpe_match.get("versionStartIncluding")
                        v_start_e = cpe_match.get("versionStartExcluding")
                        v_end_i = cpe_match.get("versionEndIncluding")
                        v_end_e = cpe_match.get("versionEndExcluding")

                        # WordPress Core: CPE product="wordpress", vendor="wordpress" (unambiguous)
                        if vendor.lower() == "wordpress" and product.lower() == "wordpress":
                            vuln_obj = NormalizedVuln(
                                cve_id=cve_id,
                                software_type="core",
                                slug="wordpress",
                                cpe_vendor=vendor,
                                cpe_product=product,
                                match_confidence=1.0,
                                version_start_incl=v_start_i,
                                version_start_excl=v_start_e,
                                version_end_incl=v_end_i,
                                version_end_excl=v_end_e,
                                cvss_score=cvss_score,
                                severity=severity,
                                title=f"WordPress Core: {cve_id}",
                                description=desc,
                                remediation="Update WordPress to the latest version.",
                                references_json=refs,
                                published_at=published,
                            )
                            await _upsert_vuln_free(session, vuln_obj)
                            if collected is not None:
                                collected.append({
                                    "cve_id": cve_id,
                                    "software_type": "core",
                                    "slug": "wordpress",
                                    "cpe_vendor": vendor,
                                    "cpe_product": product,
                                    "match_confidence": 1.0,
                                    "version_start_incl": v_start_i,
                                    "version_start_excl": v_start_e,
                                    "version_end_incl": v_end_i,
                                    "version_end_excl": v_end_e,
                                    "cvss_score": cvss_score,
                                    "severity": severity,
                                    "title": f"WordPress Core: {cve_id}",
                                    "description": desc,
                                    "remediation": "Update WordPress to the latest version.",
                                    "references": refs_list,
                                    "has_exploit": False,
                                    "published_at": published_date,
                                })
                            found_any = True
                            continue

                        # Plugins/Themes: filter by target_sw=wordpress
                        if not _is_wp_plugin_cpe(target_sw):
                            continue

                        # Try to map to a known plugin slug
                        slug, conf = _match_slug(product, plugin_slugs)
                        sw_type = "plugin"
                        if not slug:
                            slug, conf = _match_slug(product, theme_slugs)
                            sw_type = "theme"
                        if not slug:
                            slug = product
                            conf = 0.5
                            sw_type = "plugin"

                        vuln_obj = NormalizedVuln(
                            cve_id=cve_id,
                            software_type=sw_type,
                            slug=slug,
                            cpe_vendor=vendor,
                            cpe_product=product,
                            match_confidence=conf,
                            version_start_incl=v_start_i,
                            version_start_excl=v_start_e,
                            version_end_incl=v_end_i,
                            version_end_excl=v_end_e,
                            cvss_score=cvss_score,
                            severity=severity,
                            title=f"{product}: {cve_id}",
                            description=desc,
                            remediation="Update the plugin/theme to the latest version.",
                            references_json=refs,
                            published_at=published,
                        )
                        await _upsert_vuln_free(session, vuln_obj)
                        if collected is not None:
                            collected.append({
                                "cve_id": cve_id,
                                "software_type": sw_type,
                                "slug": slug,
                                "cpe_vendor": vendor,
                                "cpe_product": product,
                                "match_confidence": conf,
                                "version_start_incl": v_start_i,
                                "version_start_excl": v_start_e,
                                "version_end_incl": v_end_i,
                                "version_end_excl": v_end_e,
                                "cvss_score": cvss_score,
                                "severity": severity,
                                "title": f"{product}: {cve_id}",
                                "description": desc,
                                "remediation": "Update the plugin/theme to the latest version.",
                                "references": refs_list,
                                "has_exploit": False,
                                "published_at": published_date,
                            })
                        found_any = True

            # If there were no useful configurations, skip
            if not found_any and desc:
                pass  # Skip CVEs without useful CPEs

        await session.commit()


class DatabaseUpdater:
    def __init__(self, db_url: str, years_back: int = 5, nvd_api_key: str | None = None) -> None:
        self._db_url = db_url
        self._years_back = years_back
        self._api_key = nvd_api_key

    async def run(self) -> None:
        engine = make_engine(self._db_url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        sf = make_session_factory(engine)

        headers: dict[str, str] = {"User-Agent": "Plecost/4.0 (security research; github.com/Plecost/plecost)"}
        if self._api_key:
            headers["apiKey"] = self._api_key

        start_date = (datetime.now(timezone.utc) - timedelta(days=self._years_back * 365)).strftime("%Y-%m-%dT00:00:00.000")

        async with httpx.AsyncClient(timeout=60, headers=headers) as client:
            # Download wordlists first (slugs needed for matching)
            plugin_slugs = await self._fetch_plugin_slugs(client, sf)
            theme_slugs = await self._fetch_theme_slugs(client, sf)
            # Download and process CVEs from NVD
            await self._fetch_nvd(client, sf, plugin_slugs, theme_slugs, start_date)

        # Save synchronization metadata
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
        async with sf() as session:
            existing = await session.get(DbMetadata, "last_nvd_sync")
            if existing:
                existing.value = now_str
            else:
                session.add(DbMetadata(key="last_nvd_sync", value=now_str))
            start_date_meta = await session.get(DbMetadata, "initial_sync_from")
            if not start_date_meta:
                session.add(DbMetadata(key="initial_sync_from", value=start_date))
            await session.commit()

        await engine.dispose()

    async def _fetch_plugin_slugs(
        self, client: httpx.AsyncClient, sf: async_sessionmaker[AsyncSession]
    ) -> list[str]:
        slugs: list[str] = []
        for page in range(1, 20):  # up to 5000 plugins
            try:
                r = await client.get(WP_PLUGINS_API.format(page=page), timeout=30)
                data = r.json()
                plugins = data.get("plugins", {})
                if not plugins:
                    break
                page_slugs = list(plugins.keys()) if isinstance(plugins, dict) else [p.get("slug", "") for p in plugins]
                slugs.extend(s for s in page_slugs if s)
                if len(page_slugs) < 250:
                    break
            except Exception:
                break
        # Save to DB
        async with sf() as session:
            for slug in slugs:
                existing = await session.get(PluginsWordlist, slug)
                if not existing:
                    session.add(PluginsWordlist(slug=slug))
            await session.commit()
        return slugs

    async def _fetch_theme_slugs(
        self, client: httpx.AsyncClient, sf: async_sessionmaker[AsyncSession]
    ) -> list[str]:
        slugs: list[str] = []
        for page in range(1, 10):
            try:
                r = await client.get(WP_THEMES_API.format(page=page), timeout=30)
                data = r.json()
                themes = data.get("themes", [])
                if not themes:
                    break
                page_slugs = [t.get("slug", "") for t in themes if isinstance(t, dict)]
                slugs.extend(s for s in page_slugs if s)
                if len(themes) < 100:
                    break
            except Exception:
                break
        async with sf() as session:
            for slug in slugs:
                existing = await session.get(ThemesWordlist, slug)
                if not existing:
                    session.add(ThemesWordlist(slug=slug))
            await session.commit()
        return slugs

    async def _fetch_nvd(
        self, client: httpx.AsyncClient, sf: async_sessionmaker[AsyncSession], plugin_slugs: list[str], theme_slugs: list[str],
        start_date: str | None = None,
    ) -> None:
        if start_date is None:
            start_date = (datetime.now(timezone.utc) - timedelta(days=self._years_back * 365)).strftime("%Y-%m-%dT00:00:00.000")
        end_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT23:59:59.999")
        start_index = 0
        results_per_page = 2000

        while True:
            params: dict[str, str | int] = {
                "keywordSearch": "wordpress",
                "pubStartDate": start_date,
                "pubEndDate": end_date,
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
            }
            try:
                r = await client.get(NVD_CVE_API, params=params, timeout=60)
                data = r.json()
            except Exception:
                break

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            await process_nvd_batch(vulns, sf, plugin_slugs, theme_slugs)

            total = data.get("totalResults", 0)
            start_index += len(vulns)
            if start_index >= total:
                break
            # NVD rate limiting: 6 req/30s without API key, 0.6s with key
            await asyncio.sleep(6 if not self._api_key else 0.6)
