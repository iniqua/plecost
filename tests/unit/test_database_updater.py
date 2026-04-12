from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from plecost.database.models import Base, NormalizedVuln
from plecost.database.updater import (
    process_nvd_batch,
    _normalize,
    _jaro_winkler,
    _match_slug,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_cve(
    cve_id: str,
    vendor: str,
    product: str,
    target_sw: str = "*",
    version_end_excl: str | None = None,
) -> dict:
    """Build a minimal NVD-format CVE item."""
    cpe_uri = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:{target_sw}:*:*"
    cpe_match: dict = {
        "vulnerable": True,
        "criteria": cpe_uri,
    }
    if version_end_excl:
        cpe_match["versionEndExcluding"] = version_end_excl

    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": f"Test description for {cve_id}"}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                        }
                    }
                ]
            },
            "references": [],
            "published": "2024-01-01T00:00:00.000",
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [cpe_match],
                        }
                    ]
                }
            ],
        }
    }


@pytest.fixture
async def db_sf():
    """In-memory SQLite session factory with all tables created."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    yield sf
    await engine.dispose()


# ---------------------------------------------------------------------------
# Tests for process_nvd_batch
# ---------------------------------------------------------------------------

async def test_process_nvd_batch_core_vuln(db_sf):
    """CVE with vendor=wordpress product=wordpress → software_type='core'."""
    cve = _make_cve("CVE-2024-0001", vendor="wordpress", product="wordpress")
    await process_nvd_batch([cve], db_sf, [], [])

    async with db_sf() as session:
        results = (await session.execute(select(NormalizedVuln))).scalars().all()

    assert len(results) == 1
    vuln = results[0]
    assert vuln.cve_id == "CVE-2024-0001"
    assert vuln.software_type == "core"
    assert vuln.slug == "wordpress"
    assert vuln.match_confidence == 1.0


async def test_process_nvd_batch_plugin_vuln(db_sf):
    """CVE with target_sw=wordpress + product matching known slug → software_type='plugin'."""
    cve = _make_cve("CVE-2024-0002", vendor="woocommerce", product="woocommerce", target_sw="wordpress")
    await process_nvd_batch([cve], db_sf, ["woocommerce"], [])

    async with db_sf() as session:
        results = (await session.execute(select(NormalizedVuln))).scalars().all()

    assert len(results) == 1
    vuln = results[0]
    assert vuln.cve_id == "CVE-2024-0002"
    assert vuln.software_type == "plugin"
    assert vuln.slug == "woocommerce"
    assert vuln.match_confidence == 1.0


async def test_process_nvd_batch_skips_non_wordpress(db_sf):
    """CVE with unrelated CPE (no wordpress target_sw) → nothing stored."""
    cve = _make_cve("CVE-2024-0003", vendor="apache", product="httpd", target_sw="linux")
    await process_nvd_batch([cve], db_sf, [], [])

    async with db_sf() as session:
        results = (await session.execute(select(NormalizedVuln))).scalars().all()

    assert len(results) == 0


async def test_upsert_updates_on_higher_confidence(db_sf):
    """Upsert same CVE+slug with higher confidence → confidence updated."""
    # First insert with low confidence (simulate fuzzy match)
    cve_low = _make_cve("CVE-2024-0004", vendor="acmecorp", product="woocomerce", target_sw="wordpress")
    # Manually insert with low confidence
    async with db_sf() as session:
        session.add(NormalizedVuln(
            cve_id="CVE-2024-0004",
            software_type="plugin",
            slug="woocommerce",
            cpe_vendor="acmecorp",
            cpe_product="woocomerce",
            match_confidence=0.7,
            cvss_score=7.5,
            severity="HIGH",
            title="Test",
            description="Test desc",
            remediation="Update",
            references_json="[]",
            published_at="2024-01-01",
        ))
        await session.commit()

    # Now upsert with exact match (confidence 1.0)
    cve_high = _make_cve("CVE-2024-0004", vendor="woocommerce", product="woocommerce", target_sw="wordpress")
    await process_nvd_batch([cve_high], db_sf, ["woocommerce"], [])

    async with db_sf() as session:
        results = (await session.execute(select(NormalizedVuln))).scalars().all()

    # Should only have one row (upserted)
    assert len(results) == 1
    assert results[0].match_confidence == 1.0


# ---------------------------------------------------------------------------
# Tests for utility functions
# ---------------------------------------------------------------------------

def test_normalize_function():
    assert _normalize("hello-world_test") == "helloworldtest"
    assert _normalize("Hello World") == "helloworld"
    assert _normalize("foo_bar-baz") == "foobarbaz"


def test_jaro_winkler_exact():
    assert _jaro_winkler("abc", "abc") == 1.0


def test_jaro_winkler_different():
    score = _jaro_winkler("abc", "xyz")
    assert 0.0 <= score < 1.0


def test_jaro_winkler_empty():
    assert _jaro_winkler("", "abc") == 0.0
    assert _jaro_winkler("abc", "") == 0.0


def test_match_slug_exact():
    slug, confidence = _match_slug("woocommerce", ["woocommerce", "akismet"])
    assert slug == "woocommerce"
    assert confidence == 1.0


def test_match_slug_no_match():
    slug, confidence = _match_slug("completelydifferent", ["woocommerce", "akismet"])
    # Either no match or low confidence
    if slug is not None:
        assert confidence < 0.82
    else:
        assert confidence == 0.0


def test_match_slug_normalized_exact():
    """Product with separators should still match slug exactly after normalization."""
    slug, confidence = _match_slug("woo-commerce", ["woocommerce"])
    assert slug == "woocommerce"
    assert confidence == 1.0
