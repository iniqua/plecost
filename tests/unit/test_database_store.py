import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from plecost.database.models import Base, NormalizedVuln
from plecost.database.store import CVEStore


@pytest.fixture
async def store(tmp_path):
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    engine = create_async_engine(db_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    # Insert test data
    async with sf() as session:
        session.add(NormalizedVuln(
            cve_id="CVE-2024-1234",
            software_type="plugin",
            slug="woocommerce",
            cpe_vendor="woocommerce",
            cpe_product="woocommerce",
            match_confidence=1.0,
            version_start_incl="8.0.0",
            version_end_incl="8.3.0",
            cvss_score=8.1,
            severity="HIGH",
            title="SQL Injection in WooCommerce",
            description="SQL injection via order param",
            remediation="Update to 8.3.1",
            references_json='["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"]',
            has_exploit=True,
            published_at="2024-01-15",
        ))
        await session.commit()
    return CVEStore(sf)


@pytest.mark.asyncio
async def test_find_plugin_vulnerabilities(store):
    vulns = await store.find("plugin", "woocommerce", "8.1.0")
    assert len(vulns) == 1
    assert vulns[0].cve_id == "CVE-2024-1234"
    assert vulns[0].severity == "HIGH"
    assert vulns[0].has_exploit is True


@pytest.mark.asyncio
async def test_no_vulns_for_patched_version(store):
    vulns = await store.find("plugin", "woocommerce", "8.4.0")
    assert len(vulns) == 0


@pytest.mark.asyncio
async def test_no_vulns_for_different_plugin(store):
    vulns = await store.find("plugin", "akismet", "5.0.0")
    assert len(vulns) == 0
