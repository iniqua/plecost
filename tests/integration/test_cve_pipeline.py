"""
Integration tests for the full CVE detection pipeline.

AC-24 (G2-025): CVE present in DB for a detected plugin → scan emits PC-CVE-* finding.
AC-25 (G2-026): CVE in rejected_cves → scan does NOT emit the corresponding finding.
"""
from __future__ import annotations

import pytest
import httpx
import respx
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from plecost.database.models import Base, NormalizedVuln, RejectedCve
from plecost.models import ScanOptions
from plecost.scanner import Scanner


# ---------------------------------------------------------------------------
# HTML fixture — WordPress site with woocommerce 8.1.0 in the page source
# ---------------------------------------------------------------------------

WP_PAGE_WITH_WOOCOMMERCE = """\
<html>
<head>
<meta name="generator" content="WordPress 6.4.2" />
<link rel="stylesheet"
      href="/wp-content/plugins/woocommerce/assets/css/woocommerce.css?ver=8.1.0" />
</head>
<body><p>Shop page</p></body>
</html>
"""

WOOCOMMERCE_README = """\
=== WooCommerce ===
Contributors: automattic
Stable tag: 8.1.0
Requires at least: 6.0
"""


# ---------------------------------------------------------------------------
# Fixture: temporary CVE database with one known vulnerability
# ---------------------------------------------------------------------------

@pytest.fixture
async def cve_db_path(tmp_path):
    """
    Create a real SQLite DB at tmp_path/test.db containing:
      - NormalizedVuln for woocommerce 8.0.0–8.3.0 (CVE-2024-INTEG)
    Yields the db_url string to pass as ScanOptions(db_url=...).
    """
    db_path = tmp_path / "test.db"
    db_url = f"sqlite+aiosqlite:///{db_path}"
    engine = create_async_engine(db_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    async with sf() as session:
        session.add(NormalizedVuln(
            cve_id="CVE-2024-INTEG",
            software_type="plugin",
            slug="woocommerce",
            cpe_vendor="woocommerce",
            cpe_product="woocommerce",
            match_confidence=1.0,
            version_start_incl="8.0.0",
            version_end_excl="8.3.0",
            cvss_score=9.0,
            severity="CRITICAL",
            title="Integration Test CVE — WooCommerce RCE",
            description="Remote code execution vulnerability",
            remediation="Update WooCommerce to 8.3.0 or later",
            references_json='[]',
            has_exploit=False,
            published_at="2024-01-01",
        ))
        await session.commit()
    await engine.dispose()
    yield db_url


@pytest.fixture
async def cve_db_with_rejected(tmp_path):
    """
    Same DB as cve_db_path but CVE-2024-INTEG is also in rejected_cves,
    simulating a CVE that was later retracted.
    """
    db_path = tmp_path / "rejected.db"
    db_url = f"sqlite+aiosqlite:///{db_path}"
    engine = create_async_engine(db_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    async with sf() as session:
        session.add(NormalizedVuln(
            cve_id="CVE-2024-INTEG",
            software_type="plugin",
            slug="woocommerce",
            cpe_vendor="woocommerce",
            cpe_product="woocommerce",
            match_confidence=1.0,
            version_start_incl="8.0.0",
            version_end_excl="8.3.0",
            cvss_score=9.0,
            severity="CRITICAL",
            title="Integration Test CVE — WooCommerce RCE",
            description="Remote code execution vulnerability",
            remediation="Update WooCommerce to 8.3.0 or later",
            references_json='[]',
            has_exploit=False,
            published_at="2024-01-01",
        ))
        session.add(RejectedCve(
            cve_id="CVE-2024-INTEG",
            reason="deleted",
            rejected_at="2024-06-01",
        ))
        await session.commit()
    await engine.dispose()
    yield db_url


# ---------------------------------------------------------------------------
# Helper: set up respx mocks for a minimal WordPress site
# ---------------------------------------------------------------------------

def _mock_wordpress_site(base_url: str = "https://wp.test") -> None:
    """Register respx routes for a WordPress site exposing woocommerce 8.1.0."""
    respx.get(f"{base_url}/").mock(
        return_value=httpx.Response(200, text=WP_PAGE_WITH_WOOCOMMERCE)
    )
    respx.get(f"{base_url}/wp-content/plugins/woocommerce/readme.txt").mock(
        return_value=httpx.Response(200, text=WOOCOMMERCE_README)
    )
    # Catch-all for every other path
    respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))


# ---------------------------------------------------------------------------
# AC-24: full pipeline — CVE in DB → scan → PC-CVE-* finding emitted
# ---------------------------------------------------------------------------

@respx.mock
async def test_cve_pipeline_emits_finding(cve_db_path):
    """AC-24 (G2-025): A CVE present in the local DB for a detected plugin is reported
    as a PC-CVE-CVE-2024-INTEG finding in the final ScanResult."""
    _mock_wordpress_site("https://wp.test")

    opts = ScanOptions(
        url="https://wp.test",
        modules=["fingerprint", "plugins", "cves"],
        db_url=cve_db_path,
    )
    scanner = Scanner(opts)
    result = await scanner.run()

    cve_findings = [f for f in result.findings if f.id == "PC-CVE-CVE-2024-INTEG"]
    assert len(cve_findings) >= 1, (
        f"Expected PC-CVE-CVE-2024-INTEG finding. "
        f"All finding ids: {[f.id for f in result.findings]}"
    )
    finding = cve_findings[0]
    # Verify the finding carries meaningful data from the DB record
    assert "CVE-2024-INTEG" in finding.title
    from plecost.models import Severity
    assert finding.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# AC-25: rejected_cves suppresses finding in scan
# ---------------------------------------------------------------------------

@respx.mock
async def test_rejected_cve_suppresses_finding(cve_db_with_rejected):
    """AC-25 (G2-026): A CVE that is in rejected_cves must NOT appear in the scan findings,
    even when the plugin version falls within the affected range."""
    _mock_wordpress_site("https://wp.test")

    opts = ScanOptions(
        url="https://wp.test",
        modules=["fingerprint", "plugins", "cves"],
        db_url=cve_db_with_rejected,
    )
    scanner = Scanner(opts)
    result = await scanner.run()

    cve_findings = [f for f in result.findings if f.id == "PC-CVE-CVE-2024-INTEG"]
    assert len(cve_findings) == 0, (
        "Rejected CVE must not produce a finding in the scan output"
    )
