import pytest
from unittest.mock import AsyncMock, MagicMock

from plecost.engine.context import ScanContext
from plecost.models import ScanOptions, Plugin
from plecost.modules.cves import CVEsModule
from plecost.database.store import CVEStore, VulnerabilityRecord


def _make_vuln(cve_id: str = "CVE-2024-1234") -> VulnerabilityRecord:
    return VulnerabilityRecord(
        cve_id=cve_id,
        software_type="plugin",
        software_slug="woocommerce",
        version_start_incl="8.0.0",
        version_start_excl=None,
        version_end_incl="8.3.0",
        version_end_excl=None,
        cvss_score=8.1,
        severity="HIGH",
        title="SQL Injection in WooCommerce",
        description="desc",
        remediation="Update to 8.3.1",
        references=[],
        has_exploit=True,
        published_at="2024-01-15",
        match_confidence=1.0,
    )


@pytest.fixture
def ctx_with_plugins():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    ctx.wordpress_version = "6.4.2"
    ctx.add_plugin(Plugin("woocommerce", "8.1.0", None, "/wp-content/plugins/woocommerce/"))
    return ctx


@pytest.mark.asyncio
async def test_finds_plugin_cve(ctx_with_plugins):
    store = MagicMock(spec=CVEStore)
    store.find = AsyncMock(return_value=[_make_vuln()])
    mod = CVEsModule(store)
    await mod.run(ctx_with_plugins, None)
    cve_findings = [
        f for f in ctx_with_plugins.findings
        if "CVE-2024-1234" in f.description or "CVE-2024-1234" in f.id
    ]
    assert len(cve_findings) >= 1
    assert any(f.severity.value == "HIGH" for f in ctx_with_plugins.findings)


@pytest.mark.asyncio
async def test_no_findings_when_not_wordpress():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = False
    store = MagicMock(spec=CVEStore)
    store.find = AsyncMock(return_value=[])
    mod = CVEsModule(store)
    await mod.run(ctx, None)
    assert len(ctx.findings) == 0
    store.find.assert_not_called()
