import pytest
from unittest.mock import AsyncMock, MagicMock

from plecost.engine.context import ScanContext
from plecost.models import ScanOptions, Plugin, Theme, Severity
from plecost.modules.cves import CVEsModule
from plecost.database.store import CVEStore, VulnerabilityRecord


def _make_vuln(
    cve_id: str = "CVE-2024-1234",
    software_type: str = "plugin",
    software_slug: str = "woocommerce",
    severity: str = "HIGH",
    title: str = "SQL Injection in WooCommerce",
) -> VulnerabilityRecord:
    return VulnerabilityRecord(
        cve_id=cve_id,
        software_type=software_type,
        software_slug=software_slug,
        version_start_incl="8.0.0",
        version_start_excl=None,
        version_end_incl="8.3.0",
        version_end_excl=None,
        cvss_score=8.1,
        severity=severity,
        title=title,
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


async def test_finds_plugin_cve(ctx_with_plugins):
    """AC-20: CVEsModule emits a finding with correct id/severity/title and populates plugin.vulns."""
    plugin_vuln = _make_vuln("CVE-2024-1234")

    def _find_side_effect(stype, slug, version, rejected_ids=None):
        if stype == "plugin" and slug == "woocommerce":
            return [plugin_vuln]
        return []

    store = MagicMock(spec=CVEStore)
    store.get_rejected_ids = AsyncMock(return_value=set())
    store.find = AsyncMock(side_effect=_find_side_effect)
    store.find_all_by_slug = AsyncMock(return_value=[plugin_vuln])
    mod = CVEsModule(store)
    await mod.run(ctx_with_plugins, None)

    # 1. Finding was emitted with correct id format and severity mapping
    cve_findings = [f for f in ctx_with_plugins.findings if f.id == "PC-CVE-CVE-2024-1234"]
    assert len(cve_findings) == 1
    finding = cve_findings[0]
    assert finding.severity == Severity.HIGH
    assert "CVE-2024-1234" in finding.title

    # 2. plugin.vulns must be populated from find_all_by_slug result
    plugin = ctx_with_plugins.plugins[0]
    assert len(plugin.vulns) == 1, "plugin.vulns must be populated from find_all_by_slug result"
    assert plugin.vulns[0].cve_id == "CVE-2024-1234"


@pytest.mark.asyncio
async def test_no_findings_when_not_wordpress():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = False
    store = MagicMock(spec=CVEStore)
    store.get_rejected_ids = AsyncMock(return_value=set())
    store.find = AsyncMock(return_value=[])
    mod = CVEsModule(store)
    await mod.run(ctx, None)
    assert len(ctx.findings) == 0
    store.find.assert_not_called()


# ---------------------------------------------------------------------------
# AC-21 (G-040): Theme CVE detection path
# ---------------------------------------------------------------------------

async def test_finds_theme_cve():
    """AC-21: CVEsModule detects theme CVEs, emits exactly one finding per CVE,
    and populates theme.vulns."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    ctx.wordpress_version = "6.4.2"
    ctx.themes.append(Theme("twentytwentyfour", "1.0.0", None, "/wp-content/themes/twentytwentyfour/"))

    theme_vuln = _make_vuln(
        cve_id="CVE-2024-THEME",
        software_type="theme",
        software_slug="twentytwentyfour",
    )

    store = MagicMock(spec=CVEStore)
    store.get_rejected_ids = AsyncMock(return_value=set())
    store.find = AsyncMock(side_effect=lambda stype, slug, version, rejected_ids=None: (
        [theme_vuln] if stype == "theme" else []
    ))
    store.find_all_by_slug = AsyncMock(side_effect=lambda stype, slug, rejected_ids=None: (
        [theme_vuln] if stype == "theme" else []
    ))
    mod = CVEsModule(store)
    await mod.run(ctx, None)

    # Exactly one finding for this CVE, with correct id and severity
    cve_findings = [f for f in ctx.findings if f.id == "PC-CVE-CVE-2024-THEME"]
    assert len(cve_findings) == 1, "Exactly one PC-CVE-CVE-2024-THEME finding expected"
    assert cve_findings[0].severity == Severity.HIGH

    # theme.vulns must be populated
    theme = ctx.themes[0]
    assert len(theme.vulns) == 1, "theme.vulns must be populated from find_all_by_slug"
    assert theme.vulns[0].cve_id == "CVE-2024-THEME"


# ---------------------------------------------------------------------------
# AC-22 (G-041): plugin with version=None skips store.find()
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_plugin_without_version_skips_cve_check():
    """AC-22: plugin with version=None does not trigger store.find() for that plugin."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    ctx.wordpress_version = None
    ctx.add_plugin(Plugin("akismet", None, None, "/wp-content/plugins/akismet/"))

    store = MagicMock(spec=CVEStore)
    store.get_rejected_ids = AsyncMock(return_value=set())
    store.find = AsyncMock(return_value=[])
    store.find_all_by_slug = AsyncMock(return_value=[])
    mod = CVEsModule(store)
    await mod.run(ctx, None)

    # find() must not have been called with ("plugin", "akismet", ...)
    for c in store.find.call_args_list:
        args = c.args
        assert not (len(args) >= 2 and args[0] == "plugin" and args[1] == "akismet"), (
            "store.find() must not be called for a plugin with version=None"
        )
