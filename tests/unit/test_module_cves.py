import pytest
import sqlite3
from plecost.engine.context import ScanContext
from plecost.models import ScanOptions, Plugin
from plecost.modules.cves import CVEsModule
from plecost.database.store import CVEStore


@pytest.fixture
def db_path(tmp_path):
    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    conn.execute("""CREATE TABLE vulnerabilities (
        id TEXT, software_type TEXT, software_slug TEXT,
        version_from TEXT, version_to TEXT, cvss_score REAL,
        severity TEXT, title TEXT, description TEXT, remediation TEXT,
        "references" TEXT, has_exploit INTEGER, published_at TEXT
    )""")
    conn.execute("""CREATE TABLE plugins_wordlist (slug TEXT, last_updated TEXT, active_installs INTEGER)""")
    conn.execute("""CREATE TABLE themes_wordlist (slug TEXT, last_updated TEXT)""")
    conn.execute("""INSERT INTO vulnerabilities VALUES
        ('CVE-2024-1234','plugin','woocommerce','8.0.0','8.3.0',
         8.1,'HIGH','SQL Injection','desc','Update to 8.3.1','[]',1,'2024-01-15')
    """)
    conn.commit()
    conn.close()
    return str(db)


@pytest.fixture
def ctx_with_plugins(db_path):
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    ctx.wordpress_version = "6.4.2"
    ctx.add_plugin(Plugin("woocommerce", "8.1.0", None, "/wp-content/plugins/woocommerce/"))
    return ctx, db_path


@pytest.mark.asyncio
async def test_finds_plugin_cve(ctx_with_plugins):
    ctx, db_path = ctx_with_plugins
    store = CVEStore(db_path)
    mod = CVEsModule(store)
    await mod.run(ctx, None)
    cve_findings = [f for f in ctx.findings if "CVE-2024-1234" in f.description or "CVE-2024-1234" in f.id]
    assert len(cve_findings) >= 1
    assert any(f.severity.value == "HIGH" for f in ctx.findings)
