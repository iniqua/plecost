import pytest
import sqlite3
from plecost.database.store import CVEStore


@pytest.fixture
def db_path(tmp_path):
    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    conn.execute("""CREATE TABLE vulnerabilities (
        id TEXT PRIMARY KEY, software_type TEXT, software_slug TEXT,
        version_from TEXT, version_to TEXT, cvss_score REAL,
        severity TEXT, title TEXT, description TEXT, remediation TEXT,
        "references" TEXT, has_exploit INTEGER, published_at TEXT
    )""")
    conn.execute("""INSERT INTO vulnerabilities VALUES
        ('CVE-2024-1234','plugin','woocommerce','8.0.0','8.3.0',
         8.1,'HIGH','SQL Injection in WooCommerce','SQL injection via order param',
         'Update to 8.3.1','["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"]',1,'2024-01-15')
    """)
    conn.commit()
    conn.close()
    return str(db)


def test_find_plugin_vulnerabilities(db_path):
    store = CVEStore(db_path)
    vulns = store.find("plugin", "woocommerce", "8.1.0")
    assert len(vulns) == 1
    assert vulns[0].cve_id == "CVE-2024-1234"
    assert vulns[0].severity == "HIGH"
    assert vulns[0].has_exploit is True


def test_no_vulns_for_patched_version(db_path):
    store = CVEStore(db_path)
    vulns = store.find("plugin", "woocommerce", "8.4.0")
    assert len(vulns) == 0


def test_no_vulns_for_different_plugin(db_path):
    store = CVEStore(db_path)
    vulns = store.find("plugin", "akismet", "5.0.0")
    assert len(vulns) == 0
