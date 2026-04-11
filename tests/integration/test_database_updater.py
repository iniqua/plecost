import pytest
import respx
import httpx
from pathlib import Path
from plecost.database.updater import DatabaseUpdater


NVD_RESPONSE = {
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2024-9999",
            "descriptions": [{"lang": "en", "value": "SQL injection in WooCommerce"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}]},
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-9999"}],
            "published": "2024-01-01T00:00:00.000",
        }
    }],
    "totalResults": 1,
}


@pytest.mark.asyncio
async def test_updater_creates_database(tmp_path):
    db_path = str(tmp_path / "plecost.db")
    async with respx.mock:
        respx.route(url__regex=r".*nvd\.nist\.gov.*").mock(
            return_value=httpx.Response(200, json=NVD_RESPONSE)
        )
        respx.route(url__regex=r".*wordpress\.org.*plugins.*").mock(
            return_value=httpx.Response(200, json={"plugins": {"woocommerce": {}, "akismet": {}}})
        )
        updater = DatabaseUpdater(db_url=f"sqlite+aiosqlite:///{db_path}")
        await updater.run()
    assert Path(db_path).exists()
