import json
import pytest
from datetime import datetime
from plecost.reporters.json_reporter import JSONReporter
from plecost.models import ScanResult, ScanSummary, Finding, Severity


@pytest.fixture
def result():
    return ScanResult(
        scan_id="test-123", url="https://example.com",
        timestamp=datetime(2026, 4, 10, 12, 0, 0),
        duration_seconds=5.2, is_wordpress=True, wordpress_version="6.4.2",
        plugins=[], themes=[], users=[], waf_detected="Cloudflare",
        findings=[Finding(
            id="PC-FP-001", remediation_id="REM-FP-001",
            title="Version disclosed", severity=Severity.LOW,
            description="WP 6.4.2 found", evidence={"url": "https://example.com"},
            remediation="Remove meta tag", references=[], cvss_score=None, module="fingerprint"
        )],
        summary=ScanSummary(low=1)
    )


def test_json_reporter_creates_valid_json(result, tmp_path):
    path = str(tmp_path / "report.json")
    JSONReporter(result).save(path)
    data = json.loads(open(path).read())
    assert data["url"] == "https://example.com"
    assert data["wordpress_version"] == "6.4.2"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["id"] == "PC-FP-001"
    assert data["summary"]["low"] == 1


def test_json_reporter_to_string(result):
    output = JSONReporter(result).to_string()
    data = json.loads(output)
    assert data["waf_detected"] == "Cloudflare"
