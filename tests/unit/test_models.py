import json
from datetime import datetime
from plecost.models import (
    Finding, Severity, ScanResult, ScanOptions,
    Plugin, Theme, User, ScanSummary
)


def test_finding_id_format():
    f = Finding(
        id="PC-FP-001", remediation_id="REM-FP-001",
        title="Test", severity=Severity.HIGH,
        description="desc", evidence={}, remediation="fix",
        references=[], cvss_score=None, module="fingerprint"
    )
    assert f.id.startswith("PC-")
    assert f.remediation_id.startswith("REM-")


def test_scan_result_to_json(tmp_path):
    result = ScanResult(
        scan_id="test-uuid", url="https://example.com",
        timestamp=datetime.now(), duration_seconds=1.5,
        is_wordpress=True, wordpress_version="6.4.2",
        plugins=[], themes=[], users=[], waf_detected=None,
        findings=[], summary=ScanSummary(critical=0, high=0, medium=0, low=0, info=0)
    )
    out = tmp_path / "report.json"
    result.to_json(str(out))
    data = json.loads(out.read_text())
    assert data["url"] == "https://example.com"
    assert data["wordpress_version"] == "6.4.2"


def test_scan_options_defaults():
    opts = ScanOptions(url="https://example.com")
    assert opts.concurrency == 10
    assert opts.timeout == 10
    assert opts.stealth is False
    assert opts.modules is None  # None = all modules
