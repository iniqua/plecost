"""
Schema contract tests for JSON output format.
These tests ensure the JSON output structure doesn't change unexpectedly
between versions (golden/snapshot testing for the output schema).
"""
import json
from datetime import datetime, timezone
from plecost.models import (
    ScanResult, ScanSummary, Finding, Severity,
)
from plecost.reporters.json_reporter import JSONReporter


def _make_minimal_result() -> ScanResult:
    """Build the minimal valid ScanResult for schema testing."""
    return ScanResult(
        scan_id="test-scan-001",
        url="https://example.com",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        duration_seconds=1.0,
        is_wordpress=True,
        wordpress_version="6.4.2",
        plugins=[],
        themes=[],
        users=[],
        waf_detected=None,
        findings=[],
        summary=ScanSummary(critical=0, high=0, medium=0, low=0, info=0),
        blocked=False,
        woocommerce=None,
        wp_ecommerce=None,
    )


def _to_dict(result: ScanResult) -> dict:
    """Serialize a ScanResult via JSONReporter and return it as a dict."""
    return json.loads(JSONReporter(result).to_string())


def test_json_output_has_required_top_level_keys():
    """JSON output must always contain these top-level keys."""
    data = _to_dict(_make_minimal_result())

    required_keys = {
        "scan_id", "url", "timestamp", "duration_seconds",
        "is_wordpress", "wordpress_version", "plugins", "themes",
        "users", "waf_detected", "findings", "summary", "blocked",
    }
    missing = required_keys - set(data.keys())
    assert not missing, f"Missing keys in JSON output: {missing}"


def test_json_output_ecommerce_keys_always_present():
    """woocommerce and wp_ecommerce keys must always be present (null when not detected)."""
    data = _to_dict(_make_minimal_result())

    assert "woocommerce" in data, "woocommerce key missing from JSON output"
    assert "wp_ecommerce" in data, "wp_ecommerce key missing from JSON output"
    assert data["woocommerce"] is None
    assert data["wp_ecommerce"] is None


def test_json_finding_has_required_keys():
    """Each Finding in JSON output must have all required fields."""
    finding = Finding(
        id="PC-WC-001",
        remediation_id="REM-WC-001",
        title="Test finding",
        severity=Severity.HIGH,
        description="Test description",
        evidence={"url": "https://example.com"},
        remediation="Fix it",
        references=["https://example.com"],
        cvss_score=7.5,
        module="woocommerce",
    )
    result = _make_minimal_result()
    result.findings.append(finding)
    data = _to_dict(result)

    assert len(data["findings"]) == 1
    f = data["findings"][0]
    required = {
        "id", "remediation_id", "title", "severity", "description",
        "evidence", "remediation", "references", "cvss_score", "module",
    }
    missing = required - set(f.keys())
    assert not missing, f"Missing keys in finding: {missing}"


def test_json_summary_has_all_severity_counts():
    """Summary must have all severity level counts."""
    data = _to_dict(_make_minimal_result())

    summary = data["summary"]
    required = {"critical", "high", "medium", "low", "info"}
    missing = required - set(summary.keys())
    assert not missing, f"Missing summary keys: {missing}"


def test_json_severity_serialized_as_string():
    """Severity enum must be serialized as its string value, not as an integer."""
    finding = Finding(
        id="PC-WC-001",
        remediation_id="REM-WC-001",
        title="Test",
        severity=Severity.CRITICAL,
        description="Desc",
        evidence={},
        remediation="Fix",
        references=[],
        cvss_score=9.8,
        module="test",
    )
    result = _make_minimal_result()
    result.findings.append(finding)
    data = _to_dict(result)

    assert data["findings"][0]["severity"] == "CRITICAL"


def test_json_timestamp_serialized_as_string():
    """Timestamp must be serialized as an ISO string, not as a datetime object."""
    data = _to_dict(_make_minimal_result())

    assert isinstance(data["timestamp"], str), "timestamp must be a string in JSON output"


def test_json_output_is_valid_json():
    """JSONReporter.to_string() must always produce valid JSON."""
    reporter = JSONReporter(_make_minimal_result())
    raw = reporter.to_string()
    # json.loads raises if not valid; let it propagate as a test failure
    parsed = json.loads(raw)
    assert isinstance(parsed, dict)


def test_json_plugins_and_themes_are_lists():
    """plugins and themes fields must serialize as JSON arrays."""
    data = _to_dict(_make_minimal_result())

    assert isinstance(data["plugins"], list)
    assert isinstance(data["themes"], list)
    assert isinstance(data["users"], list)
    assert isinstance(data["findings"], list)


def test_json_summary_values_are_integers():
    """All summary severity counts must be integers."""
    data = _to_dict(_make_minimal_result())

    for key in ("critical", "high", "medium", "low", "info"):
        assert isinstance(data["summary"][key], int), (
            f"summary.{key} should be int, got {type(data['summary'][key])}"
        )


def test_json_blocked_field_is_boolean():
    """blocked field must serialize as a JSON boolean."""
    data = _to_dict(_make_minimal_result())

    assert isinstance(data["blocked"], bool), "blocked must be a boolean in JSON output"


def test_json_duration_seconds_is_numeric():
    """duration_seconds must serialize as a JSON number."""
    data = _to_dict(_make_minimal_result())

    assert isinstance(data["duration_seconds"], (int, float)), (
        "duration_seconds must be numeric in JSON output"
    )
