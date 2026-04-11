"""
Functional tests against a real WordPress instance.
Requires: docker-compose -f docker-compose.test.yml up -d
Run with: pytest tests/functional/ -m functional -v
"""
from __future__ import annotations
import asyncio
import os
import re
import json
import pytest
from plecost.models import ScanOptions, Severity
from plecost.scanner import Scanner

WP_URL = os.getenv("PLECOST_TEST_URL", "http://localhost:8765")

# Skip if WordPress is not available
pytestmark = pytest.mark.skipif(
    os.getenv("PLECOST_FUNCTIONAL_TESTS") != "1",
    reason="Set PLECOST_FUNCTIONAL_TESTS=1 to run functional tests"
)


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.mark.asyncio
async def test_scanner_returns_result():
    """The scanner returns a valid ScanResult."""
    opts = ScanOptions(url=WP_URL, concurrency=5, timeout=30)
    scanner = Scanner(opts)
    result = await scanner.run()
    assert result.scan_id
    assert result.url == WP_URL
    assert result.duration_seconds > 0


@pytest.mark.asyncio
async def test_scanner_detects_wordpress():
    """The scanner detects that the site is WordPress."""
    opts = ScanOptions(url=WP_URL, concurrency=5, timeout=30)
    scanner = Scanner(opts)
    result = await scanner.run()
    assert result.is_wordpress is True


@pytest.mark.asyncio
async def test_scanner_finds_wordpress_version():
    """The scanner detects the WordPress version."""
    opts = ScanOptions(url=WP_URL, concurrency=5, timeout=30)
    scanner = Scanner(opts)
    result = await scanner.run()
    # WordPress 6.4 should be detected
    assert result.wordpress_version is not None
    assert result.wordpress_version.startswith("6.")


@pytest.mark.asyncio
async def test_scanner_findings_have_valid_ids():
    """All findings have IDs with format PC-XXX-NNN."""
    opts = ScanOptions(url=WP_URL, concurrency=5, timeout=30)
    scanner = Scanner(opts)
    result = await scanner.run()
    pattern = re.compile(r'^PC-[A-Z]+-\d{3}$')
    for finding in result.findings:
        assert pattern.match(finding.id), f"Invalid ID: {finding.id}"
        assert finding.remediation_id.startswith("REM-"), f"Invalid REM ID: {finding.remediation_id}"


@pytest.mark.asyncio
async def test_scanner_summary_counts_match():
    """The summary correctly counts findings by severity."""
    opts = ScanOptions(url=WP_URL, concurrency=5, timeout=30)
    scanner = Scanner(opts)
    result = await scanner.run()
    critical = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in result.findings if f.severity == Severity.HIGH)
    medium = sum(1 for f in result.findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in result.findings if f.severity == Severity.LOW)
    assert result.summary.critical == critical
    assert result.summary.high == high
    assert result.summary.medium == medium
    assert result.summary.low == low


@pytest.mark.asyncio
async def test_scanner_detects_readme_html():
    """WordPress exposes readme.html with version info — should generate a finding."""
    opts = ScanOptions(url=WP_URL, concurrency=5, timeout=30)
    scanner = Scanner(opts)
    result = await scanner.run()
    finding_ids = [f.id for f in result.findings]
    # readme.html is almost always accessible on fresh WordPress installs
    assert "PC-MCFG-009" in finding_ids, f"readme.html not detected. Findings: {finding_ids}"


@pytest.mark.asyncio
async def test_scanner_rest_api_users():
    """The REST API module can enumerate users if available."""
    opts = ScanOptions(url=WP_URL, concurrency=5, timeout=30)
    scanner = Scanner(opts)
    result = await scanner.run()
    # WordPress exposes users via REST API by default
    # Not mandatory but we record how many were found
    assert isinstance(result.users, list)


@pytest.mark.asyncio
async def test_scanner_with_json_reporter():
    """The JSON reporter correctly serializes the result."""
    from plecost.reporters.json_reporter import JSONReporter
    opts = ScanOptions(url=WP_URL, concurrency=5, timeout=30)
    scanner = Scanner(opts)
    result = await scanner.run()
    reporter = JSONReporter(result)
    output = reporter.to_string()
    parsed = json.loads(output)
    assert parsed["url"] == WP_URL
    assert "findings" in parsed
    assert "summary" in parsed
