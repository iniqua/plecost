"""
Tests funcionales contra WordPress real.
Requiere: docker-compose -f docker-compose.test.yml up -d
Ejecutar con: pytest tests/functional/ -m functional -v
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

# Skip si no hay WordPress disponible
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
    """El scanner devuelve un ScanResult válido."""
    opts = ScanOptions(url=WP_URL, concurrency=5, timeout=30)
    scanner = Scanner(opts)
    result = await scanner.run()
    assert result.scan_id
    assert result.url == WP_URL
    assert result.duration_seconds > 0


@pytest.mark.asyncio
async def test_scanner_detects_wordpress():
    """El scanner detecta que es WordPress."""
    opts = ScanOptions(url=WP_URL, concurrency=5, timeout=30)
    scanner = Scanner(opts)
    result = await scanner.run()
    assert result.is_wordpress is True


@pytest.mark.asyncio
async def test_scanner_finds_wordpress_version():
    """El scanner detecta la versión de WordPress."""
    opts = ScanOptions(url=WP_URL, concurrency=5, timeout=30)
    scanner = Scanner(opts)
    result = await scanner.run()
    # WordPress 6.4 debería ser detectado
    assert result.wordpress_version is not None
    assert result.wordpress_version.startswith("6.")


@pytest.mark.asyncio
async def test_scanner_findings_have_valid_ids():
    """Todos los findings tienen IDs con formato PC-XXX-NNN."""
    opts = ScanOptions(url=WP_URL, concurrency=5, timeout=30)
    scanner = Scanner(opts)
    result = await scanner.run()
    pattern = re.compile(r'^PC-[A-Z]+-\d{3}$')
    for finding in result.findings:
        assert pattern.match(finding.id), f"ID inválido: {finding.id}"
        assert finding.remediation_id.startswith("REM-"), f"REM ID inválido: {finding.remediation_id}"


@pytest.mark.asyncio
async def test_scanner_summary_counts_match():
    """El summary cuenta correctamente los findings por severidad."""
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
    """WordPress expone readme.html con la versión — debería generar finding."""
    opts = ScanOptions(url=WP_URL, concurrency=5, timeout=30)
    scanner = Scanner(opts)
    result = await scanner.run()
    finding_ids = [f.id for f in result.findings]
    # readme.html es casi siempre accesible en WordPress nuevo
    assert "PC-MCFG-009" in finding_ids, f"readme.html no detectado. Findings: {finding_ids}"


@pytest.mark.asyncio
async def test_scanner_rest_api_users():
    """El módulo REST API puede enumerar usuarios si está disponible."""
    opts = ScanOptions(url=WP_URL, concurrency=5, timeout=30)
    scanner = Scanner(opts)
    result = await scanner.run()
    # WordPress por defecto expone usuarios via REST API
    # No es obligatorio pero registramos cuántos encontró
    assert isinstance(result.users, list)


@pytest.mark.asyncio
async def test_scanner_with_json_reporter():
    """El JSON reporter serializa correctamente el resultado."""
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
