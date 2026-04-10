import io
from rich.console import Console
from plecost.reporters.terminal import TerminalReporter
from plecost.models import ScanResult, ScanSummary, Finding, Severity
from datetime import datetime


def make_result():
    return ScanResult(
        scan_id="abc", url="https://example.com", timestamp=datetime.now(),
        duration_seconds=3.1, is_wordpress=True, wordpress_version="6.4.2",
        plugins=[], themes=[], users=[], waf_detected=None,
        findings=[Finding("PC-FP-001", "REM-FP-001", "Version disclosure",
                          Severity.LOW, "WP found", {}, "Remove tag", [], None, "fingerprint")],
        summary=ScanSummary(low=1)
    )


def test_terminal_reporter_outputs_url():
    buf = io.StringIO()
    console = Console(file=buf, no_color=True)
    TerminalReporter(make_result(), console=console).print()
    output = buf.getvalue()
    assert "https://example.com" in output
    assert "6.4.2" in output
    assert "PC-FP-001" in output
