from plecost.engine.context import ScanContext
from plecost.models import ScanOptions, Finding, Severity, Plugin


def test_context_stores_findings():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    finding = Finding(
        id="PC-FP-001", remediation_id="REM-FP-001",
        title="Test", severity=Severity.HIGH, description="d",
        evidence={}, remediation="r", references=[], cvss_score=None,
        module="fingerprint"
    )
    ctx.add_finding(finding)
    assert len(ctx.findings) == 1
    assert ctx.findings[0].id == "PC-FP-001"


def test_context_stores_plugins():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.add_plugin(Plugin("woocommerce", "8.0.0", "8.5.0", "/wp-content/plugins/woocommerce/", outdated=True))
    assert len(ctx.plugins) == 1


def test_context_is_wordpress_default_false():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    assert ctx.is_wordpress is False


def test_context_on_finding_callback():
    """on_finding callback is called when a finding is added."""
    calls = []
    ctx = ScanContext(ScanOptions(url="https://example.com"), on_finding=calls.append)
    finding = Finding(
        id="PC-FP-001", remediation_id="REM-FP-001",
        title="Test", severity=Severity.HIGH, description="d",
        evidence={}, remediation="r", references=[], cvss_score=None,
        module="fingerprint"
    )
    ctx.add_finding(finding)
    assert len(calls) == 1
    assert calls[0].id == "PC-FP-001"


def test_context_no_callback_does_not_fail():
    """ScanContext works normally without callback."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    finding = Finding(
        id="PC-FP-002", remediation_id="REM-FP-002",
        title="Test2", severity=Severity.LOW, description="d",
        evidence={}, remediation="r", references=[], cvss_score=None,
        module="fingerprint"
    )
    ctx.add_finding(finding)
    assert len(ctx.findings) == 1


def test_context_thread_safe_findings():
    """Multiple modules can add findings concurrently."""
    import asyncio
    ctx = ScanContext(ScanOptions(url="https://example.com"))

    async def add_findings():
        tasks = []
        for i in range(20):
            f = Finding(f"PC-TEST-{i:03d}", f"REM-TEST-{i:03d}", f"T{i}",
                        Severity.INFO, "d", {}, "r", [], None, "test")
            tasks.append(asyncio.to_thread(ctx.add_finding, f))
        await asyncio.gather(*tasks)

    asyncio.run(add_findings())
    assert len(ctx.findings) == 20
