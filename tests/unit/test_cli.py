import json
from datetime import datetime
from unittest.mock import patch
import respx
import httpx
from typer.testing import CliRunner
from plecost.cli import app, _parse_module_options
from plecost.models import ScanResult, ScanSummary

runner = CliRunner()


def _make_scan_result(url: str = "https://example.com") -> ScanResult:
    """Return a minimal ScanResult for use in mocks."""
    return ScanResult(
        scan_id="test-id",
        url=url,
        timestamp=datetime.utcnow(),
        duration_seconds=0.1,
        is_wordpress=False,
        wordpress_version=None,
        plugins=[],
        themes=[],
        users=[],
        waf_detected=None,
        findings=[],
        summary=ScanSummary(critical=0, high=0, medium=0, low=0, info=0),
    )


def test_cli_scan_requires_url():
    result = runner.invoke(app, ["scan"])
    assert result.exit_code != 0


def test_cli_modules_list():
    result = runner.invoke(app, ["modules", "list"])
    assert result.exit_code == 0
    assert "fingerprint" in result.output
    assert "plugins" in result.output


def test_cli_scan_not_wordpress():
    with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        result = runner.invoke(app, ["scan", "https://example.com", "--modules", "fingerprint"])
    assert result.exit_code == 0


def test_cli_scan_verbose_flag_accepted():
    """The -v flag is accepted without error."""
    with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        result = runner.invoke(app, ["scan", "https://example.com", "--modules", "fingerprint", "-v"])
    assert result.exit_code != 2  # 2 = typer usage error (unrecognized option)


def test_cli_scan_outputs_json(tmp_path):
    out = tmp_path / "report.json"
    with respx.mock:
        html = '<meta name="generator" content="WordPress 6.4.2"/>'
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        result = runner.invoke(app, [
            "scan", "https://example.com",
            "--modules", "fingerprint",
            "--output", str(out)
        ])
    assert result.exit_code == 0
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["is_wordpress"] is True


# ---------------------------------------------------------------------------
# explain command
# ---------------------------------------------------------------------------

def test_explain_known_id():
    """plecost explain PC-WC-001 should exit 0 and print the finding title."""
    result = runner.invoke(app, ["explain", "PC-WC-001"])
    assert result.exit_code == 0
    assert "WooCommerce" in result.output


def test_explain_unknown_id():
    """plecost explain with an unknown ID should exit non-zero and show an error."""
    result = runner.invoke(app, ["explain", "PC-UNKNOWN-999"])
    assert result.exit_code != 0
    assert "Unknown finding ID" in result.output or "unknown" in result.output.lower()


# ---------------------------------------------------------------------------
# modules command
# ---------------------------------------------------------------------------

def test_modules_command():
    """plecost modules list should list both eCommerce module names."""
    result = runner.invoke(app, ["modules", "list"])
    assert result.exit_code == 0
    assert "woocommerce" in result.output
    assert "wp_ecommerce" in result.output


# ---------------------------------------------------------------------------
# _parse_module_options() — pure unit tests (no CLI, no async)
# ---------------------------------------------------------------------------

def test_parse_module_options_single():
    result = _parse_module_options(["woocommerce:mode=semi-active"])
    assert result == {"woocommerce": {"mode": "semi-active"}}


def test_parse_module_options_multiple():
    result = _parse_module_options([
        "woocommerce:mode=semi-active",
        "wpec:mode=semi-active",
    ])
    assert result == {
        "woocommerce": {"mode": "semi-active"},
        "wpec": {"mode": "semi-active"},
    }


def test_parse_module_options_value_with_equals():
    """A value that itself contains '=' should be preserved fully (split on first '=' only)."""
    result = _parse_module_options(["woocommerce:wc_consumer_key=ck_foo=bar"])
    assert result == {"woocommerce": {"wc_consumer_key": "ck_foo=bar"}}


def test_parse_module_options_invalid_no_colon():
    """An entry without ':' should be silently ignored."""
    result = _parse_module_options(["invalidoption"])
    assert result == {}


def test_parse_module_options_invalid_no_equals():
    """An entry with ':' but without '=' in the right-hand side should be silently ignored."""
    result = _parse_module_options(["woocommerce:novalor"])
    assert result == {}


def test_parse_module_options_empty():
    result = _parse_module_options([])
    assert result == {}


# ---------------------------------------------------------------------------
# scan --force flag propagation (mock Scanner)
# ---------------------------------------------------------------------------

def test_scan_force_flag_passes_to_options():
    """--force=True should be reflected in the ScanOptions passed to Scanner."""
    captured: list = []

    async def fake_run(self):  # noqa: ANN001
        captured.append(self._opts)
        return _make_scan_result()

    with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        with patch("plecost.scanner.Scanner.run", fake_run):
            result = runner.invoke(app, [
                "scan", "https://example.com",
                "--modules", "fingerprint",
                "--force",
            ])

    assert result.exit_code == 0
    assert len(captured) == 1
    assert captured[0].force is True


# ---------------------------------------------------------------------------
# scan --module-option flag propagation
# ---------------------------------------------------------------------------

def test_scan_module_option_flag():
    """--module-option woocommerce:mode=semi-active should reach ScanOptions.module_options."""
    captured: list = []

    async def fake_run(self):  # noqa: ANN001
        captured.append(self._opts)
        return _make_scan_result()

    with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        with patch("plecost.scanner.Scanner.run", fake_run):
            result = runner.invoke(app, [
                "scan", "https://example.com",
                "--modules", "fingerprint",
                "--module-option", "woocommerce:mode=semi-active",
            ])

    assert result.exit_code == 0
    assert len(captured) == 1
    assert captured[0].module_options.get("woocommerce", {}).get("mode") == "semi-active"


# ---------------------------------------------------------------------------
# scan -T / --targets (bulk scan from file)
# ---------------------------------------------------------------------------

def test_scan_targets_file(tmp_path):
    """Passing -T with a file of URLs should cause Scanner.run to be called once per URL."""
    urls_file = tmp_path / "urls.txt"
    urls_file.write_text("https://example.com\nhttps://example.org\n")

    call_count = 0

    async def fake_run(self):  # noqa: ANN001
        nonlocal call_count
        call_count += 1
        return _make_scan_result(url=self._opts.url)

    with respx.mock:
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        with patch("plecost.scanner.Scanner.run", fake_run):
            result = runner.invoke(app, [
                "scan",
                "-T", str(urls_file),
                "--modules", "fingerprint",
            ])

    assert result.exit_code == 0
    assert call_count == 2
