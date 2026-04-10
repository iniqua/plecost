import json
import pytest
import respx
import httpx
from typer.testing import CliRunner
from plecost.cli import app

runner = CliRunner()


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
