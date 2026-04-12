from __future__ import annotations

import pytest
import respx
import httpx
from unittest.mock import AsyncMock, patch, MagicMock

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.ssl_tls import SSLTLSModule


@pytest.fixture
def ctx():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    return ctx


@pytest.fixture
def ctx_http():
    ctx = ScanContext(ScanOptions(url="http://example.com"))
    ctx.is_wordpress = True
    return ctx


async def test_ssl_tls_skips_non_wordpress():
    """When ctx.is_wordpress is False the module is a no-op."""
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = False
    async with respx.mock:
        async with PlecostHTTPClient(ctx.opts) as http:
            await SSLTLSModule().run(ctx, http)
    assert ctx.findings == []


async def test_ssl_cert_valid(ctx):
    """No SSL finding when cert is valid and HSTS header is present."""
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(
                200,
                headers={"strict-transport-security": "max-age=31536000"},
                text="<html></html>",
            )
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            # Patch _check_http_redirect and the inner AsyncClient to avoid real network
            with patch("plecost.modules.ssl_tls.httpx.AsyncClient") as mock_client_cls:
                mock_resp = MagicMock()
                mock_resp.status_code = 301

                mock_client_instance = AsyncMock()
                mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
                mock_client_instance.__aexit__ = AsyncMock(return_value=False)
                mock_client_instance.get = AsyncMock(return_value=mock_resp)
                mock_client_cls.return_value = mock_client_instance

                await SSLTLSModule().run(ctx, http)

    ssl_findings = [f for f in ctx.findings if f.id in ("PC-SSL-001", "PC-SSL-002")]
    assert ssl_findings == []


async def test_ssl_cert_invalid_sslerror(ctx):
    """PC-SSL-002 is added when SSL cert validation raises ConnectError with 'ssl'."""
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(
                200,
                headers={"strict-transport-security": "max-age=31536000"},
                text="",
            )
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            with patch("plecost.modules.ssl_tls.httpx.AsyncClient") as mock_client_cls:
                # First call: _check_http_redirect — return 301
                # Second call: _check_ssl_cert — raise SSL ConnectError
                redirect_resp = MagicMock()
                redirect_resp.status_code = 301

                def make_client_side_effect(*args, **kwargs):
                    verify = kwargs.get("verify", True)
                    mock_inst = AsyncMock()
                    mock_inst.__aenter__ = AsyncMock(return_value=mock_inst)
                    mock_inst.__aexit__ = AsyncMock(return_value=False)
                    if verify is True:
                        # SSL verify client — raise ssl error
                        mock_inst.get = AsyncMock(
                            side_effect=httpx.ConnectError("ssl: certificate verify failed")
                        )
                    else:
                        # no-redirect client
                        mock_inst.get = AsyncMock(return_value=redirect_resp)
                    return mock_inst

                mock_client_cls.side_effect = make_client_side_effect

                await SSLTLSModule().run(ctx, http)

    assert any(f.id == "PC-SSL-002" for f in ctx.findings)


async def test_ssl_no_redirect_adds_finding(ctx):
    """PC-SSL-001 is added when HTTP does not redirect to HTTPS (non-3xx response)."""
    async with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(
                200,
                headers={"strict-transport-security": "max-age=31536000"},
                text="",
            )
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            with patch("plecost.modules.ssl_tls.httpx.AsyncClient") as mock_client_cls:
                ok_resp = MagicMock()
                ok_resp.status_code = 200  # Not a redirect

                def make_client_side_effect(*args, **kwargs):
                    verify = kwargs.get("verify", True)
                    mock_inst = AsyncMock()
                    mock_inst.__aenter__ = AsyncMock(return_value=mock_inst)
                    mock_inst.__aexit__ = AsyncMock(return_value=False)
                    if verify is True:
                        # SSL verify client — success, no error
                        mock_inst.get = AsyncMock(return_value=MagicMock())
                    else:
                        # no-redirect client returns 200 (no redirect)
                        mock_inst.get = AsyncMock(return_value=ok_resp)
                    return mock_inst

                mock_client_cls.side_effect = make_client_side_effect

                await SSLTLSModule().run(ctx, http)

    assert any(f.id == "PC-SSL-001" for f in ctx.findings)


async def test_hsts_missing_adds_finding(ctx):
    """PC-SSL-003 is added when HSTS header is absent from an HTTPS response."""
    async with respx.mock:
        # Response with no HSTS header
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text="<html></html>")
        )
        async with PlecostHTTPClient(ctx.opts) as http:
            with patch("plecost.modules.ssl_tls.httpx.AsyncClient") as mock_client_cls:
                mock_inst = AsyncMock()
                mock_inst.__aenter__ = AsyncMock(return_value=mock_inst)
                mock_inst.__aexit__ = AsyncMock(return_value=False)
                redirect_resp = MagicMock()
                redirect_resp.status_code = 301
                mock_inst.get = AsyncMock(return_value=redirect_resp)
                mock_client_cls.return_value = mock_inst

                await SSLTLSModule().run(ctx, http)

    assert any(f.id == "PC-SSL-003" for f in ctx.findings)


async def test_http_url_skips_ssl_checks(ctx_http):
    """For http:// URLs the SSL and redirect checks are skipped entirely."""
    async with respx.mock:
        async with PlecostHTTPClient(ctx_http.opts) as http:
            with patch("plecost.modules.ssl_tls.httpx.AsyncClient") as mock_client_cls:
                await SSLTLSModule().run(ctx_http, http)
                # AsyncClient should never be called for http:// sites
                mock_client_cls.assert_not_called()
