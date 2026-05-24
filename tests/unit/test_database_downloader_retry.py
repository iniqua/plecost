"""Tests for retry backoff and Authorization header protection in downloader.py.

AC-1: _fetch_bytes retries on HTTP 429 and 5xx (500-599)
AC-2: Delay is 2^attempt + random.uniform(0,1)
AC-3: After 3 retries exhausted, raises httpx.HTTPStatusError
AC-4: URL github.com/raw.githubusercontent.com → Authorization header included
AC-7: Non-GitHub URL with GITHUB_TOKEN → Authorization NOT included
"""
from __future__ import annotations

import pytest
import httpx
import respx

from plecost.database.downloader import (
    _fetch_bytes,
    _make_headers,
    _is_github_url,
    _MAX_RETRIES,
    _RETRY_STATUS_CODES,
    fetch_remote_index_checksum,
    INDEX_CHECKSUM_URL,
)


# ---------------------------------------------------------------------------
# Helper: build a minimal async client for unit tests
# ---------------------------------------------------------------------------

def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=5, follow_redirects=True)


# ---------------------------------------------------------------------------
# AC-1: Retry on 429
# ---------------------------------------------------------------------------

@respx.mock
async def test_fetch_bytes_retries_on_429(monkeypatch):
    """_fetch_bytes should retry on HTTP 429 and succeed on a subsequent attempt."""
    url = "https://github.com/Plecost/plecost-db/releases/download/db-patches/index.json"

    # Patch asyncio.sleep to avoid real delays
    slept: list[float] = []
    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
    monkeypatch.setattr("plecost.database.downloader.asyncio.sleep", fake_sleep)

    respx.get(url).mock(side_effect=[
        httpx.Response(429),
        httpx.Response(200, content=b"ok"),
    ])

    async with _client() as client:
        result = await _fetch_bytes(client, url)

    assert result == b"ok"
    # Exactly one retry → one sleep
    assert len(slept) == 1
    # Delay for attempt=0: between 2^0=1 and 2^0+1=2
    assert 1.0 <= slept[0] < 2.0 + 1e-9


@respx.mock
async def test_fetch_bytes_retries_on_503(monkeypatch):
    """_fetch_bytes should retry on HTTP 503."""
    url = "https://github.com/Plecost/plecost-db/releases/download/db-patches/index.json"

    slept: list[float] = []
    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
    monkeypatch.setattr("plecost.database.downloader.asyncio.sleep", fake_sleep)

    respx.get(url).mock(side_effect=[
        httpx.Response(503),
        httpx.Response(503),
        httpx.Response(200, content=b"success"),
    ])

    async with _client() as client:
        result = await _fetch_bytes(client, url)

    assert result == b"success"
    assert len(slept) == 2
    # attempt=0 delay: [1, 2), attempt=1 delay: [2, 3)
    assert 1.0 <= slept[0] < 2.0 + 1e-9
    assert 2.0 <= slept[1] < 3.0 + 1e-9


# ---------------------------------------------------------------------------
# AC-3: After 3 retries exhausted, raises HTTPStatusError
# ---------------------------------------------------------------------------

@respx.mock
async def test_fetch_bytes_raises_after_max_retries(monkeypatch):
    """After _MAX_RETRIES retries (4 total attempts), raises httpx.HTTPStatusError."""
    url = "https://github.com/Plecost/plecost-db/releases/download/db-patches/index.json"

    slept: list[float] = []
    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
    monkeypatch.setattr("plecost.database.downloader.asyncio.sleep", fake_sleep)

    # 4 attempts: initial + 3 retries — all fail with 429
    respx.get(url).mock(side_effect=[
        httpx.Response(429),
        httpx.Response(429),
        httpx.Response(429),
        httpx.Response(429),
    ])

    async with _client() as client:
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await _fetch_bytes(client, url)

    assert exc_info.value.response.status_code == 429
    # 3 sleeps: after attempts 0, 1, 2 (not after attempt 3 = last)
    assert len(slept) == 3


@respx.mock
async def test_fetch_bytes_does_not_retry_on_404(monkeypatch):
    """404 is NOT a retryable status — should raise immediately without sleeping."""
    url = "https://github.com/Plecost/plecost-db/releases/download/db-patches/index.json"

    slept: list[float] = []
    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
    monkeypatch.setattr("plecost.database.downloader.asyncio.sleep", fake_sleep)

    respx.get(url).mock(return_value=httpx.Response(404))

    async with _client() as client:
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await _fetch_bytes(client, url)

    assert exc_info.value.response.status_code == 404
    # No retries → no sleeps
    assert len(slept) == 0


@respx.mock
async def test_fetch_bytes_does_not_retry_on_401(monkeypatch):
    """401 Unauthorized is NOT retryable — should raise immediately."""
    url = "https://github.com/Plecost/plecost-db/releases/download/db-patches/index.json"

    slept: list[float] = []
    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
    monkeypatch.setattr("plecost.database.downloader.asyncio.sleep", fake_sleep)

    respx.get(url).mock(return_value=httpx.Response(401))

    async with _client() as client:
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await _fetch_bytes(client, url)

    assert exc_info.value.response.status_code == 401
    assert len(slept) == 0


# ---------------------------------------------------------------------------
# AC-4: GitHub URLs receive Authorization header
# ---------------------------------------------------------------------------

def test_make_headers_github_com_receives_auth():
    """github.com URL → Authorization header included."""
    url = "https://github.com/Plecost/plecost-db/releases/download/db-patches/index.json"
    token = "ghp_testtoken123"
    headers = _make_headers(token, url)
    assert "Authorization" in headers
    assert headers["Authorization"] == f"Bearer {token}"


def test_make_headers_api_github_com_receives_auth():
    """api.github.com (subdomain of .github.com) → Authorization header included."""
    url = "https://api.github.com/repos/Plecost/plecost-db/releases/latest"
    token = "ghp_testtoken123"
    headers = _make_headers(token, url)
    assert "Authorization" in headers


def test_make_headers_raw_githubusercontent_receives_auth():
    """raw.githubusercontent.com → Authorization header included."""
    url = "https://raw.githubusercontent.com/Plecost/plecost-db/main/index.json"
    token = "ghp_testtoken123"
    headers = _make_headers(token, url)
    assert "Authorization" in headers


# ---------------------------------------------------------------------------
# AC-7: Non-GitHub URLs do NOT receive Authorization header
# ---------------------------------------------------------------------------

def test_make_headers_non_github_url_no_auth():
    """Non-GitHub URL with token → Authorization NOT included."""
    url = "https://api.wordpress.org/plugins/info/1.2/?action=query_plugins"
    token = "ghp_testtoken123"
    headers = _make_headers(token, url)
    assert "Authorization" not in headers


def test_make_headers_wordpress_org_no_auth():
    """api.wordpress.org URL with token → Authorization NOT included."""
    url = "https://api.wordpress.org/core/version-check/1.7/"
    token = "ghp_testtoken123"
    headers = _make_headers(token, url)
    assert "Authorization" not in headers


def test_make_headers_evil_github_subdomain_no_auth():
    """Domain that mimics GitHub (e.g. evil.github.com.attacker.com) → NO auth."""
    url = "https://evil.github.com.attacker.com/steal"
    token = "ghp_testtoken123"
    headers = _make_headers(token, url)
    assert "Authorization" not in headers


def test_make_headers_no_token_no_auth():
    """No token → no Authorization header regardless of URL."""
    url = "https://github.com/Plecost/plecost-db/releases/download/db-patches/index.json"
    headers = _make_headers(None, url)
    assert "Authorization" not in headers


def test_make_headers_legacy_no_url_includes_auth():
    """Legacy call without URL: token present → Authorization included (backwards compat)."""
    token = "ghp_testtoken123"
    headers = _make_headers(token)
    assert "Authorization" in headers


# ---------------------------------------------------------------------------
# AC-5: _is_github_url covers all expected hostnames
# ---------------------------------------------------------------------------

def test_is_github_url_github_com():
    assert _is_github_url("https://github.com/foo") is True


def test_is_github_url_api_github_com():
    assert _is_github_url("https://api.github.com/repos") is True


def test_is_github_url_raw_githubusercontent():
    assert _is_github_url("https://raw.githubusercontent.com/foo") is True


def test_is_github_url_evil_host_false():
    assert _is_github_url("https://evil.com/github.com") is False


def test_is_github_url_wordpress_org_false():
    assert _is_github_url("https://api.wordpress.org/foo") is False


# ---------------------------------------------------------------------------
# Integration: retry + header protection via fetch_remote_index_checksum
# ---------------------------------------------------------------------------

@respx.mock
async def test_fetch_remote_index_checksum_retries_429(monkeypatch):
    """fetch_remote_index_checksum retries 429 and returns on success."""
    slept: list[float] = []
    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
    monkeypatch.setattr("plecost.database.downloader.asyncio.sleep", fake_sleep)

    respx.get(INDEX_CHECKSUM_URL).mock(side_effect=[
        httpx.Response(429),
        httpx.Response(200, content=b"abc123def456"),
    ])

    result = await fetch_remote_index_checksum()

    assert result == "abc123def456"
    assert len(slept) == 1


@respx.mock
async def test_fetch_remote_index_checksum_no_auth_for_non_github(monkeypatch):
    """If INDEX_CHECKSUM_URL were on a non-GitHub host, no Authorization header would be sent.

    This test verifies the _make_headers logic directly for the non-GitHub case,
    since the actual INDEX_CHECKSUM_URL is on github.com.
    """
    non_github_url = "https://api.wordpress.org/fake/checksum"
    token = "ghp_secret"
    headers = _make_headers(token, non_github_url)
    # Verify that non-GitHub URLs never get the Authorization header
    assert "Authorization" not in headers
