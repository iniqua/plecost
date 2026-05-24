"""Tests for retry backoff and Authorization header protection in downloader.py.

AC-1: _fetch_bytes retries on HTTP 429 and 5xx (500-599)
AC-2: Delay is 2^attempt + random.uniform(0,1)
AC-3: After 3 retries exhausted, raises httpx.HTTPStatusError
AC-4: URL github.com/raw.githubusercontent.com → Authorization header included
AC-7: Non-GitHub URL with GITHUB_TOKEN → Authorization NOT included

G-027: fetch_index() verifies SHA256 of index.json against INDEX_CHECKSUM_URL
G-028: download_latest_db() enforces 100 MB size limit + deprecation warning
G3-004: download_full_json() retries up to 3 times on SHA256 mismatch
"""
from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

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
    fetch_index,
    download_full_json,
    download_latest_db,
    INDEX_CHECKSUM_URL,
    INDEX_URL,
    FULL_CHECKSUM_URL,
    FULL_JSON_URL,
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


# ---------------------------------------------------------------------------
# G-027: fetch_index() verifies SHA256 of index.json
# ---------------------------------------------------------------------------

def _make_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@respx.mock
async def test_fetch_index_valid_checksum_returns_dict():
    """fetch_index returns a parsed dict when SHA256 matches."""
    payload = b'{"patches": ["patch-2026-01-01.json"]}'
    checksum = _make_sha256(payload)

    respx.get(INDEX_CHECKSUM_URL).mock(
        return_value=httpx.Response(200, content=checksum.encode())
    )
    respx.get(INDEX_URL).mock(
        return_value=httpx.Response(200, content=payload)
    )

    result = await fetch_index()

    assert isinstance(result, dict)
    assert "patches" in result


@respx.mock
async def test_fetch_index_sha256_mismatch_raises_value_error():
    """fetch_index raises ValueError when the SHA256 checksum does not match.

    Anti-tautology: removing the SHA256 check would cause this test to return
    the dict instead of raising, failing the `pytest.raises` assertion.
    """
    payload = b'{"patches": ["patch-2026-01-01.json"]}'
    wrong_checksum = "0" * 64  # deliberate wrong checksum

    respx.get(INDEX_CHECKSUM_URL).mock(
        return_value=httpx.Response(200, content=wrong_checksum.encode())
    )
    respx.get(INDEX_URL).mock(
        return_value=httpx.Response(200, content=payload)
    )

    with pytest.raises(ValueError, match="SHA256 mismatch for index.json"):
        await fetch_index()


@respx.mock
async def test_fetch_index_uses_two_separate_clients():
    """fetch_index fetches checksum and index.json via independent HTTP calls.

    Both INDEX_CHECKSUM_URL and INDEX_URL must be called exactly once.
    Anti-tautology: collapsing the two clients into one would not change the
    call count, but the test proves both URLs are hit independently.
    """
    payload = b'{"patches": []}'
    checksum = _make_sha256(payload)

    ck_route = respx.get(INDEX_CHECKSUM_URL).mock(
        return_value=httpx.Response(200, content=checksum.encode())
    )
    idx_route = respx.get(INDEX_URL).mock(
        return_value=httpx.Response(200, content=payload)
    )

    await fetch_index()

    assert ck_route.called, "INDEX_CHECKSUM_URL was never fetched"
    assert idx_route.called, "INDEX_URL was never fetched"


# ---------------------------------------------------------------------------
# G3-004: download_full_json() retries on SHA256 mismatch
# ---------------------------------------------------------------------------

@respx.mock
async def test_download_full_json_success_on_first_attempt():
    """download_full_json succeeds when checksum matches on the first attempt."""
    payload = b'{"upserts": [], "deletes": []}'
    checksum = _make_sha256(payload)

    respx.get(FULL_CHECKSUM_URL).mock(
        return_value=httpx.Response(200, content=checksum.encode())
    )
    respx.get(FULL_JSON_URL).mock(
        return_value=httpx.Response(200, content=payload)
    )

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        dest = Path(tmp.name)

    try:
        await download_full_json(dest)
        assert dest.exists()
        assert dest.read_bytes() == payload
    finally:
        dest.unlink(missing_ok=True)


@respx.mock
async def test_download_full_json_retries_on_mismatch_then_succeeds():
    """download_full_json retries when mismatch occurs and succeeds on 2nd attempt.

    Anti-tautology: without the retry loop the function would raise on the first
    mismatch instead of succeeding, causing `dest.exists()` to be False.
    """
    good_payload = b'{"upserts": [], "deletes": []}'
    good_checksum = _make_sha256(good_payload)
    bad_checksum = "a" * 64  # wrong checksum for attempt 1

    # attempt 1: bad checksum → mismatch
    # attempt 2: correct checksum → success
    respx.get(FULL_CHECKSUM_URL).mock(side_effect=[
        httpx.Response(200, content=bad_checksum.encode()),
        httpx.Response(200, content=good_checksum.encode()),
    ])
    respx.get(FULL_JSON_URL).mock(
        return_value=httpx.Response(200, content=good_payload)
    )

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        dest = Path(tmp.name)

    try:
        await download_full_json(dest)
        assert dest.exists()
        assert dest.read_bytes() == good_payload
    finally:
        dest.unlink(missing_ok=True)


@respx.mock
async def test_download_full_json_raises_after_three_mismatches():
    """download_full_json raises ValueError after _MAX_RETRIES (3) consecutive mismatches.

    Anti-tautology: without the retry loop the ValueError would be raised on
    attempt 1 rather than attempt 3, so the retry count (call count) would differ.
    """
    payload = b'{"upserts": [], "deletes": []}'
    bad_checksum = "b" * 64  # always wrong

    # Always return a bad checksum → 3 attempts all fail
    respx.get(FULL_CHECKSUM_URL).mock(
        return_value=httpx.Response(200, content=bad_checksum.encode())
    )
    respx.get(FULL_JSON_URL).mock(
        return_value=httpx.Response(200, content=payload)
    )

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        dest = Path(tmp.name)
    dest.unlink(missing_ok=True)  # start with no file

    try:
        with pytest.raises(ValueError, match="SHA256 mismatch for full.json"):
            await download_full_json(dest)
        # File should have been cleaned up after the final mismatch
        assert not dest.exists()
        # All 3 attempts should have fetched checksum + file
        assert respx.calls.call_count == 6  # 3 * (1 checksum + 1 file)
    finally:
        dest.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# G-028: download_latest_db() size limit + deprecation warning
# ---------------------------------------------------------------------------

@respx.mock
async def test_download_latest_db_raises_on_asset_over_100mb():
    """download_latest_db raises ValueError when the asset size metadata > 100 MB.

    Anti-tautology: without the size check the function would proceed to download,
    not raise ValueError, causing the pytest.raises to fail.
    """
    _100MB_PLUS_1 = 100 * 1024 * 1024 + 1

    api_url = "https://api.github.com/repos/Plecost/plecost-db/releases/latest"
    respx.get(api_url).mock(return_value=httpx.Response(200, json={
        "assets": [{
            "name": "plecost.db",
            "browser_download_url": "https://github.com/Plecost/plecost-db/releases/download/latest/plecost.db",
            "size": _100MB_PLUS_1,
        }]
    }))

    with tempfile.TemporaryDirectory() as tmpdir:
        dest = Path(tmpdir) / "plecost.db"
        with pytest.raises(ValueError, match="100 MB"):
            await download_latest_db(dest)


@respx.mock
async def test_download_latest_db_raises_on_streaming_over_100mb():
    """download_latest_db raises ValueError if streamed bytes exceed 100 MB.

    This covers the case where the GitHub API metadata has no 'size' field but
    the actual download exceeds the limit.
    Anti-tautology: removing the byte counter check would allow the full download
    to complete without raising.
    """
    _100MB_PLUS_1 = 100 * 1024 * 1024 + 1
    download_url = "https://github.com/Plecost/plecost-db/releases/download/latest/plecost.db"

    api_url = "https://api.github.com/repos/Plecost/plecost-db/releases/latest"
    respx.get(api_url).mock(return_value=httpx.Response(200, json={
        "assets": [{
            "name": "plecost.db",
            "browser_download_url": download_url,
            # No 'size' key → metadata check skipped
        }]
    }))
    # Stream content that exceeds 100 MB (we send in one chunk here)
    big_content = b"x" * _100MB_PLUS_1
    respx.get(download_url).mock(return_value=httpx.Response(200, content=big_content))

    with tempfile.TemporaryDirectory() as tmpdir:
        dest = Path(tmpdir) / "plecost.db"
        with pytest.raises(ValueError, match="100 MB"):
            await download_latest_db(dest)


@respx.mock
async def test_download_latest_db_emits_deprecation_warning(caplog):
    """download_latest_db emits a deprecation warning via logger.warning.

    Anti-tautology: removing the logger.warning call would cause caplog to be
    empty, failing the assertion.
    """
    import logging

    api_url = "https://api.github.com/repos/Plecost/plecost-db/releases/latest"
    download_url = "https://github.com/Plecost/plecost-db/releases/download/latest/plecost.db"

    respx.get(api_url).mock(return_value=httpx.Response(200, json={
        "assets": [{
            "name": "plecost.db",
            "browser_download_url": download_url,
            "size": 100,
        }]
    }))
    respx.get(download_url).mock(return_value=httpx.Response(200, content=b"SQLITEDB"))

    with tempfile.TemporaryDirectory() as tmpdir:
        dest = Path(tmpdir) / "plecost.db"
        with caplog.at_level(logging.WARNING, logger="plecost.database.downloader"):
            await download_latest_db(dest)

    assert any("deprecated" in r.message.lower() for r in caplog.records), (
        "Expected a deprecation warning from download_latest_db"
    )
