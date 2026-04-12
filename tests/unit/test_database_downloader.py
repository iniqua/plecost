from __future__ import annotations

import pytest
import httpx
import respx

from plecost.database.downloader import download_latest_db, GITHUB_REPO, RELEASE_ASSET_NAME

GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
ASSET_DOWNLOAD_URL = "https://github.com/iniqua/plecost/releases/download/db-base/plecost.db"

FAKE_RELEASE_WITH_ASSET = {
    "tag_name": "db-base",
    "assets": [
        {
            "name": RELEASE_ASSET_NAME,
            "browser_download_url": ASSET_DOWNLOAD_URL,
        }
    ],
}

FAKE_RELEASE_NO_ASSET = {
    "tag_name": "db-base",
    "assets": [
        {
            "name": "other_file.txt",
            "browser_download_url": "https://example.com/other_file.txt",
        }
    ],
}

FAKE_DB_BYTES = b"SQLite format 3\x00" + b"\x00" * 100


@respx.mock
async def test_download_latest_db_success(tmp_path):
    dest = tmp_path / "plecost.db"

    respx.get(GITHUB_API_URL).mock(
        return_value=httpx.Response(200, json=FAKE_RELEASE_WITH_ASSET)
    )
    respx.get(ASSET_DOWNLOAD_URL).mock(
        return_value=httpx.Response(200, content=FAKE_DB_BYTES)
    )

    await download_latest_db(dest)

    assert dest.exists()
    assert dest.read_bytes() == FAKE_DB_BYTES


@respx.mock
async def test_download_no_assets_raises(tmp_path):
    dest = tmp_path / "plecost.db"

    respx.get(GITHUB_API_URL).mock(
        return_value=httpx.Response(200, json=FAKE_RELEASE_NO_ASSET)
    )

    with pytest.raises(RuntimeError, match=RELEASE_ASSET_NAME):
        await download_latest_db(dest)


@respx.mock
async def test_download_with_token(tmp_path):
    dest = tmp_path / "plecost.db"
    token = "ghp_testtoken123"

    api_route = respx.get(GITHUB_API_URL).mock(
        return_value=httpx.Response(200, json=FAKE_RELEASE_WITH_ASSET)
    )
    respx.get(ASSET_DOWNLOAD_URL).mock(
        return_value=httpx.Response(200, content=FAKE_DB_BYTES)
    )

    await download_latest_db(dest, token=token)

    # Verify the Authorization header was sent in the API call
    assert api_route.called
    request = api_route.calls[0].request
    assert "Authorization" in request.headers
    assert request.headers["Authorization"] == f"Bearer {token}"
