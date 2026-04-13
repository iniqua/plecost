from __future__ import annotations

import hashlib
import json

import pytest
import httpx
import respx

from plecost.database.downloader import (
    download_latest_db,
    GITHUB_REPO,
    RELEASE_ASSET_NAME,
    INDEX_CHECKSUM_URL,
    INDEX_URL,
    FULL_JSON_URL,
    FULL_CHECKSUM_URL,
    fetch_remote_index_checksum,
    fetch_index,
    download_full_json,
    download_patch,
)

GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
ASSET_DOWNLOAD_URL = "https://github.com/Plecost/plecost/releases/download/db-base/plecost.db"

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

FAKE_INDEX = {
    "generated_at": "2026-04-12T02:00:00Z",
    "full": {
        "url": FULL_JSON_URL,
        "sha256": "abc123",
    },
    "patches": [
        {
            "date": "2026-04-11",
            "url": "https://github.com/Plecost/plecost/releases/download/db-patches/patch-2026-04-11.json",
            "sha256": "def456",
        }
    ],
}

FAKE_PATCH = {
    "date": "2026-04-11",
    "source": "nvd",
    "upsert": [{"cve_id": "CVE-2024-1234", "software_type": "plugin", "slug": "woocommerce"}],
    "delete": [],
}


# --- Legacy download_latest_db tests ---

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

    with pytest.raises(RuntimeError, match="plecost.db"):
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

    assert api_route.called
    request = api_route.calls[0].request
    assert "Authorization" in request.headers
    assert request.headers["Authorization"] == f"Bearer {token}"


# --- New JSON patch system tests ---

@respx.mock
async def test_fetch_remote_index_checksum():
    expected = "abc123def456"
    respx.get(INDEX_CHECKSUM_URL).mock(
        return_value=httpx.Response(200, content=expected.encode())
    )

    result = await fetch_remote_index_checksum()

    assert result == expected


@respx.mock
async def test_fetch_index_returns_parsed_json():
    respx.get(INDEX_URL).mock(
        return_value=httpx.Response(200, json=FAKE_INDEX)
    )

    result = await fetch_index()

    assert result["generated_at"] == "2026-04-12T02:00:00Z"
    assert len(result["patches"]) == 1  # type: ignore[arg-type]


@respx.mock
async def test_download_full_json_verifies_sha256(tmp_path):
    content = json.dumps({"upsert": [], "delete": []}).encode()
    sha256 = hashlib.sha256(content).hexdigest()
    dest = tmp_path / "full.json"

    respx.get(FULL_CHECKSUM_URL).mock(
        return_value=httpx.Response(200, content=sha256.encode())
    )
    respx.get(FULL_JSON_URL).mock(
        return_value=httpx.Response(200, content=content)
    )

    await download_full_json(dest)

    assert dest.exists()
    assert json.loads(dest.read_bytes()) == {"upsert": [], "delete": []}


@respx.mock
async def test_download_full_json_sha256_mismatch_raises(tmp_path):
    content = json.dumps({"upsert": [], "delete": []}).encode()
    dest = tmp_path / "full.json"

    respx.get(FULL_CHECKSUM_URL).mock(
        return_value=httpx.Response(200, content=b"wrongchecksum")
    )
    respx.get(FULL_JSON_URL).mock(
        return_value=httpx.Response(200, content=content)
    )

    with pytest.raises(ValueError, match="SHA256 mismatch"):
        await download_full_json(dest)

    assert not dest.exists()


@respx.mock
async def test_download_patch_verifies_sha256():
    content = json.dumps(FAKE_PATCH).encode()
    sha256 = hashlib.sha256(content).hexdigest()
    patch_url = "https://github.com/Plecost/plecost/releases/download/db-patches/patch-2026-04-11.json"

    respx.get(patch_url).mock(
        return_value=httpx.Response(200, content=content)
    )

    result = await download_patch(patch_url, sha256)

    assert result["date"] == "2026-04-11"
    assert len(result["upsert"]) == 1  # type: ignore[arg-type]


@respx.mock
async def test_download_patch_sha256_mismatch_raises():
    content = json.dumps(FAKE_PATCH).encode()
    patch_url = "https://github.com/Plecost/plecost/releases/download/db-patches/patch-2026-04-11.json"

    respx.get(patch_url).mock(
        return_value=httpx.Response(200, content=content)
    )

    with pytest.raises(ValueError, match="SHA256 mismatch"):
        await download_patch(patch_url, "wrongchecksum")
