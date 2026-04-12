from __future__ import annotations
import hashlib
import json
from pathlib import Path
import httpx

GITHUB_REPO = "iniqua/plecost"
RELEASE_ASSET_NAME = "plecost.db"  # Deprecated: kept for backwards compatibility
PATCHES_RELEASE_TAG = "db-patches"
BASE_URL = f"https://github.com/{GITHUB_REPO}/releases/download/{PATCHES_RELEASE_TAG}"

INDEX_URL = f"{BASE_URL}/index.json"
INDEX_CHECKSUM_URL = f"{BASE_URL}/index.checksum"
FULL_JSON_URL = f"{BASE_URL}/full.json"
FULL_CHECKSUM_URL = f"{BASE_URL}/full.checksum"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def _fetch_bytes(client: httpx.AsyncClient, url: str) -> bytes:
    r = await client.get(url)
    r.raise_for_status()
    return r.content


async def _stream_to_file(client: httpx.AsyncClient, url: str, dest: Path) -> None:
    async with client.stream("GET", url) as resp:
        resp.raise_for_status()
        with open(dest, "wb") as f:
            async for chunk in resp.aiter_bytes(chunk_size=65536):
                f.write(chunk)


async def fetch_remote_index_checksum(token: str | None = None) -> str:
    """Fetch only the checksum of the remote index (cheap, ~64 bytes)."""
    headers = _make_headers(token)
    async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers=headers) as client:
        data = await _fetch_bytes(client, INDEX_CHECKSUM_URL)
    return data.decode().strip()


async def fetch_index(token: str | None = None) -> dict[str, object]:
    """Download and return the full index.json."""
    headers = _make_headers(token)
    async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers=headers) as client:
        data = await _fetch_bytes(client, INDEX_URL)
    result: dict[str, object] = json.loads(data)
    return result


async def download_full_json(dest: Path, token: str | None = None) -> None:
    """Download the full.json patch file and verify its SHA256."""
    headers = _make_headers(token)
    async with httpx.AsyncClient(timeout=300, follow_redirects=True, headers=headers) as client:
        # Fetch checksum first
        checksum_data = await _fetch_bytes(client, FULL_CHECKSUM_URL)
        expected_sha256 = checksum_data.decode().strip().split()[0]

        # Stream download
        await _stream_to_file(client, FULL_JSON_URL, dest)

    # Verify SHA256
    actual = _sha256_file(dest)
    if actual != expected_sha256:
        dest.unlink(missing_ok=True)
        raise ValueError(
            f"SHA256 mismatch for full.json: expected {expected_sha256}, got {actual}"
        )


async def download_patch(url: str, expected_sha256: str, token: str | None = None) -> dict[str, object]:
    """Download a single daily patch JSON and verify its SHA256. Returns parsed JSON."""
    headers = _make_headers(token)
    async with httpx.AsyncClient(timeout=60, follow_redirects=True, headers=headers) as client:
        data = await _fetch_bytes(client, url)

    actual = _sha256_bytes(data)
    if actual != expected_sha256:
        raise ValueError(
            f"SHA256 mismatch for {url}: expected {expected_sha256}, got {actual}"
        )

    result: dict[str, object] = json.loads(data)
    return result


def _make_headers(token: str | None) -> dict[str, str]:
    headers: dict[str, str] = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


# Legacy function kept for backwards compatibility
async def download_latest_db(dest_path: str | Path, token: str | None = None) -> None:
    """
    DEPRECATED: downloads the legacy SQLite DB from GitHub releases.
    Use download_patches() instead.
    Kept for backwards compatibility with existing installations.
    """
    dest = Path(dest_path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    api_url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"

    async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
        r = await client.get(api_url, headers=headers)
        r.raise_for_status()
        release = r.json()

        asset_url = None
        for asset in release.get("assets", []):
            if asset["name"] == "plecost.db":
                asset_url = asset["browser_download_url"]
                break

        if not asset_url:
            raise RuntimeError(
                f"'plecost.db' not found in the latest release of {GITHUB_REPO}. "
                f"Run 'plecost build-db' to create the initial database."
            )

        async with client.stream("GET", asset_url, headers=headers) as resp:
            resp.raise_for_status()
            with open(dest, "wb") as f:
                async for chunk in resp.aiter_bytes(chunk_size=8192):
                    f.write(chunk)
