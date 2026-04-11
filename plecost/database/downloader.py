from __future__ import annotations
import httpx
from pathlib import Path


GITHUB_REPO = "iniqua/plecost"
RELEASE_ASSET_NAME = "plecost.db"


async def download_latest_db(dest_path: str | Path, token: str | None = None) -> None:
    """
    Descarga plecost.db del último release de GitHub.
    Si token es None, usa la API pública (60 req/h).
    """
    dest = Path(dest_path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    api_url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"

    async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
        r = await client.get(api_url, headers=headers)
        r.raise_for_status()
        release = r.json()

        # Buscar el asset plecost.db
        asset_url = None
        for asset in release.get("assets", []):
            if asset["name"] == RELEASE_ASSET_NAME:
                asset_url = asset["browser_download_url"]
                break

        if not asset_url:
            raise RuntimeError(
                f"No se encontró '{RELEASE_ASSET_NAME}' en el último release de {GITHUB_REPO}. "
                f"Ejecuta 'plecost build-db' para crear la base de datos inicial."
            )

        # Descarga en streaming
        async with client.stream("GET", asset_url, headers=headers) as resp:
            resp.raise_for_status()
            with open(dest, "wb") as f:
                async for chunk in resp.aiter_bytes(chunk_size=8192):
                    f.write(chunk)
