from __future__ import annotations
import asyncio
import json
import sqlite3
from pathlib import Path
import httpx

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WP_PLUGINS_API = "https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[per_page]=250&request[page]={page}"


class DatabaseUpdater:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path

    async def run(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = self._init_db()
        async with httpx.AsyncClient(timeout=30) as client:
            await asyncio.gather(
                self._fetch_nvd(client, conn),
                self._fetch_plugin_wordlist(client, conn),
            )
        conn.commit()
        conn.close()

    def _init_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY, software_type TEXT, software_slug TEXT,
                version_from TEXT, version_to TEXT, cvss_score REAL,
                severity TEXT, title TEXT, description TEXT, remediation TEXT,
                "references" TEXT, has_exploit INTEGER, published_at TEXT
            );
            CREATE TABLE IF NOT EXISTS plugins_wordlist (
                slug TEXT PRIMARY KEY, last_updated TEXT, active_installs INTEGER
            );
            CREATE TABLE IF NOT EXISTS themes_wordlist (
                slug TEXT PRIMARY KEY, last_updated TEXT
            );
        """)
        return conn

    async def _fetch_nvd(self, client: httpx.AsyncClient, conn: sqlite3.Connection) -> None:
        params: dict[str, str | int] = {"keywordSearch": "wordpress", "resultsPerPage": 2000, "startIndex": 0}
        r = await client.get(NVD_BASE, params=params)
        data = r.json()
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
            metrics = cve.get("metrics", {})
            cvss = None
            severity = "MEDIUM"
            if v31 := metrics.get("cvssMetricV31"):
                cvss = v31[0]["cvssData"]["baseScore"]
                severity = v31[0]["cvssData"]["baseSeverity"]
            refs = [r["url"] for r in cve.get("references", [])]
            conn.execute(
                "INSERT OR REPLACE INTO vulnerabilities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (cve_id, "core", "wordpress", "0.0.1", "99.99.99", cvss, severity,
                 f"WordPress vulnerability: {cve_id}", desc, "Update WordPress to the latest version.",
                 json.dumps(refs), 0, cve.get("published", ""))
            )

    async def _fetch_plugin_wordlist(self, client: httpx.AsyncClient, conn: sqlite3.Connection) -> None:
        r = await client.get(WP_PLUGINS_API.format(page=1))
        data = r.json()
        for slug in data.get("plugins", {}).keys():
            conn.execute(
                "INSERT OR REPLACE INTO plugins_wordlist VALUES (?,?,?)",
                (slug, "", 0)
            )
