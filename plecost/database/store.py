from __future__ import annotations
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from packaging.version import Version, InvalidVersion


@dataclass
class VulnerabilityRecord:
    cve_id: str
    software_type: str
    software_slug: str
    version_from: str
    version_to: str
    cvss_score: float | None
    severity: str
    title: str
    description: str
    remediation: str
    references: list[str]
    has_exploit: bool
    published_at: str


class CVEStore:
    def __init__(self, db_path: str) -> None:
        if not Path(db_path).exists():
            from plecost.exceptions import DatabaseNotFoundError
            raise DatabaseNotFoundError(f"CVE database not found at {db_path}. Run: plecost update-db")
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def find(self, software_type: str, slug: str, installed_version: str) -> list[VulnerabilityRecord]:
        rows = self._conn.execute(
            "SELECT * FROM vulnerabilities WHERE software_type=? AND software_slug=?",
            (software_type, slug)
        ).fetchall()
        results = []
        try:
            iv = Version(installed_version)
        except InvalidVersion:
            return []
        for row in rows:
            try:
                if Version(row["version_from"]) <= iv <= Version(row["version_to"]):
                    results.append(VulnerabilityRecord(
                        cve_id=row["id"], software_type=row["software_type"],
                        software_slug=row["software_slug"], version_from=row["version_from"],
                        version_to=row["version_to"], cvss_score=row["cvss_score"],
                        severity=row["severity"], title=row["title"],
                        description=row["description"], remediation=row["remediation"],
                        references=json.loads(row["references"] or "[]"),
                        has_exploit=bool(row["has_exploit"]), published_at=row["published_at"]
                    ))
            except InvalidVersion:
                continue
        return results

    def get_plugins_wordlist(self) -> list[str]:
        try:
            rows = self._conn.execute("SELECT slug FROM plugins_wordlist").fetchall()
            return [r["slug"] for r in rows]
        except Exception:
            return []

    def get_themes_wordlist(self) -> list[str]:
        try:
            rows = self._conn.execute("SELECT slug FROM themes_wordlist").fetchall()
            return [r["slug"] for r in rows]
        except Exception:
            return []
