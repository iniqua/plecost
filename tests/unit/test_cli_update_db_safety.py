"""
Tests for update-db safety hardening in cli.py.

AC-1 (G-024): File lock prevents concurrent update-db runs
AC-2 (G-006): Plain sqlite:// URL rejected with clear error message
AC-3 (G-004): CISA KEV sync marks has_exploit=True for matching CVEs
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from io import StringIO

import pytest
import httpx
import respx
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from typer.testing import CliRunner

from plecost.cli import app, _acquire_db_lock, _release_db_lock, _sync_cisa_kev
from plecost.database.models import Base, NormalizedVuln

runner = CliRunner()

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _make_sf():
    """Create an in-memory SQLite session factory with the full schema."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    return engine, sf


async def _seed_vulns(sf, cve_ids: list[str]) -> None:
    """Insert NormalizedVuln rows for the given CVE IDs (has_exploit=False)."""
    async with sf() as session:
        for cve_id in cve_ids:
            session.add(NormalizedVuln(
                cve_id=cve_id,
                software_type="plugin",
                slug="some-plugin",
                severity="HIGH",
                cvss_score=7.5,
                match_confidence=1.0,
                has_exploit=False,
            ))
        await session.commit()


async def _count_exploited(sf) -> int:
    """Return number of NormalizedVuln rows with has_exploit=True."""
    from sqlalchemy import select
    async with sf() as session:
        result = await session.execute(
            select(NormalizedVuln).where(NormalizedVuln.has_exploit == True)  # noqa: E712
        )
        return len(result.scalars().all())


# ---------------------------------------------------------------------------
# AC-1: File lock tests
# ---------------------------------------------------------------------------

class TestFileLock:
    def test_acquire_and_release(self, tmp_path):
        """Lock can be acquired and released cleanly."""
        lock_path = tmp_path / "test.lock"
        lock_file = _acquire_db_lock(lock_path)
        assert lock_path.exists()
        _release_db_lock(lock_file, lock_path)
        assert not lock_path.exists()

    @pytest.mark.skipif(sys.platform == "win32", reason="fcntl not available on Windows")
    def test_second_acquire_raises_runtime_error(self, tmp_path):
        """A second acquire on the same lockfile raises RuntimeError immediately."""
        import fcntl
        lock_path = tmp_path / "test.lock"
        lock_file = _acquire_db_lock(lock_path)
        try:
            with pytest.raises(RuntimeError, match="Another update-db process is running"):
                _acquire_db_lock(lock_path)
        finally:
            _release_db_lock(lock_file, lock_path)

    @pytest.mark.skipif(sys.platform == "win32", reason="fcntl not available on Windows")
    def test_lock_released_after_first_holder_exits(self, tmp_path):
        """After releasing, a fresh acquire succeeds."""
        lock_path = tmp_path / "test.lock"
        lock_file1 = _acquire_db_lock(lock_path)
        _release_db_lock(lock_file1, lock_path)
        # Second acquire must succeed now
        lock_file2 = _acquire_db_lock(lock_path)
        _release_db_lock(lock_file2, lock_path)

    def test_update_db_cli_lock_error_prints_and_exits(self, tmp_path):
        """When lock acquisition fails, CLI prints an error and exits 1."""
        db_path = tmp_path / "plecost.db"
        lock_path = tmp_path / "plecost.lock"

        # Simulate lock already held by making _acquire_db_lock raise
        with patch("plecost.cli._acquire_db_lock", side_effect=RuntimeError("lock held")):
            result = runner.invoke(app, [
                "update-db",
                "--db-url", f"sqlite+aiosqlite:///{db_path}",
            ])
        assert result.exit_code == 1
        assert "lock held" in result.output or "Error" in result.output


# ---------------------------------------------------------------------------
# AC-2: URL validation tests
# ---------------------------------------------------------------------------

class TestURLValidation:
    def test_plain_sqlite_url_rejected(self, tmp_path):
        """sqlite:// (without +aiosqlite) is rejected with a clear error."""
        result = runner.invoke(app, [
            "update-db",
            "--db-url", "sqlite:///some/path/db.sqlite",
        ])
        assert result.exit_code == 1
        assert "sqlite+aiosqlite" in result.output
        assert "sqlite://" in result.output or "async SQLite" in result.output

    def test_plain_sqlite_url_from_env_rejected(self, tmp_path, monkeypatch):
        """sqlite:// via PLECOST_DB_URL env var is also rejected."""
        monkeypatch.setenv("PLECOST_DB_URL", "sqlite:///some/path/db.sqlite")
        result = runner.invoke(app, ["update-db"])
        assert result.exit_code == 1
        assert "sqlite+aiosqlite" in result.output

    def test_sqlite_aiosqlite_url_passes_validation(self, tmp_path):
        """sqlite+aiosqlite:// passes the URL check (may fail later on network, that's ok)."""
        db_path = tmp_path / "test.db"
        # Patch _acquire_db_lock to avoid creating real files and
        # mock asyncio.run to avoid real network calls
        with patch("plecost.cli._acquire_db_lock") as mock_lock, \
             patch("plecost.cli._release_db_lock"), \
             patch("asyncio.run", side_effect=SystemExit(0)):
            mock_lock.return_value = MagicMock()
            result = runner.invoke(app, [
                "update-db",
                "--db-url", f"sqlite+aiosqlite:///{db_path}",
            ])
        # Should NOT show the URL-validation error message
        assert "Use 'sqlite+aiosqlite" not in result.output

    def test_postgresql_url_rejected_with_different_message(self, tmp_path):
        """postgresql+asyncpg:// is rejected with a different message (not the sqlite:// check)."""
        result = runner.invoke(app, [
            "update-db",
            "--db-url", "postgresql+asyncpg://user:pass@localhost/db",
        ])
        assert result.exit_code == 1
        # Must NOT show the sqlite-specific validation error
        assert "Use 'sqlite+aiosqlite" not in result.output
        # Should show the update-db-only-sqlite message
        assert "SQLite" in result.output or "sqlite" in result.output.lower()


# ---------------------------------------------------------------------------
# AC-3: CISA KEV sync tests
# ---------------------------------------------------------------------------

class TestCisaKevSync:
    @respx.mock
    async def test_marks_matching_cves_as_has_exploit(self):
        """CVEs present in both local DB and KEV catalog get has_exploit=True."""
        engine, sf = await _make_sf()
        try:
            await _seed_vulns(sf, ["CVE-2021-44228", "CVE-2021-45046", "CVE-2022-99999"])

            kev_payload = {
                "vulnerabilities": [
                    {"cveID": "CVE-2021-44228", "vulnerabilityName": "Log4Shell"},
                    {"cveID": "CVE-2021-45046", "vulnerabilityName": "Log4Shell 2"},
                    {"cveID": "CVE-2000-00001", "vulnerabilityName": "Old CVE not in DB"},
                ]
            }
            respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=kev_payload))
            respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

            await _sync_cisa_kev(sf)

            count = await _count_exploited(sf)
            assert count == 2  # CVE-2021-44228 and CVE-2021-45046
        finally:
            await engine.dispose()

    @respx.mock
    async def test_no_match_emits_no_error(self):
        """If no KEV CVEs match the local DB, no exception is raised."""
        engine, sf = await _make_sf()
        try:
            await _seed_vulns(sf, ["CVE-2023-00001"])

            kev_payload = {
                "vulnerabilities": [
                    {"cveID": "CVE-2099-99999", "vulnerabilityName": "Future CVE"},
                ]
            }
            respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=kev_payload))
            respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

            # Must not raise
            await _sync_cisa_kev(sf)

            count = await _count_exploited(sf)
            assert count == 0
        finally:
            await engine.dispose()

    @respx.mock
    async def test_api_failure_does_not_crash(self):
        """If the CISA API is unavailable, _sync_cisa_kev returns without raising."""
        engine, sf = await _make_sf()
        try:
            await _seed_vulns(sf, ["CVE-2021-44228"])

            # Simulate network error
            respx.get(KEV_URL).mock(side_effect=httpx.ConnectError("connection refused"))
            respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

            # Must not raise — warning is printed internally
            await _sync_cisa_kev(sf)

            count = await _count_exploited(sf)
            assert count == 0  # DB unchanged
        finally:
            await engine.dispose()

    @respx.mock
    async def test_api_http_error_does_not_crash(self):
        """If the CISA API returns an HTTP error, function returns gracefully."""
        engine, sf = await _make_sf()
        try:
            await _seed_vulns(sf, ["CVE-2021-44228"])

            respx.get(KEV_URL).mock(return_value=httpx.Response(503))
            respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

            await _sync_cisa_kev(sf)

            count = await _count_exploited(sf)
            assert count == 0
        finally:
            await engine.dispose()

    @respx.mock
    async def test_empty_vulnerabilities_list_does_not_crash(self):
        """An empty vulnerabilities list in the KEV response is handled gracefully."""
        engine, sf = await _make_sf()
        try:
            await _seed_vulns(sf, ["CVE-2021-44228"])

            respx.get(KEV_URL).mock(return_value=httpx.Response(200, json={"vulnerabilities": []}))
            respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

            await _sync_cisa_kev(sf)

            count = await _count_exploited(sf)
            assert count == 0
        finally:
            await engine.dispose()

    @respx.mock
    async def test_does_not_overwrite_existing_false_for_non_kev_cves(self):
        """CVEs NOT in the KEV catalog remain has_exploit=False."""
        engine, sf = await _make_sf()
        try:
            await _seed_vulns(sf, ["CVE-2021-44228", "CVE-2023-99999"])

            kev_payload = {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}
            respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=kev_payload))
            respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

            await _sync_cisa_kev(sf)

            # Only the KEV CVE should be marked
            count = await _count_exploited(sf)
            assert count == 1
        finally:
            await engine.dispose()
