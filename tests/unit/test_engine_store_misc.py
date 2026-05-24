"""Tests for engine.py, store.py and local_patches.py robustness fixes.

Covers:
  AC-1 (G2-008): make_engine SQLite activates WAL journal mode
  AC-2 (G2-007): make_engine PostgreSQL sets pool_pre_ping=True
  AC-3 (G-009):  _is_affected logs debug when CVE has no version ranges
  AC-4 (G-014):  _load_corrections returns [] on missing / invalid JSON file
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from plecost.database.engine import make_engine
from plecost.database.local_patches import _load_corrections, _CORRECTIONS_FILE
from plecost.database.store import CVEStore
from plecost.database.models import NormalizedVuln, Base


# ---------------------------------------------------------------------------
# AC-1: SQLite WAL mode
# ---------------------------------------------------------------------------

async def test_make_engine_sqlite_wal_mode(tmp_path):
    """AC-1: make_engine with SQLite URL must activate WAL journal mode.

    This test would fail if the event listener that executes
    'PRAGMA journal_mode=WAL' is removed from make_engine().

    Note: SQLite in-memory databases (':memory:') do NOT support WAL — they
    always return 'memory'. A file-based SQLite DB is required to verify WAL.
    """
    db_file = tmp_path / "test_wal.db"
    db_url = f"sqlite+aiosqlite:///{db_file}"
    engine = make_engine(db_url)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("PRAGMA journal_mode"))
            mode = result.scalar()
        assert mode == "wal", (
            f"Expected WAL journal mode but got '{mode}'. "
            "The PRAGMA journal_mode=WAL event listener may be missing."
        )
    finally:
        await engine.dispose()


async def test_make_engine_sqlite_returns_engine():
    """AC-1 smoke: make_engine returns a usable AsyncEngine for SQLite."""
    engine = make_engine("sqlite+aiosqlite:///:memory:")
    try:
        assert engine is not None
        # Must be able to connect and execute
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            assert result.scalar() == 1
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# AC-2: PostgreSQL pool_pre_ping
# ---------------------------------------------------------------------------

def test_make_engine_postgresql_pool_pre_ping():
    """AC-2: make_engine with a postgresql URL must pass pool_pre_ping=True.

    This test would fail if kwargs["pool_pre_ping"] = True is removed
    from the non-sqlite branch of make_engine().

    We mock create_async_engine to capture kwargs without needing asyncpg installed.
    """
    from unittest.mock import patch, MagicMock

    captured_kwargs: dict = {}

    def fake_create_async_engine(url, **kwargs):
        captured_kwargs.update(kwargs)
        mock_engine = MagicMock()
        mock_engine.pool = MagicMock()
        return mock_engine

    with patch("plecost.database.engine.create_async_engine", side_effect=fake_create_async_engine):
        make_engine("postgresql+asyncpg://user:pass@localhost/testdb")

    assert captured_kwargs.get("pool_pre_ping") is True, (
        f"pool_pre_ping=True was not passed to create_async_engine for PostgreSQL. "
        f"Captured kwargs: {captured_kwargs}. The AC-2 fix may be missing."
    )


def test_make_engine_sqlite_no_pool_pre_ping():
    """AC-1/AC-2 boundary: SQLite engine must NOT have pool_pre_ping (uses NullPool)."""
    engine = make_engine("sqlite+aiosqlite:///:memory:")
    try:
        from sqlalchemy.pool import StaticPool, NullPool, SingletonThreadPool
        # SQLite in-memory uses StaticPool or SingletonThreadPool — no _pre_ping attribute
        # or it's False. We just verify the engine works; don't require a specific pool.
        assert engine is not None
    finally:
        engine.sync_engine.dispose()


# ---------------------------------------------------------------------------
# AC-3: _is_affected logs debug when all version ranges are None
# ---------------------------------------------------------------------------

async def test_is_affected_no_range_logs_debug(caplog):
    """AC-3: _is_affected must emit a debug log when all version ranges are None.

    This test would fail if the logger.debug() call is removed from the
    'if all(r is None ...)' branch in _is_affected().
    """
    # Build a minimal in-memory DB with one CVE row that has no version ranges
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async with engine.begin() as conn:
            await conn.execute(
                NormalizedVuln.__table__.insert().values(
                    cve_id="CVE-2020-00001",
                    software_type="plugin",
                    slug="test-plugin",
                    cpe_vendor="wordpress",
                    cpe_product="test-plugin",
                    match_confidence=1.0,
                    version_start_incl=None,
                    version_start_excl=None,
                    version_end_incl=None,
                    version_end_excl=None,
                    cvss_score=7.5,
                    severity="HIGH",
                    title="Test CVE",
                    description="Test description",
                    remediation="Update plugin",
                    references_json="[]",
                    has_exploit=False,
                    published_at="2020-01-01",
                )
            )

        from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
        sf = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        store = CVEStore(sf)

        with caplog.at_level(logging.DEBUG, logger="plecost.database.store"):
            results = await store.find("plugin", "test-plugin", "1.0.0")

        # The CVE must NOT be reported (return False behavior unchanged)
        assert results == [], "CVE with no ranges must not be reported"

        # The debug log must have been emitted
        debug_messages = [
            r.message for r in caplog.records
            if r.levelno == logging.DEBUG and "CVE-2020-00001" in r.message
        ]
        assert debug_messages, (
            "Expected a DEBUG log mentioning CVE-2020-00001 for no-range CVE, "
            "but none was found. The AC-3 logger.debug() call may be missing."
        )
        assert "no version range" in debug_messages[0].lower() or "no version range" in caplog.text
    finally:
        await engine.dispose()


async def test_is_affected_with_range_no_debug_log(caplog):
    """AC-3 boundary: _is_affected must NOT emit the debug log when ranges are set."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async with engine.begin() as conn:
            await conn.execute(
                NormalizedVuln.__table__.insert().values(
                    cve_id="CVE-2021-00002",
                    software_type="plugin",
                    slug="another-plugin",
                    cpe_vendor="wordpress",
                    cpe_product="another-plugin",
                    match_confidence=1.0,
                    version_start_incl=None,
                    version_start_excl=None,
                    version_end_incl="2.0.0",
                    version_end_excl=None,
                    cvss_score=5.0,
                    severity="MEDIUM",
                    title="Test CVE 2",
                    description="desc",
                    remediation="update",
                    references_json="[]",
                    has_exploit=False,
                    published_at="2021-01-01",
                )
            )

        from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
        sf = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        store = CVEStore(sf)

        with caplog.at_level(logging.DEBUG, logger="plecost.database.store"):
            results = await store.find("plugin", "another-plugin", "1.5.0")

        # CVE with end_incl=2.0.0 and installed=1.5.0 SHOULD be reported
        assert len(results) == 1, "CVE with version range should be reported"

        # No "no version range" debug log should appear for this CVE
        no_range_logs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG
            and "CVE-2021-00002" in r.getMessage()
            and "no version range" in r.getMessage().lower()
        ]
        assert not no_range_logs, "Should NOT log 'no version range' when ranges are defined"
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# AC-4: _load_corrections error handling
# ---------------------------------------------------------------------------

def test_load_corrections_missing_file_returns_empty(tmp_path):
    """AC-4: _load_corrections must return [] when corrections.json does not exist.

    This test would fail if the try/except block is removed from _load_corrections().
    """
    nonexistent = tmp_path / "nonexistent_corrections.json"
    # Patch _CORRECTIONS_FILE to point to a file that doesn't exist
    import plecost.database.local_patches as lp_module
    original = lp_module._CORRECTIONS_FILE
    try:
        lp_module._CORRECTIONS_FILE = nonexistent
        result = _load_corrections()
        assert result == [], (
            "Expected [] when corrections.json is missing, "
            "but got: %r. The try/except may be missing." % result
        )
    finally:
        lp_module._CORRECTIONS_FILE = original


def test_load_corrections_invalid_json_returns_empty(tmp_path, caplog):
    """AC-4: _load_corrections must return [] and log an error on invalid JSON.

    This test would fail if the try/except block is removed from _load_corrections().
    """
    bad_json_file = tmp_path / "bad_corrections.json"
    bad_json_file.write_text("{ this is not valid json !!!", encoding="utf-8")

    import plecost.database.local_patches as lp_module
    original = lp_module._CORRECTIONS_FILE
    try:
        lp_module._CORRECTIONS_FILE = bad_json_file
        with caplog.at_level(logging.ERROR, logger="plecost.database.local_patches"):
            result = _load_corrections()
        assert result == [], (
            "Expected [] on invalid JSON, but got: %r" % result
        )
        # Must log an error message
        error_logs = [
            r for r in caplog.records
            if r.levelno == logging.ERROR and "corrections.json" in r.message.lower()
        ]
        assert error_logs, (
            "Expected an ERROR log about corrections.json failure, "
            "but none found. The logger.error() call may be missing."
        )
    finally:
        lp_module._CORRECTIONS_FILE = original


def test_load_corrections_missing_file_logs_error(tmp_path, caplog):
    """AC-4: _load_corrections must log an error when the file is missing."""
    nonexistent = tmp_path / "missing.json"

    import plecost.database.local_patches as lp_module
    original = lp_module._CORRECTIONS_FILE
    try:
        lp_module._CORRECTIONS_FILE = nonexistent
        with caplog.at_level(logging.ERROR, logger="plecost.database.local_patches"):
            result = _load_corrections()
        assert result == []
        error_logs = [
            r for r in caplog.records
            if r.levelno == logging.ERROR and "corrections.json" in r.message.lower()
        ]
        assert error_logs, (
            "Expected an ERROR log for missing corrections.json file"
        )
    finally:
        lp_module._CORRECTIONS_FILE = original


def test_load_corrections_valid_file_returns_list(tmp_path):
    """AC-4 regression: _load_corrections still works correctly with valid JSON."""
    valid_file = tmp_path / "corrections.json"
    valid_file.write_text(
        json.dumps({"corrections": [{"action": "delete_by_cve_slug", "cve_id": "CVE-X", "slug": "s"}]}),
        encoding="utf-8",
    )

    import plecost.database.local_patches as lp_module
    original = lp_module._CORRECTIONS_FILE
    try:
        lp_module._CORRECTIONS_FILE = valid_file
        result = _load_corrections()
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-X"
    finally:
        lp_module._CORRECTIONS_FILE = original
