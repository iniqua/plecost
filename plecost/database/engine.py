from __future__ import annotations

from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def make_engine(db_url: str) -> AsyncEngine:
    """
    db_url:
      SQLite:     "sqlite+aiosqlite:////home/user/.plecost/plecost.db"
      PostgreSQL: "postgresql+asyncpg://user:pass@host/plecost"
    """
    kwargs: dict[str, Any] = {"echo": False}
    if db_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        engine = create_async_engine(db_url, **kwargs)

        # AC-1: WAL mode reduces SQLITE_BUSY under concurrent reads (run_many)
        @event.listens_for(engine.sync_engine, "connect")
        def set_wal_mode(dbapi_conn, connection_record):  # type: ignore[no-untyped-def]
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

        return engine
    else:
        # AC-2: pool_pre_ping detects stale PostgreSQL connections before use
        kwargs["pool_pre_ping"] = True
        return create_async_engine(db_url, **kwargs)


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)
