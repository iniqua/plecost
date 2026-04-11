from __future__ import annotations
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker, AsyncEngine


def make_engine(db_url: str) -> AsyncEngine:
    """
    db_url:
      SQLite:     "sqlite+aiosqlite:////home/user/.plecost/plecost.db"
      PostgreSQL: "postgresql+asyncpg://user:pass@host/plecost"
    """
    kwargs: dict = {"echo": False}
    if db_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_async_engine(db_url, **kwargs)


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)
