from __future__ import annotations
from sqlalchemy import String, Float, Boolean, Integer, Text, Index, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class NormalizedVuln(Base):
    """One row per (cve_id, slug). Main lookup table at scan time."""
    __tablename__ = "normalized_vulns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String(30), index=True)
    software_type: Mapped[str] = mapped_column(String(20))  # "core", "plugin", "theme"
    slug: Mapped[str] = mapped_column(String(255), index=True)
    cpe_vendor: Mapped[str] = mapped_column(String(255), default="")
    cpe_product: Mapped[str] = mapped_column(String(255), default="")
    match_confidence: Mapped[float] = mapped_column(Float, default=1.0)  # 1.0=exact, <1=fuzzy
    version_start_incl: Mapped[str | None] = mapped_column(String(50), nullable=True)
    version_start_excl: Mapped[str | None] = mapped_column(String(50), nullable=True)
    version_end_incl: Mapped[str | None] = mapped_column(String(50), nullable=True)
    version_end_excl: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM")
    title: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    references_json: Mapped[str] = mapped_column(Text, default="[]")
    has_exploit: Mapped[bool] = mapped_column(Boolean, default=False)
    published_at: Mapped[str] = mapped_column(String(30), default="")

    __table_args__ = (
        UniqueConstraint("cve_id", "slug", name="uq_cve_slug"),
        Index("idx_slug_type", "slug", "software_type"),
    )


class PluginsWordlist(Base):
    __tablename__ = "plugins_wordlist"
    slug: Mapped[str] = mapped_column(String(255), primary_key=True)
    last_updated: Mapped[str] = mapped_column(String(30), default="")
    active_installs: Mapped[int] = mapped_column(Integer, default=0)


class ThemesWordlist(Base):
    __tablename__ = "themes_wordlist"
    slug: Mapped[str] = mapped_column(String(255), primary_key=True)
    last_updated: Mapped[str] = mapped_column(String(30), default="")


class DbMetadata(Base):
    """Database metadata: last synchronization, version, etc."""
    __tablename__ = "db_metadata"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


class RejectedCve(Base):
    """CVEs rejected or deleted from NVD. Never physically delete - mark here instead."""
    __tablename__ = "rejected_cves"

    cve_id: Mapped[str] = mapped_column(String(30), primary_key=True)
    reason: Mapped[str] = mapped_column(String(50), default="deleted")  # "deleted", "disputed", "false_positive"
    rejected_at: Mapped[str] = mapped_column(String(30), default="")
