from __future__ import annotations
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    id: str                      # "PC-MCFG-001" — stable permanent ID
    remediation_id: str          # "REM-MCFG-001" — stable permanent ID
    title: str
    severity: Severity
    description: str
    evidence: dict[str, Any]
    remediation: str
    references: list[str]
    cvss_score: float | None
    module: str


@dataclass
class Plugin:
    slug: str
    version: str | None
    latest_version: str | None
    url: str
    outdated: bool = False
    abandoned: bool = False


@dataclass
class Theme:
    slug: str
    version: str | None
    latest_version: str | None
    url: str
    outdated: bool = False
    active: bool = True


@dataclass
class User:
    id: int | None
    username: str
    display_name: str | None
    source: str  # "rest_api", "author_archive", "rss", "oEmbed"


@dataclass
class ScanSummary:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


@dataclass
class ScanResult:
    scan_id: str
    url: str
    timestamp: datetime
    duration_seconds: float
    is_wordpress: bool
    wordpress_version: str | None
    plugins: list[Plugin]
    themes: list[Theme]
    users: list[User]
    waf_detected: str | None
    findings: list[Finding]
    summary: ScanSummary

    def to_json(self, path: str) -> None:
        def default(obj: Any) -> Any:
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, Enum):
                return obj.value
            raise TypeError(f"Not serializable: {type(obj)}")
        with open(path, "w") as f:
            json.dump(asdict(self), f, indent=2, default=default)


@dataclass
class ScanOptions:
    url: str
    concurrency: int = 10
    timeout: int = 10
    proxy: str | None = None
    modules: list[str] | None = None   # None = all modules
    skip_modules: list[str] = field(default_factory=list)
    credentials: tuple[str, str] | None = None
    stealth: bool = False
    aggressive: bool = False
    user_agent: str = "Plecost/4.0"
    random_user_agent: bool = False
    verify_ssl: bool = True
    force: bool = False
    output: str | None = None
