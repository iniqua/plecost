from __future__ import annotations
import json
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


_CATEGORY_EXACT: dict[str, str] = {
    # credentials / secrets
    "PC-MCFG-001": "credentials_exposed",
    "PC-MCFG-002": "credentials_exposed",
    "PC-MCFG-003": "credentials_exposed",
    # source code
    "PC-MCFG-004": "source_code_exposed",
    # debug
    "PC-MCFG-005": "debug_exposure",
    "PC-DBG-001":  "debug_exposure",
    # backups
    "PC-MCFG-006": "backup_files",
    # admin scripts
    "PC-MCFG-007": "admin_scripts",
    "PC-MCFG-008": "admin_scripts",
    # version disclosure
    "PC-MCFG-009": "version_disclosure",
    "PC-MCFG-010": "version_disclosure",
    "PC-MCFG-011": "version_disclosure",
    "PC-HDR-007":  "version_disclosure",
    "PC-HDR-008":  "version_disclosure",
    "PC-DBG-003":  "version_disclosure",
    "PC-FP-001":   "version_disclosure",
    "PC-FP-002":   "version_disclosure",
    # attack surface
    "PC-MCFG-012": "attack_surface",
    # http security headers
    "PC-HDR-001": "hsts",
    "PC-HDR-002": "clickjacking",
    "PC-HDR-003": "http_headers",
    "PC-HDR-004": "content_security_policy",
    "PC-HDR-005": "http_headers",
    "PC-HDR-006": "http_headers",
    # ssl/tls
    "PC-SSL-001": "ssl_redirect",
    "PC-SSL-002": "ssl_certificate",
    "PC-SSL-003": "hsts",
    # authentication
    "PC-AUTH-001": "authentication",
    "PC-AUTH-002": "open_registration",
    # woocommerce
    "PC-WC-004": "woocommerce_api_exposure",
    "PC-WC-005": "woocommerce_api_exposure",
    "PC-WC-006": "woocommerce_api_exposure",
    "PC-WC-007": "woocommerce_api_exposure",
    "PC-WC-013": "woocommerce_api_exposure",
    "PC-WC-020": "woocommerce_cve",
    "PC-WC-021": "woocommerce_cve",
    # wp-ecommerce cves
    "PC-WPEC-020": "wp_ecommerce_cve",
    "PC-WPEC-021": "wp_ecommerce_cve",
    # content / malicious code
    "PC-CNT-001": "card_skimmer",
    "PC-CNT-002": "suspicious_content",
    "PC-CNT-003": "suspicious_content",
}

_CATEGORY_PREFIXES: list[tuple[str, str]] = [
    ("PC-DIR-",   "directory_listing"),
    ("PC-USR-",   "user_enumeration"),
    ("PC-XMLRPC-","xmlrpc"),
    ("PC-REST-",  "rest_api_exposure"),
    ("PC-WAF-",   "waf_detected"),
    ("PC-WC-",    "woocommerce_detection"),
    ("PC-WPEC-",  "wp_ecommerce"),
    ("PC-MGC-",   "card_skimmer"),
    ("PC-WSH-",   "webshell"),
    ("PC-CVE-",   "cve"),
    ("PC-PRE-",   "infrastructure"),
]


def derive_finding_category(finding_id: str) -> str:
    if finding_id in _CATEGORY_EXACT:
        return _CATEGORY_EXACT[finding_id]
    for prefix, category in _CATEGORY_PREFIXES:
        if finding_id.startswith(prefix):
            return category
    return "other"


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
    category: str = field(default="")

    def __post_init__(self) -> None:
        if not self.category:
            self.category = derive_finding_category(self.id)


@dataclass
class PluginVuln:
    cve_id: str
    title: str
    severity: str          # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    cvss_score: float | None
    has_exploit: bool
    version_range: str     # e.g. "1.0.0–2.3.4" or "*–*"
    description: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class Plugin:
    slug: str
    version: str | None
    latest_version: str | None
    url: str
    outdated: bool = False
    abandoned: bool = False
    vulns: list[PluginVuln] = field(default_factory=list)

    @property
    def vuln_count(self) -> int:
        return len(self.vulns)


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
class WooCommerceInfo:
    detected: bool
    version: str | None
    active_plugins: list[str]   # e.g. ["core", "payments", "blocks", "stripe-gateway"]
    api_namespaces: list[str]   # e.g. ["wc/v3", "wc/store/v1"]


@dataclass
class WPECommerceInfo:
    detected: bool
    version: str | None
    active_gateways: list[str]   # e.g. ["chronopay"]
    checks_run: list[str]        # e.g. ["readme", "dir_listing", "cve_sqli"]


@dataclass
class MagecartInfo:
    detected: bool
    pages_scanned: list[str]
    scripts_analyzed: int
    malicious_domains: list[str]


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
    blocked: bool = False
    woocommerce: WooCommerceInfo | None = None
    wp_ecommerce: WPECommerceInfo | None = None
    magecart: MagecartInfo | None = None

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
    deep: bool = False  # False = fast mode (top 150 plugins, top 50 themes); True = full wordlist
    output: str | None = None
    db_url: str | None = None  # None = default SQLite at ~/.plecost/db/plecost.db
    module_options: dict[str, dict[str, str]] = field(default_factory=dict)
