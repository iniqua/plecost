from __future__ import annotations
import threading
from plecost.models import ScanOptions, Finding, Plugin, Theme, User


class ScanContext:
    """Shared state for all scan modules. Thread-safe."""

    def __init__(self, opts: ScanOptions) -> None:
        self.opts = opts
        self.url = opts.url.rstrip("/")
        self.is_wordpress: bool = False
        self.wordpress_version: str | None = None
        self.waf_detected: str | None = None
        self.plugins: list[Plugin] = []
        self.themes: list[Theme] = []
        self.users: list[User] = []
        self.findings: list[Finding] = []
        self._lock = threading.Lock()

    def add_finding(self, finding: Finding) -> None:
        with self._lock:
            self.findings.append(finding)

    def add_plugin(self, plugin: Plugin) -> None:
        with self._lock:
            self.plugins.append(plugin)

    def add_theme(self, theme: Theme) -> None:
        with self._lock:
            self.themes.append(theme)

    def add_user(self, user: User) -> None:
        with self._lock:
            self.users.append(user)
