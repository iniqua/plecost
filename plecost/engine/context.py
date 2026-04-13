from __future__ import annotations
import threading
from collections.abc import Callable
from plecost.models import ScanOptions, Finding, Plugin, Theme, User


class ScanContext:
    """Shared state for all scan modules. Thread-safe."""

    def __init__(self, opts: ScanOptions, on_finding: Callable[[Finding], None] | None = None) -> None:
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
        self._on_finding = on_finding

    def add_finding(self, finding: Finding) -> None:
        with self._lock:
            self.findings.append(finding)
        if self._on_finding:
            self._on_finding(finding)

    def add_plugin(self, plugin: Plugin) -> None:
        with self._lock:
            self.plugins.append(plugin)

    def add_theme(self, theme: Theme) -> None:
        with self._lock:
            self.themes.append(theme)

    def add_user(self, user: User) -> None:
        with self._lock:
            self.users.append(user)
