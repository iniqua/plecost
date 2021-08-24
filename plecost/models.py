from typing import List
from dataclasses import dataclass, field


@dataclass
class WordpressVersion:
    status: str  # insecure | outdated | latest
    installed_version: str
    latest_version: str


@dataclass
class PlecostRunningOptions:
    target: str
    concurrency: int = 4
    report_filename: str = None
    proxy: dict = field(default_factory=dict)
    no_check_plugins: bool = False
    no_check_wordpress: bool = False
    no_check_wordpress_version: bool = False
    force_scan: bool = False
    jackass: bool = False
