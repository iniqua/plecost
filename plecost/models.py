from typing import List
from dataclasses import dataclass


@dataclass
class WordpressPlugin:
    name: str
    slug: str
    latest_version: str

@dataclass
class CPE:
    cpe: str
    vulnerable: bool
    version_end_including: str or None = None
    version_end_excluding: str or None = None
    version_start_including: str or None = None
    version_start_excluding: str or None = None

@dataclass
class CVEInfo:
    cve: str
    description: str
    cpes: List[CPE]
    cvss: float or None
