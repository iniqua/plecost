from __future__ import annotations
from abc import ABC, abstractmethod
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding


class BaseDetector(ABC):
    """Base class for all webshell detection strategies."""

    name: str = ""
    requires_auth: bool = False

    @abstractmethod
    async def detect(
        self, ctx: ScanContext, http: PlecostHTTPClient
    ) -> list[Finding]: ...

    async def _detect_catch_all(
        self,
        http: PlecostHTTPClient,
        probe_url_a: str,
        probe_url_b: str,
        tolerance: float = 0.05,
    ) -> int | None:
        """
        Sends two requests to invented paths. If both return HTTP 200 and their
        response sizes differ by less than `tolerance` (default 5%), the server
        is a catch-all. Returns the reference size; returns None if not catch-all.
        """
        try:
            r_a = await http.get(probe_url_a)
            if r_a.status_code != 200:
                return None
            r_b = await http.get(probe_url_b)
            if r_b.status_code != 200:
                return None
            size_a = len(r_a.content)
            size_b = len(r_b.content)
            if size_a == 0 and size_b == 0:
                return 0
            max_size = max(size_a, size_b)
            if abs(size_a - size_b) / max_size < tolerance:
                return size_a
            return None
        except Exception:
            return None
