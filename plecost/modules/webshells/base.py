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
