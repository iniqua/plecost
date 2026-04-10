from __future__ import annotations
from abc import ABC, abstractmethod
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient


class ScanModule(ABC):
    name: str = ""
    depends_on: list[str] = []

    @abstractmethod
    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None: ...
