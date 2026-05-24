"""Base attacker ABC for the brute module."""
from __future__ import annotations

from abc import ABC, abstractmethod

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding


class BaseAttacker(ABC):
    """Abstract base for credential attack strategies."""

    @abstractmethod
    async def attack(
        self,
        ctx: ScanContext,
        http: PlecostHTTPClient,
        usernames: list[str],
        passwords: list[str],
    ) -> list[Finding]:
        """
        Attempt credentials against target.
        Returns a list of findings (empty if none found or rate-limited).
        """
