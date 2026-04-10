from __future__ import annotations
import random
from typing import Any
import httpx
from plecost.models import ScanOptions

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
]


class PlecostHTTPClient:
    def __init__(self, opts: ScanOptions) -> None:
        self._opts = opts
        ua = random.choice(_USER_AGENTS) if (opts.stealth or opts.random_user_agent) else opts.user_agent
        limits = httpx.Limits(
            max_connections=opts.concurrency,
            max_keepalive_connections=opts.concurrency,
        )
        self._client = httpx.AsyncClient(
            timeout=opts.timeout,
            verify=opts.verify_ssl,
            proxy=opts.proxy,
            limits=limits,
            headers={"user-agent": ua},
            follow_redirects=True,
        )

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._client.get(url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._client.post(url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._client.head(url, **kwargs)

    async def __aenter__(self) -> "PlecostHTTPClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self._client.__aexit__(*args)
