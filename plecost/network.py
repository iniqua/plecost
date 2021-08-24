import asyncio
import urllib.parse as pr

from typing import Tuple

import aiohttp
import orjson as json

from plecost.interfaces import Singleton

def join_url(base_url: str, path: str):
    return pr.urljoin(base_url, path)

class _HTTP(metaclass=Singleton):

    def __init__(self, concurrency: int = 5):

        self._mutexes = {}
        self._sessions = {}
        self.concurrency = concurrency

    def _get_session(
            self, url: str
    ) -> Tuple[aiohttp.ClientSession, asyncio.Semaphore]:

        hostname: str = pr.urlparse(url).hostname

        try:
            return self._sessions[hostname], self._mutexes[hostname]
        except KeyError:
            self._sessions[hostname] = aiohttp.ClientSession()
            self._mutexes[hostname] = asyncio.Semaphore(self.concurrency)

            return self._sessions[hostname], self._mutexes[hostname]

    async def get(self, url: str) -> Tuple[int, str]:
        session, mutex = self._get_session(url)

        async with mutex:
            async with session.get(url) as resp:
                body = await resp.text(errors="ignore")
                return resp.status, body

    async def get_json(self, url: str) -> Tuple[int, dict]:
        session, mutex = self._get_session(url)

        async with mutex:
            async with session.get(url) as resp:
                body = await resp.text(errors="ignore")
                return resp.status, json.loads(body)


HTTP = _HTTP()

__all__ = ("HTTP", "join_url")
