from __future__ import annotations
import asyncio
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.modules.base import ScanModule


class Scheduler:
    def __init__(self, modules: list[ScanModule]) -> None:
        self._modules = modules

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient | None) -> None:
        skip = set(ctx.opts.skip_modules)
        only = set(ctx.opts.modules) if ctx.opts.modules else None

        active = {
            m.name: m for m in self._modules
            if m.name not in skip and (only is None or m.name in only)
        }

        completed: set[str] = set()
        events: dict[str, asyncio.Event] = {name: asyncio.Event() for name in active}

        async def run_module(m: ScanModule) -> None:
            # Wait for all dependencies
            for dep in m.depends_on:
                if dep in events:
                    await events[dep].wait()
            await m.run(ctx, http)  # type: ignore[arg-type]
            completed.add(m.name)
            events[m.name].set()

        await asyncio.gather(*[run_module(m) for m in active.values()])
