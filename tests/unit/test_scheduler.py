import pytest
from plecost.engine.scheduler import Scheduler
from plecost.engine.context import ScanContext
from plecost.modules.base import ScanModule
from plecost.models import ScanOptions


class ModuleA(ScanModule):
    name = "module_a"
    depends_on: list[str] = []
    async def run(self, ctx: ScanContext, http: object) -> None:
        ctx.is_wordpress = True


class ModuleB(ScanModule):
    name = "module_b"
    depends_on = ["module_a"]
    async def run(self, ctx: ScanContext, http: object) -> None:
        assert ctx.is_wordpress is True  # must run after A


class ModuleC(ScanModule):
    name = "module_c"
    depends_on = ["module_a"]
    async def run(self, ctx: ScanContext, http: object) -> None:
        assert ctx.is_wordpress is True


@pytest.mark.asyncio
async def test_scheduler_respects_dependencies():
    opts = ScanOptions(url="https://example.com")
    ctx = ScanContext(opts)
    modules = [ModuleA(), ModuleB(), ModuleC()]
    scheduler = Scheduler(modules)
    await scheduler.run(ctx, http=None)
    assert ctx.is_wordpress is True


@pytest.mark.asyncio
async def test_scheduler_calls_callbacks():
    """on_module_start and on_module_done are called with the module name."""
    started = []
    done = []
    opts = ScanOptions(url="https://example.com")
    ctx = ScanContext(opts)

    class SimpleModule(ScanModule):
        name = "simple"
        depends_on: list[str] = []
        async def run(self, ctx, http):
            pass

    scheduler = Scheduler(
        [SimpleModule()],
        on_module_start=started.append,
        on_module_done=done.append,
    )
    await scheduler.run(ctx, http=None)
    assert started == ["simple"]
    assert done == ["simple"]


@pytest.mark.asyncio
async def test_scheduler_skips_excluded_modules():
    opts = ScanOptions(url="https://example.com", skip_modules=["module_b"])
    ctx = ScanContext(opts)
    executed = []

    class TrackA(ScanModule):
        name = "module_a"
        depends_on: list[str] = []
        async def run(self, ctx, http):
            executed.append("a")

    class TrackB(ScanModule):
        name = "module_b"
        depends_on: list[str] = []
        async def run(self, ctx, http):
            executed.append("b")

    scheduler = Scheduler([TrackA(), TrackB()])
    await scheduler.run(ctx, http=None)
    assert "a" in executed
    assert "b" not in executed
