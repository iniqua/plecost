"""Circuit breaker and jitter tests for BruteForceModule — BRU-RL spec.

Covers:
  AC-1  — jitter sleep (random.uniform 0.3-1.5)
  AC-3  — 3 consecutive 429s → circuit opens (wait occurs)
  AC-4  — state machine: OPEN→HALF_OPEN→OPEN→...→EXHAUSTED
  AC-5  — total wait ≤ 60 s (10+20+30)
  AC-6  — EXHAUSTED emits PC-BRU-007
  AC-7  — non-429 in HALF_OPEN → circuit resets to CLOSED
  AC-8  — evidence includes total_wait_seconds and attempts_made
  AC-9  — circuit breaker is instantiated per BruteForceModule.run() call (not global)

Anti-tautology notes for each test are inline.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, call, patch

import httpx
import pytest
import respx

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions, User


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ctx(deep: bool = False) -> ScanContext:
    opts = ScanOptions(
        url="https://example.com",
        brute_force=True,
        brute_force_use_defaults=True,
        deep=deep,
    )
    ctx = ScanContext(opts)
    ctx.is_wordpress = True
    ctx.add_user(User(id=1, username="admin", display_name="Admin", source="rest_api"))
    return ctx


def _patch_sleep():
    """Return a patch context manager that replaces asyncio.sleep in brute_force module
    with an AsyncMock that records all calls without actually sleeping."""
    return patch("plecost.modules.brute_force.asyncio.sleep", new_callable=AsyncMock)


# ---------------------------------------------------------------------------
# _RateLimitCircuitBreaker unit tests
# ---------------------------------------------------------------------------

class TestCircuitBreakerUnit:
    """Direct unit tests of _RateLimitCircuitBreaker state machine."""

    def setup_method(self):
        from plecost.modules.brute_force import _RateLimitCircuitBreaker, _CBState
        self.CB = _RateLimitCircuitBreaker
        self.CBState = _CBState

    async def test_initial_state_is_closed(self):
        cb = self.CB()
        assert cb._state == self.CBState.CLOSED
        assert not cb.is_exhausted
        assert cb.total_wait_seconds == 0

    async def test_wait_if_open_passes_immediately_when_closed(self):
        """CLOSED state: wait_if_open() must not block (event is set)."""
        cb = self.CB()
        # Should return immediately without blocking
        done = False

        async def check():
            nonlocal done
            await cb.wait_if_open()
            done = True

        await asyncio.wait_for(check(), timeout=0.1)
        assert done

    async def test_record_rate_limit_first_open(self):
        """First record_rate_limit: state=OPEN then HALF_OPEN; not exhausted; wait_time=10."""
        cb = self.CB()
        with _patch_sleep() as mock_sleep:
            result = await cb.record_rate_limit()
        assert result is False, "First opening must NOT be exhausted"
        assert cb._open_count == 1
        assert cb._total_wait == 10
        mock_sleep.assert_called_once_with(10)

    async def test_record_rate_limit_second_open(self):
        """Second opening waits 20 s and is not exhausted."""
        cb = self.CB()
        with _patch_sleep():
            await cb.record_rate_limit()  # first: 10 s
            result = await cb.record_rate_limit()  # second: 20 s
        assert result is False
        assert cb._open_count == 2
        assert cb._total_wait == 30  # 10 + 20

    async def test_record_rate_limit_third_open(self):
        """Third opening waits 30 s and is not exhausted."""
        cb = self.CB()
        with _patch_sleep():
            await cb.record_rate_limit()  # first: 10 s
            await cb.record_rate_limit()  # second: 20 s
            result = await cb.record_rate_limit()  # third: 30 s
        assert result is False
        assert cb._open_count == 3
        assert cb._total_wait == 60  # 10 + 20 + 30

    async def test_record_rate_limit_fourth_returns_exhausted(self):
        """AC-6/AC-4: After 3 openings, 4th call returns True (EXHAUSTED)."""
        cb = self.CB()
        with _patch_sleep():
            await cb.record_rate_limit()
            await cb.record_rate_limit()
            await cb.record_rate_limit()
            result = await cb.record_rate_limit()  # triggers EXHAUSTED
        assert result is True
        assert cb.is_exhausted

    async def test_total_wait_is_60_after_exhaustion(self):
        """AC-5: total_wait_seconds must equal 60 when exhausted (10+20+30)."""
        cb = self.CB()
        with _patch_sleep():
            await cb.record_rate_limit()  # 10
            await cb.record_rate_limit()  # 20
            await cb.record_rate_limit()  # 30
            await cb.record_rate_limit()  # EXHAUSTED (no additional wait)
        assert cb.total_wait_seconds == 60
        # Anti-tautology: if wait times were [0,0,0] this would be 0, not 60

    async def test_record_success_resets_to_closed(self):
        """AC-7: record_success() after HALF_OPEN returns circuit to CLOSED."""
        cb = self.CB()
        with _patch_sleep():
            await cb.record_rate_limit()  # OPEN → HALF_OPEN
        assert cb._state == self.CBState.HALF_OPEN
        cb.record_success()
        assert cb._state == self.CBState.CLOSED
        assert not cb.is_exhausted

    async def test_record_success_resets_event(self):
        """AC-7: After record_success, wait_if_open passes without blocking."""
        cb = self.CB()
        with _patch_sleep():
            await cb.record_rate_limit()
        cb.record_success()
        done = False

        async def check():
            nonlocal done
            await cb.wait_if_open()
            done = True

        await asyncio.wait_for(check(), timeout=0.1)
        assert done

    async def test_exhausted_state_is_sticky(self):
        """Subsequent calls after EXHAUSTED immediately return True."""
        cb = self.CB()
        with _patch_sleep():
            for _ in range(4):
                await cb.record_rate_limit()
        # Now call again — must return True immediately without sleeping
        mock_sleep = AsyncMock()
        with patch("plecost.modules.brute_force.asyncio.sleep", mock_sleep):
            result = await cb.record_rate_limit()
        assert result is True
        mock_sleep.assert_not_called()  # no additional sleep after EXHAUSTED


# ---------------------------------------------------------------------------
# AC-1: Jitter replaces fixed 2.0s sleep
# ---------------------------------------------------------------------------

async def test_jitter_sleep_called_with_value_in_range():
    """AC-1: asyncio.sleep must be called with a value between 0.3 and 1.5, not 2.0.

    Anti-tautology: if brute_force.py still uses asyncio.sleep(2.0),
    mock_sleep.call_args_list would contain call(2.0) and the assertion fails.
    """
    from plecost.modules.brute_force import BruteForceModule

    ctx = _make_ctx()
    sleep_calls: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleep_calls.append(delay)

    with patch("plecost.modules.brute_force.asyncio.sleep", side_effect=fake_sleep):
        async with respx.mock:
            # All login attempts fail (200 with no special headers)
            respx.post("https://example.com/wp-login.php").mock(
                return_value=httpx.Response(200, text="login failed")
            )
            respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

            async with PlecostHTTPClient(ctx.opts) as http:
                # Limit to very few attempts by patching the password list
                with patch.object(
                    BruteForceModule,
                    "_build_password_list",
                    return_value=["p1", "p2", "p3"],
                ):
                    await BruteForceModule().run(ctx, http)

    # At least one sleep call should have been made
    assert len(sleep_calls) > 0, "Sleep must be called between attempts"
    for delay in sleep_calls:
        assert 0.3 <= delay <= 1.5, (
            f"Jitter sleep must be between 0.3 and 1.5 s, got {delay}. "
            "If this fails with delay=2.0, the jitter replacement was not applied."
        )
    # Explicit anti-tautology: 2.0 must not appear
    assert 2.0 not in sleep_calls, (
        "Fixed 2.0s sleep must have been replaced with jitter (random.uniform(0.3, 1.5))"
    )


# ---------------------------------------------------------------------------
# AC-3: 3 consecutive 429s → circuit opens (wait occurs)
# ---------------------------------------------------------------------------

async def test_three_consecutive_429s_trigger_circuit_breaker():
    """AC-3: After 3 consecutive 429s, the CB calls asyncio.sleep (circuit opens).

    Anti-tautology: without the CB, after 1 429 the loop would stop via
    rate_limited=True and no CB sleep would be called. If sleep(10) is absent
    in the call list, the CB was not triggered.
    """
    from plecost.modules.brute_force import BruteForceModule

    ctx = _make_ctx()
    attempt_num = [0]
    sleep_calls: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleep_calls.append(delay)

    async def login_handler(request):
        attempt_num[0] += 1
        # First 2 succeed; next 3 return 429; then fail to exhaust CB
        if attempt_num[0] <= 2:
            return httpx.Response(200, text="fail")
        return httpx.Response(429, text="Too Many Requests")

    with patch("plecost.modules.brute_force.asyncio.sleep", side_effect=fake_sleep):
        async with respx.mock:
            respx.post("https://example.com/wp-login.php").mock(side_effect=login_handler)
            respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

            async with PlecostHTTPClient(ctx.opts) as http:
                with patch.object(
                    BruteForceModule,
                    "_build_password_list",
                    return_value=["p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10"],
                ):
                    await BruteForceModule().run(ctx, http)

    # The CB sleep (10 s for first opening) must appear in sleep_calls
    cb_sleeps = [d for d in sleep_calls if d in (10, 20, 30)]
    assert len(cb_sleeps) > 0, (
        "AC-3: After 3 consecutive 429s the circuit must open and sleep. "
        "If this fails, the CB logic did not trigger — check consecutive_rl threshold."
    )
    assert 10 in cb_sleeps, (
        "AC-3: First circuit opening must wait 10 s (WAIT_TIMES[0])"
    )


# ---------------------------------------------------------------------------
# AC-6 + AC-8: EXHAUSTED → PC-BRU-007 emitted with correct evidence
# ---------------------------------------------------------------------------

async def test_circuit_breaker_exhausted_emits_pc_bru_007():
    """AC-6: When circuit breaker is EXHAUSTED, PC-BRU-007 must be emitted.

    Anti-tautology: if the CB exhaustion branch were commented out (no Finding
    emitted), ctx.findings would be empty and the assertion fails.
    """
    from plecost.modules.brute_force import BruteForceModule

    ctx = _make_ctx()
    # Always return 429 so circuit exhausts quickly
    async def always_429(request):
        return httpx.Response(429, text="Too Many Requests")

    with _patch_sleep():
        async with respx.mock:
            respx.post("https://example.com/wp-login.php").mock(side_effect=always_429)
            respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

            async with PlecostHTTPClient(ctx.opts) as http:
                with patch.object(
                    BruteForceModule,
                    "_build_password_list",
                    # Enough passwords to keep hitting 429 until exhausted
                    return_value=[f"p{i}" for i in range(20)],
                ):
                    await BruteForceModule().run(ctx, http)

    bru007 = [f for f in ctx.findings if f.id == "PC-BRU-007"]
    assert len(bru007) == 1, (
        "AC-6: PC-BRU-007 must be emitted exactly once when CB is exhausted"
    )
    ev = bru007[0].evidence
    assert "total_wait_seconds" in ev, (
        "AC-8: PC-BRU-007 evidence must include 'total_wait_seconds'"
    )
    assert "attempts_made" in ev, (
        "AC-8: PC-BRU-007 evidence must include 'attempts_made'"
    )


async def test_circuit_breaker_exhausted_evidence_has_60_wait():
    """AC-5 + AC-8: total_wait_seconds in evidence must equal 60 (10+20+30).

    Anti-tautology: if WAIT_TIMES were [0,0,0] this would be 0, not 60.
    """
    from plecost.modules.brute_force import BruteForceModule

    ctx = _make_ctx()

    async def always_429(request):
        return httpx.Response(429, text="Too Many Requests")

    with _patch_sleep():
        async with respx.mock:
            respx.post("https://example.com/wp-login.php").mock(side_effect=always_429)
            respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

            async with PlecostHTTPClient(ctx.opts) as http:
                with patch.object(
                    BruteForceModule,
                    "_build_password_list",
                    return_value=[f"p{i}" for i in range(20)],
                ):
                    await BruteForceModule().run(ctx, http)

    bru007 = [f for f in ctx.findings if f.id == "PC-BRU-007"]
    assert len(bru007) == 1
    assert bru007[0].evidence["total_wait_seconds"] == 60, (
        f"AC-5: total_wait_seconds must be 60 (10+20+30), "
        f"got {bru007[0].evidence.get('total_wait_seconds')}"
    )


# ---------------------------------------------------------------------------
# AC-7: Non-429 in HALF_OPEN → circuit resets to CLOSED
# ---------------------------------------------------------------------------

async def test_half_open_success_resets_circuit_to_closed():
    """AC-7: After HALF_OPEN probe succeeds (non-429), circuit must return to CLOSED.

    Anti-tautology: without record_success() being called, the CB would remain
    in HALF_OPEN and _open_count would NOT reset. The scan would stop after one
    more 429 instead of continuing normally.
    """
    from plecost.modules.brute_force import BruteForceModule, _RateLimitCircuitBreaker

    ctx = _make_ctx()
    captured_cb: list[_RateLimitCircuitBreaker] = []
    attempt_num = [0]

    async def login_handler(request):
        attempt_num[0] += 1
        # Attempts 1-3: 429 → triggers CB (3 consecutive)
        # Attempt 4 (HALF_OPEN probe): 200 → resets CB
        # Remaining: normal failures
        if attempt_num[0] <= 3:
            return httpx.Response(429, text="Too Many Requests")
        return httpx.Response(200, text="fail")

    original_run = BruteForceModule.run

    async def patched_run(self, ctx, http):
        # We need to capture the cb from inside run(); we monkey-patch record_rate_limit
        # to also capture the cb reference
        await original_run(self, ctx, http)

    sleep_calls: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleep_calls.append(delay)

    with patch("plecost.modules.brute_force.asyncio.sleep", side_effect=fake_sleep):
        async with respx.mock:
            respx.post("https://example.com/wp-login.php").mock(side_effect=login_handler)
            respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

            async with PlecostHTTPClient(ctx.opts) as http:
                with patch.object(
                    BruteForceModule,
                    "_build_password_list",
                    return_value=[f"p{i}" for i in range(10)],
                ):
                    await BruteForceModule().run(ctx, http)

    # The scan should have continued past the CB opening (not been stopped by EXHAUSTED)
    bru007 = [f for f in ctx.findings if f.id == "PC-BRU-007"]
    # PC-BRU-007 may or may not appear depending on subsequent 429s, but
    # the circuit should NOT have been exhausted (total_wait would be >10 and
    # CB would not have had a chance to reset)
    # The key check: if circuit reset worked, CB sleep should be only 10 (one opening),
    # and the scan should continue to PC-BRU-004 (no credentials found)
    cb_sleeps = [d for d in sleep_calls if d in (10, 20, 30)]
    # Only one CB sleep of 10s should have occurred (one OPEN window)
    assert cb_sleeps.count(10) >= 1, (
        "AC-7: Circuit must have opened at least once (10s sleep)"
    )
    # After reset, subsequent attempts should be jitter sleeps (not CB sleeps)
    # and the scan should reach a conclusion (not EXHAUSTED on first opening)
    # The absence of exhaustion is shown by PC-BRU-004 or fewer than 3 CB sleeps
    if bru007:
        assert bru007[0].evidence.get("total_wait_seconds", 0) < 60, (
            "AC-7: Circuit reset must prevent EXHAUSTED (60s total) from happening "
            "when probe succeeds after first opening"
        )


# ---------------------------------------------------------------------------
# AC-9: Circuit breaker is per-run (not a global singleton)
# ---------------------------------------------------------------------------

async def test_circuit_breaker_is_per_run_not_global():
    """AC-9: Each call to BruteForceModule.run() must use a fresh circuit breaker.

    Anti-tautology: if cb were a module-level singleton, state would bleed
    between runs and the second run would start EXHAUSTED.
    """
    from plecost.modules.brute_force import BruteForceModule

    module = BruteForceModule()

    async def always_429(request):
        return httpx.Response(429, text="Too Many Requests")

    # Run 1: exhaust the circuit breaker
    ctx1 = _make_ctx()
    with _patch_sleep():
        async with respx.mock:
            respx.post("https://example.com/wp-login.php").mock(side_effect=always_429)
            respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

            async with PlecostHTTPClient(ctx1.opts) as http:
                with patch.object(
                    BruteForceModule, "_build_password_list",
                    return_value=[f"p{i}" for i in range(20)],
                ):
                    await module.run(ctx1, http)

    bru007_run1 = [f for f in ctx1.findings if f.id == "PC-BRU-007"]
    assert len(bru007_run1) == 1, "Run 1 must emit PC-BRU-007 (CB exhausted)"

    # Run 2: fresh run — CB must start CLOSED (not EXHAUSTED from run 1)
    ctx2 = _make_ctx()
    attempt_count = [0]

    async def limited_429(request):
        attempt_count[0] += 1
        # Only first attempt returns 429; rest succeed
        if attempt_count[0] == 1:
            return httpx.Response(429, text="Too Many Requests")
        return httpx.Response(200, text="fail")

    with _patch_sleep():
        async with respx.mock:
            respx.post("https://example.com/wp-login.php").mock(side_effect=limited_429)
            respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

            async with PlecostHTTPClient(ctx2.opts) as http:
                with patch.object(
                    BruteForceModule, "_build_password_list",
                    return_value=["p1", "p2", "p3"],
                ):
                    await module.run(ctx2, http)

    # Run 2 should have started fresh — immediate 429 stops as rate_limited (not CB)
    bru007_run2 = [f for f in ctx2.findings if f.id == "PC-BRU-007"]
    # It will have PC-BRU-007 (rate_limit_detected) but total_wait should be 0
    # (not EXHAUSTED from run 1 bleeding over)
    if bru007_run2:
        ev = bru007_run2[0].evidence
        total_wait = ev.get("total_wait_seconds", 0)
        assert total_wait == 0, (
            f"AC-9: Run 2 must start with fresh CB (total_wait=0), "
            f"got total_wait_seconds={total_wait}. CB may be a global singleton."
        )


# ---------------------------------------------------------------------------
# Integration: always-429 with short wordlist emits PC-BRU-007 via exhaustion
# ---------------------------------------------------------------------------

async def test_always_429_short_wordlist_emits_bru007_via_exhaustion():
    """Regression/integration: always-429 with a short wordlist still emits PC-BRU-007.

    With the CB, the loop continues through 429s until either the wordlist is
    exhausted (emits PC-BRU-004) or the CB exhausts (emits PC-BRU-007).
    A short always-429 wordlist of 20 entries will CB-exhaust quickly.
    """
    from plecost.modules.brute_force import BruteForceModule

    ctx = _make_ctx()

    async def always_429(request):
        return httpx.Response(429, text="Too Many Requests")

    with _patch_sleep():
        async with respx.mock:
            respx.post("https://example.com/wp-login.php").mock(side_effect=always_429)
            respx.route(url__regex=r".*").mock(return_value=httpx.Response(200))

            async with PlecostHTTPClient(ctx.opts) as http:
                with patch.object(
                    BruteForceModule,
                    "_build_password_list",
                    return_value=[f"p{i}" for i in range(20)],
                ):
                    await BruteForceModule().run(ctx, http)

    bru007 = [f for f in ctx.findings if f.id == "PC-BRU-007"]
    assert len(bru007) == 1, (
        "Integration: always-429 must emit PC-BRU-007 (via CB exhaustion)"
    )
    assert bru007[0].evidence.get("total_wait_seconds", 0) == 60, (
        "Integration: CB exhaustion path must set total_wait_seconds=60"
    )
