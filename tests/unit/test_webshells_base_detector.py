import respx
import httpx
import pytest
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.webshells.base import BaseDetector
from plecost.models import Finding


class _NoopDetector(BaseDetector):
    name = "noop"
    async def detect(self, ctx: ScanContext, http: PlecostHTTPClient) -> list[Finding]:
        return []


BASE_URL = "https://example.com"
PROBE_A = f"{BASE_URL}/__plecost_probe_a__.php"
PROBE_B = f"{BASE_URL}/__plecost_probe_b__.php"


def make_http_client():
    opts = ScanOptions(url=BASE_URL)
    return PlecostHTTPClient(opts)


async def test_catch_all_detected_when_both_probes_200_same_size():
    detector = _NoopDetector()
    async with respx.mock:
        respx.get(PROBE_A).mock(return_value=httpx.Response(200, content=b"x" * 18125))
        respx.get(PROBE_B).mock(return_value=httpx.Response(200, content=b"x" * 18125))
        async with make_http_client() as http:
            size = await detector._detect_catch_all(http, PROBE_A, PROBE_B)
    assert size == 18125


async def test_catch_all_detected_with_dynamic_content():
    # Cloudflare case: same page but Ray IDs add a few bytes per request
    detector = _NoopDetector()
    async with respx.mock:
        respx.get(PROBE_A).mock(return_value=httpx.Response(200, content=b"x" * 18125))
        respx.get(PROBE_B).mock(return_value=httpx.Response(200, content=b"x" * 18131))
        async with make_http_client() as http:
            size = await detector._detect_catch_all(http, PROBE_A, PROBE_B)
    # diff = 6/18131 = 0.033% < 5% → catch-all detected
    assert size == 18125


async def test_no_catch_all_when_probe_a_returns_404():
    detector = _NoopDetector()
    async with respx.mock:
        respx.get(PROBE_A).mock(return_value=httpx.Response(404))
        respx.get(PROBE_B).mock(return_value=httpx.Response(200, content=b"x" * 18125))
        async with make_http_client() as http:
            size = await detector._detect_catch_all(http, PROBE_A, PROBE_B)
    assert size is None


async def test_no_catch_all_when_probe_b_returns_404():
    detector = _NoopDetector()
    async with respx.mock:
        respx.get(PROBE_A).mock(return_value=httpx.Response(200, content=b"x" * 18125))
        respx.get(PROBE_B).mock(return_value=httpx.Response(404))
        async with make_http_client() as http:
            size = await detector._detect_catch_all(http, PROBE_A, PROBE_B)
    assert size is None


async def test_no_catch_all_when_sizes_differ_too_much():
    # probe_a=1000, probe_b=5000 → diff = 4000/5000 = 80% >> 5%
    detector = _NoopDetector()
    async with respx.mock:
        respx.get(PROBE_A).mock(return_value=httpx.Response(200, content=b"x" * 1000))
        respx.get(PROBE_B).mock(return_value=httpx.Response(200, content=b"x" * 5000))
        async with make_http_client() as http:
            size = await detector._detect_catch_all(http, PROBE_A, PROBE_B)
    assert size is None


async def test_no_catch_all_on_network_exception():
    detector = _NoopDetector()
    async with respx.mock:
        respx.get(PROBE_A).mock(side_effect=httpx.ConnectError("refused"))
        respx.get(PROBE_B).mock(return_value=httpx.Response(200, content=b"x" * 18125))
        async with make_http_client() as http:
            size = await detector._detect_catch_all(http, PROBE_A, PROBE_B)
    assert size is None


async def test_catch_all_with_empty_responses():
    # Both probes return 200 with 0 bytes → still catch-all
    detector = _NoopDetector()
    async with respx.mock:
        respx.get(PROBE_A).mock(return_value=httpx.Response(200, content=b""))
        respx.get(PROBE_B).mock(return_value=httpx.Response(200, content=b""))
        async with make_http_client() as http:
            size = await detector._detect_catch_all(http, PROBE_A, PROBE_B)
    assert size == 0
