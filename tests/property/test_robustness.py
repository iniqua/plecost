import re
import pytest
from hypothesis import given, settings, strategies as st
from plecost.modules.fingerprint import _META_RE, _VER_RE
from plecost.models import ScanOptions


@given(st.text())
@settings(max_examples=200)
def test_meta_regex_never_raises(text):
    """Any text input to regex should not raise."""
    _META_RE.search(text)


@given(st.text())
@settings(max_examples=200)
def test_ver_regex_never_raises(text):
    _VER_RE.search(text)


@given(st.text(min_size=1))
def test_scan_options_accepts_any_url(url):
    """ScanOptions should never raise on any URL string."""
    try:
        ScanOptions(url=url)
    except Exception as e:
        pytest.fail(f"ScanOptions raised {e} for url={url!r}")


# ---------------------------------------------------------------------------
# Additional property tests
# ---------------------------------------------------------------------------

@given(st.text())
@settings(max_examples=200)
def test_plugin_version_regex_never_raises(text):
    """plugins._VER_RE should never raise for arbitrary text input."""
    from plecost.modules.plugins import _VER_RE as _PLUGIN_VER_RE
    _PLUGIN_VER_RE.search(text)


def test_all_registry_ids_match_format():
    """Finding IDs in _FINDINGS_REGISTRY must follow the PC-<MODULE>-<ID> pattern."""
    from plecost.cli import _FINDINGS_REGISTRY
    pattern = re.compile(r'^PC-[A-Z]+-[\w]+$')
    for fid in _FINDINGS_REGISTRY:
        assert pattern.match(fid), f"ID {fid!r} does not match expected pattern PC-<MODULE>-<ID>"


@given(st.from_regex(r'https?://[a-z]{3,10}\.[a-z]{2,4}/*', fullmatch=True))
def test_scan_context_url_no_trailing_slash(url):
    """ScanContext.url must never have a trailing slash regardless of input."""
    from plecost.engine.context import ScanContext
    ctx = ScanContext(ScanOptions(url=url))
    assert not ctx.url.endswith('/'), f"URL {ctx.url!r} has trailing slash"
