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
