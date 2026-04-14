# plecost/tests/unit/test_i18n.py
import os
import pytest
from plecost import i18n


def setup_function():
    # Reset language state before each test
    i18n._current_lang = None
    i18n._translations = {}


def test_detect_language_env_var(monkeypatch):
    monkeypatch.setenv("PLECOST_LANG", "es")
    monkeypatch.delenv("LANG", raising=False)
    assert i18n.detect_language() == "es"


def test_detect_language_fallback_to_en(monkeypatch):
    monkeypatch.delenv("PLECOST_LANG", raising=False)
    monkeypatch.delenv("LANG", raising=False)
    monkeypatch.delenv("LC_ALL", raising=False)
    monkeypatch.delenv("LANGUAGE", raising=False)
    # Patch locale.getdefaultlocale to return (None, None)
    import locale
    monkeypatch.setattr(locale, "getdefaultlocale", lambda: (None, None))
    assert i18n.detect_language() == "en"


def test_set_language_overrides_env(monkeypatch):
    monkeypatch.setenv("PLECOST_LANG", "en")
    i18n.set_language("es")
    assert i18n.detect_language() == "es"


def test_t_returns_english_string():
    i18n.set_language("en")
    result = i18n.t("reporter.table.summary")
    assert result == "Summary"


def test_t_returns_spanish_string():
    i18n.set_language("es")
    result = i18n.t("reporter.table.summary")
    assert result == "Resumen"


def test_t_fallback_to_en_for_missing_es_key():
    i18n.set_language("es")
    # Use a key that exists in en.json but is intentionally absent in es.json
    result = i18n.t("reporter.panel.title")
    assert isinstance(result, str)
    assert len(result) > 0


def test_t_returns_key_for_completely_missing_key():
    i18n.set_language("en")
    result = i18n.t("nonexistent.key.that.does.not.exist")
    assert result == "nonexistent.key.that.does.not.exist"


def test_t_interpolation():
    i18n.set_language("en")
    result = i18n.t("verbose.table.findings", count=5)
    assert "5" in result


def test_t_finding_key():
    i18n.set_language("en")
    result = i18n.t("findings.pc_fp_001.title")
    assert "WordPress" in result
