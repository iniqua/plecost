# plecost/plecost/i18n.py
from __future__ import annotations

import json
import locale
import os
from pathlib import Path
from typing import Any

_LOCALES_DIR = Path(__file__).parent / "locales"

# Runtime state (module-level singletons)
_current_lang: str | None = None          # set by set_language() or CLI flag
_translations: dict[str, dict[str, Any]] = {}   # cache: lang -> parsed JSON


def _load(lang: str) -> dict[str, Any]:
    """Load and cache translation dict for *lang*. Returns empty dict on error."""
    if lang in _translations:
        return _translations[lang]
    path = _LOCALES_DIR / f"{lang}.json"
    if not path.exists():
        _translations[lang] = {}
        return {}
    data: dict[str, Any]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        data = {}
    _translations[lang] = data
    return data


def _get_nested(data: dict[str, Any], key: str) -> str | None:
    """Resolve dot-notation key in nested dict. Returns None if missing."""
    parts = key.split(".")
    node: Any = data
    for part in parts:
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node if isinstance(node, str) else None


def detect_language() -> str:
    """Resolve language using priority order (excluding forced _current_lang)."""
    if _current_lang is not None:
        return _current_lang

    # 2. Environment variable
    env = os.environ.get("PLECOST_LANG", "").strip().lower()
    if env:
        return env[:2]  # take first 2 chars: "es_ES" → "es"

    # 3. System locale
    try:
        loc, _ = locale.getdefaultlocale()
        if loc:
            return loc[:2].lower()
    except Exception:
        pass

    # 4. Fallback
    return "en"


def set_language(lang: str) -> None:
    """Force a specific language, overriding all auto-detection."""
    global _current_lang
    _current_lang = lang.strip().lower()[:2]


def t(key: str, **kwargs: Any) -> str:
    """
    Translate *key* (dot-notation) in the active language.
    Falls back to English if the key is missing in the active language.
    Returns the key itself if missing in both.
    Supports {variable} interpolation via **kwargs.
    """
    lang = detect_language()
    data = _load(lang)
    value = _get_nested(data, key)

    if value is None and lang != "en":
        en_data = _load("en")
        value = _get_nested(en_data, key)

    if value is None:
        return key

    if kwargs:
        try:
            return value.format(**kwargs)
        except (KeyError, ValueError):
            return value

    return value
