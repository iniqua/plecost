from __future__ import annotations
import json
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime
from enum import Enum
from typing import Any
from plecost.models import ScanResult


def _default(obj: object) -> object:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    raise TypeError(f"Not serializable: {type(obj)}")


def _build_findings_by_category(data: dict[str, Any]) -> dict[str, list[Any]]:
    grouped: dict[str, list[Any]] = defaultdict(list)
    for finding in data.get("findings", []):
        grouped[finding.get("category", "other")].append(finding)
    return dict(sorted(grouped.items()))


class JSONReporter:
    def __init__(self, result: ScanResult) -> None:
        self._result = result

    def to_string(self) -> str:
        data = asdict(self._result)
        data["findings_by_category"] = _build_findings_by_category(data)
        return json.dumps(data, indent=2, default=_default)

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            f.write(self.to_string())
