from __future__ import annotations
import json
from dataclasses import asdict
from datetime import datetime
from enum import Enum
from plecost.models import ScanResult


def _default(obj: object) -> object:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    raise TypeError(f"Not serializable: {type(obj)}")


class JSONReporter:
    def __init__(self, result: ScanResult) -> None:
        self._result = result

    def to_string(self) -> str:
        return json.dumps(asdict(self._result), indent=2, default=_default)

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            f.write(self.to_string())
