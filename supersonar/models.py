from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Severity = Literal["low", "medium", "high", "critical"]


@dataclass(slots=True)
class Issue:
    rule_id: str
    title: str
    severity: Severity
    message: str
    file_path: str
    line: int
    column: int


@dataclass(slots=True)
class CoverageData:
    line_rate: float
    lines_covered: int | None = None
    lines_valid: int | None = None


@dataclass(slots=True)
class ScanResult:
    issues: list[Issue]
    files_scanned: int
    coverage: CoverageData | None = None
