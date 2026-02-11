from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET

from supersonar.models import CoverageData


def read_coverage_xml(path: str) -> CoverageData:
    coverage_path = Path(path)
    if not coverage_path.exists():
        raise FileNotFoundError(f"Coverage XML not found: {coverage_path}")

    tree = ET.parse(coverage_path)
    root = tree.getroot()
    line_rate = _to_float(root.attrib.get("line-rate"))
    lines_covered = _to_int(root.attrib.get("lines-covered"))
    lines_valid = _to_int(root.attrib.get("lines-valid"))

    # Cobertura-compatible reports expose line-rate at root.
    if line_rate is None:
        if lines_covered is None or lines_valid in (None, 0):
            raise ValueError("Coverage XML missing line-rate and lines-covered/lines-valid attributes.")
        line_rate = lines_covered / lines_valid

    return CoverageData(line_rate=line_rate, lines_covered=lines_covered, lines_valid=lines_valid)


def _to_float(value: str | None) -> float | None:
    if value is None:
        return None
    return float(value)


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    return int(value)

