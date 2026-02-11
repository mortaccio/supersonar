from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from supersonar.coverage import read_coverage_xml


class CoverageTests(unittest.TestCase):
    def test_reads_cobertura_line_rate(self) -> None:
        xml = """<?xml version="1.0" ?>
<coverage line-rate="0.85" lines-covered="85" lines-valid="100"></coverage>
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "coverage.xml"
            path.write_text(xml, encoding="utf-8")
            coverage = read_coverage_xml(str(path))

        self.assertAlmostEqual(coverage.line_rate, 0.85)
        self.assertEqual(coverage.lines_covered, 85)
        self.assertEqual(coverage.lines_valid, 100)

    def test_reads_cobertura_counts_without_line_rate(self) -> None:
        xml = """<?xml version="1.0" ?>
<coverage lines-covered="30" lines-valid="40"></coverage>
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "coverage.xml"
            path.write_text(xml, encoding="utf-8")
            coverage = read_coverage_xml(str(path))

        self.assertAlmostEqual(coverage.line_rate, 0.75)


if __name__ == "__main__":
    unittest.main()

