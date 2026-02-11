from __future__ import annotations

import unittest

from supersonar.models import CoverageData, Issue, ScanResult
from supersonar.quality_gate import evaluate_gate


class QualityGateTests(unittest.TestCase):
    def test_fails_on_severity_threshold(self) -> None:
        result = ScanResult(
            issues=[
                Issue(
                    rule_id="SS001",
                    title="t",
                    severity="critical",
                    message="m",
                    file_path="x.py",
                    line=1,
                    column=1,
                )
            ],
            files_scanned=1,
        )
        passed, reasons = evaluate_gate(result, fail_on="high")
        self.assertFalse(passed)
        self.assertTrue(reasons)

    def test_passes_under_max_issues(self) -> None:
        result = ScanResult(issues=[], files_scanned=1)
        passed, reasons = evaluate_gate(result, max_issues=0)
        self.assertTrue(passed)
        self.assertEqual(reasons, [])

    def test_fails_on_per_severity_limit(self) -> None:
        result = ScanResult(
            issues=[
                Issue("SS003", "t", "high", "m", "x.py", 1, 1),
                Issue("SS003", "t", "high", "m", "x.py", 2, 1),
            ],
            files_scanned=1,
        )
        passed, reasons = evaluate_gate(result, max_high=1)
        self.assertFalse(passed)
        self.assertTrue(any("max_high" in reason for reason in reasons))

    def test_fails_when_coverage_below_threshold(self) -> None:
        result = ScanResult(issues=[], files_scanned=1, coverage=CoverageData(line_rate=0.69))
        passed, reasons = evaluate_gate(result, min_coverage=70.0)
        self.assertFalse(passed)
        self.assertTrue(any("min_coverage" in reason for reason in reasons))

    def test_fails_when_min_coverage_set_without_report(self) -> None:
        result = ScanResult(issues=[], files_scanned=1, coverage=None)
        passed, reasons = evaluate_gate(result, min_coverage=70.0)
        self.assertFalse(passed)
        self.assertTrue(any("no coverage data" in reason.lower() for reason in reasons))


if __name__ == "__main__":
    unittest.main()
