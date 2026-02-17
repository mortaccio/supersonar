from __future__ import annotations

import unittest

from supersonar.models import Issue, ScanResult
from supersonar.reporters import to_json_report


class ReporterTests(unittest.TestCase):
    def test_json_report_contains_rule_counts_and_files_with_issues(self) -> None:
        result = ScanResult(
            files_scanned=3,
            issues=[
                Issue("SS001", "x", "critical", "m", "a.py", 1, 1),
                Issue("SS001", "x", "critical", "m", "a.py", 2, 1),
                Issue("SS004", "x", "low", "m", "b.py", 1, 1),
            ],
        )

        payload = to_json_report(result)

        self.assertEqual(payload["files_scanned"], 3)
        self.assertEqual(payload["files_with_issues"], 2)
        self.assertEqual(payload["rule_counts"]["SS001"], 2)
        self.assertEqual(payload["rule_counts"]["SS004"], 1)

    def test_json_report_contains_security_summary(self) -> None:
        result = ScanResult(
            files_scanned=4,
            issues=[
                Issue("SS001", "x", "critical", "m", "backend/app.py", 1, 1),
                Issue("SS110", "x", "high", "m", "Dockerfile", 2, 1),
                Issue("SS111", "x", "critical", "m", "k8s/deploy.yaml", 10, 1),
                Issue("SS004", "x", "low", "m", "frontend/a.js", 4, 1),
            ],
        )

        payload = to_json_report(result)
        summary = payload["security_summary"]

        self.assertEqual(summary["issues_total"], 3)
        self.assertEqual(summary["files_with_issues"], 3)
        self.assertEqual(summary["severity_counts"]["critical"], 2)
        self.assertEqual(summary["severity_counts"]["high"], 1)
        self.assertEqual(summary["rule_counts"]["SS001"], 1)
        self.assertEqual(summary["rule_counts"]["SS110"], 1)
        self.assertEqual(summary["language_counts"]["python"], 1)
        self.assertEqual(summary["language_counts"]["dockerfile"], 1)
        self.assertEqual(summary["language_counts"]["yaml"], 1)


if __name__ == "__main__":
    unittest.main()
