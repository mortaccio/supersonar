from __future__ import annotations

import unittest

from supersonar.models import Issue, ScanResult
from supersonar.reporters import to_json_report, to_pretty_report


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

    def test_pretty_report_groups_issues_by_file(self) -> None:
        result = ScanResult(
            files_scanned=2,
            issues=[
                Issue("SS001", "Dangerous dynamic execution", "critical", "Avoid eval", "a.py", 3, 5),
                Issue("SS004", "Work item marker in source", "low", "Found TODO", "a.py", 9, 2),
                Issue("SS110", "Piped remote script execution in Dockerfile", "high", "Avoid curl | sh", "Dockerfile", 2, 1),
            ],
        )

        rendered = to_pretty_report(result)
        self.assertIn("Summary:", rendered)
        self.assertIn("Security:", rendered)
        self.assertIn("FILE a.py", rendered)
        self.assertIn("FILE Dockerfile", rendered)
        self.assertIn("[CRITICAL] SS001", rendered)
        self.assertIn("[HIGH] SS110", rendered)


if __name__ == "__main__":
    unittest.main()
