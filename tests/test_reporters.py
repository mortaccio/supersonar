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


if __name__ == "__main__":
    unittest.main()
