from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from supersonar.baseline import filter_new_issues, load_baseline_fingerprints
from supersonar.models import Issue, ScanResult


class BaselineTests(unittest.TestCase):
    def test_loads_baseline_fingerprints(self) -> None:
        payload = {
            "issues": [
                {
                    "rule_id": "SS001",
                    "message": "m",
                    "file_path": "a.py",
                    "line": 1,
                    "column": 1,
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            fingerprints = load_baseline_fingerprints(str(path))

        self.assertIn(("a.py", "SS001", 1, 1, "m"), fingerprints)

    def test_filters_new_issues(self) -> None:
        result = ScanResult(
            issues=[
                Issue("SS001", "t", "critical", "m", "a.py", 1, 1),
                Issue("SS004", "t", "low", "m2", "b.py", 2, 1),
            ],
            files_scanned=2,
        )
        baseline = {("a.py", "SS001", 1, 1, "m")}

        filtered, baseline_matched = filter_new_issues(result, baseline)

        self.assertEqual(len(filtered.issues), 1)
        self.assertEqual(filtered.issues[0].rule_id, "SS004")
        self.assertEqual(baseline_matched, 1)


if __name__ == "__main__":
    unittest.main()
