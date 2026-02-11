from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from supersonar.rules.generic import GenericRuleEngine
from supersonar.rules.python import PythonRuleEngine


class RulesEngineTests(unittest.TestCase):
    def test_detects_all_core_rules(self) -> None:
        code = """# TODO: remove
token = "mysecretvalue"

try:
    risky()
except Exception:
    pass

value = eval("2+2")
"""
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.py"
            sample.write_text(code, encoding="utf-8")
            issues = PythonRuleEngine().run(sample)

        found = {issue.rule_id for issue in issues}
        self.assertIn("SS004", found)
        self.assertIn("SS003", found)
        self.assertIn("SS002", found)
        self.assertIn("SS001", found)

    def test_syntax_error_emits_issue(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "bad.py"
            sample.write_text("def broken(:\n    pass\n", encoding="utf-8")
            issues = PythonRuleEngine().run(sample)

        rule_ids = [issue.rule_id for issue in issues]
        self.assertIn("SS000", rule_ids)

    def test_generic_engine_detects_dynamic_eval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "app.js"
            sample.write_text("const x = eval(userInput)\n", encoding="utf-8")
            issues = GenericRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS101", rule_ids)

    def test_generic_engine_detects_merge_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "App.java"
            sample.write_text("<<<<<<< HEAD\n", encoding="utf-8")
            issues = GenericRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS005", rule_ids)


if __name__ == "__main__":
    unittest.main()
