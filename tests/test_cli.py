from __future__ import annotations

import unittest

from supersonar.cli import build_parser, validate_quality_gate_config
from supersonar.config import Config


class CLITests(unittest.TestCase):
    def test_version_flag(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit) as exc:
            parser.parse_args(["--version"])
        self.assertEqual(exc.exception.code, 0)

    def test_validates_negative_gate_values(self) -> None:
        config = Config()
        config.quality_gate.max_issues = -1

        errors = validate_quality_gate_config(config)
        self.assertTrue(any("max_issues" in error for error in errors))

    def test_validates_invalid_fail_on_value(self) -> None:
        config = Config()
        config.quality_gate.fail_on = "blocker"  # type: ignore[assignment]

        errors = validate_quality_gate_config(config)
        self.assertTrue(any("fail_on" in error for error in errors))

    def test_validates_gate_new_only_requires_baseline(self) -> None:
        config = Config()
        config.quality_gate.only_new_issues = True

        errors = validate_quality_gate_config(config)
        self.assertTrue(any("only_new_issues" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
