from __future__ import annotations

import unittest

from supersonar.cli import build_parser, merge_cli_with_config, validate_quality_gate_config
from supersonar.config import Config
from supersonar.security import resolve_enabled_rules


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

    def test_security_only_flag_enables_security_mode(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["scan", ".", "--security-only"])
        merged = merge_cli_with_config(args, Config())
        self.assertTrue(merged.scan.security_only)

    def test_pretty_flag_sets_pretty_output_format(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["scan", ".", "--pretty"])
        merged = merge_cli_with_config(args, Config())
        self.assertEqual(merged.report.output_format, "pretty")

    def test_security_only_filters_enabled_rules(self) -> None:
        resolved = resolve_enabled_rules(["SS004", "SS001", "SS007"], security_only=True)
        self.assertEqual(resolved, ["SS001", "SS007"])

    def test_security_only_default_rules_include_non_python_security(self) -> None:
        resolved = resolve_enabled_rules(None, security_only=True)
        self.assertIsNotNone(resolved)
        assert resolved is not None
        self.assertIn("SS221", resolved)
        self.assertIn("SS306", resolved)
        self.assertIn("SS407", resolved)
        self.assertIn("SS507", resolved)
        self.assertIn("SS108", resolved)
        self.assertIn("SS111", resolved)

    def test_top_level_help_contains_manual(self) -> None:
        parser = build_parser()
        help_text = parser.format_help()
        self.assertIn("Security scanning (backend + frontend + infra):", help_text)
        self.assertIn("supersonar scan . --security-only", help_text)
        self.assertIn("supersonar scan -h", help_text)


if __name__ == "__main__":
    unittest.main()
