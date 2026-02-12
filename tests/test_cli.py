from __future__ import annotations

import unittest

from supersonar.cli import build_parser


class CLITests(unittest.TestCase):
    def test_version_flag(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit) as exc:
            parser.parse_args(["--version"])
        self.assertEqual(exc.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
