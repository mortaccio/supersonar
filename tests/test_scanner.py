from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from supersonar.scanner import scan_path


class ScannerTests(unittest.TestCase):
    def _scan(self, root: str, excludes: list[str]):
        return scan_path(
            root,
            excludes=excludes,
            include_extensions=[".py", ".java", ".js", ".yml", ".yaml", ".md"],
            include_filenames=["Dockerfile"],
            max_file_size_kb=1024,
        )

    def test_detects_eval_issue(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.py"
            sample.write_text("value = eval('2+2')\n", encoding="utf-8")

            result = self._scan(str(root), excludes=[])
            rule_ids = {issue.rule_id for issue in result.issues}

            self.assertIn("SS001", rule_ids)
            self.assertEqual(result.files_scanned, 1)

    def test_excludes_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            src.mkdir()
            ignored = root / "venv"
            ignored.mkdir()
            (src / "ok.py").write_text("print('ok')\n", encoding="utf-8")
            (ignored / "bad.py").write_text("eval('x')\n", encoding="utf-8")

            result = self._scan(str(root), excludes=["venv"])
            rule_ids = {issue.rule_id for issue in result.issues}

            self.assertNotIn("SS001", rule_ids)
            self.assertEqual(result.files_scanned, 1)

    def test_scans_non_python_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            java_file = root / "App.java"
            java_file.write_text("// TODO review this class\n", encoding="utf-8")

            result = self._scan(str(root), excludes=[])
            rule_ids = {issue.rule_id for issue in result.issues}

            self.assertIn("SS004", rule_ids)
            self.assertEqual(result.files_scanned, 1)

    def test_scans_special_filenames_without_extension(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docker_file = root / "Dockerfile"
            docker_file.write_text("<<<<<<< HEAD\n", encoding="utf-8")

            result = self._scan(str(root), excludes=[])
            rule_ids = {issue.rule_id for issue in result.issues}

            self.assertIn("SS005", rule_ids)
            self.assertEqual(result.files_scanned, 1)


if __name__ == "__main__":
    unittest.main()
