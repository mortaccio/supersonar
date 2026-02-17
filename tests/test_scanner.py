from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from supersonar.scanner import scan_path


class ScannerTests(unittest.TestCase):
    def _scan(
        self,
        root: str,
        excludes: list[str],
        skip_generated: bool = True,
        enabled_rules: list[str] | None = None,
        disabled_rules: list[str] | None = None,
        inline_ignore: bool = True,
    ):
        return scan_path(
            root,
            excludes=excludes,
            include_extensions=[".py", ".java", ".kt", ".js", ".jsx", ".go", ".yml", ".yaml", ".md"],
            include_filenames=["Dockerfile"],
            max_file_size_kb=1024,
            skip_generated=skip_generated,
            enabled_rules=enabled_rules,
            disabled_rules=disabled_rules,
            inline_ignore=inline_ignore,
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
            self.assertTrue(all(not Path(issue.file_path).is_absolute() for issue in result.issues))

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

    def test_scans_java_with_java_specific_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            java_file = root / "App.java"
            java_file.write_text(
                """package com.Example.Bad;
public class app {
    public static final int badConstant = 1;
    public void DoWork() {}
}
""",
                encoding="utf-8",
            )

            result = self._scan(str(root), excludes=[])
            rule_ids = {issue.rule_id for issue in result.issues}

            self.assertIn("SS201", rule_ids)
            self.assertIn("SS202", rule_ids)
            self.assertIn("SS204", rule_ids)
            self.assertIn("SS205", rule_ids)
            self.assertEqual(result.files_scanned, 1)

    def test_scans_kotlin_with_kotlin_specific_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kt_file = root / "App.kt"
            kt_file.write_text(
                """package com.Example.Bad
class bad_class {
    fun BadName(a: Int, b: Int, c: Int, d: Int, e: Int, f: Int, g: Int): Int {
        return 1
    }
}
""",
                encoding="utf-8",
            )

            result = self._scan(str(root), excludes=[])
            rule_ids = {issue.rule_id for issue in result.issues}

            self.assertIn("SS501", rule_ids)
            self.assertIn("SS502", rule_ids)
            self.assertIn("SS503", rule_ids)
            self.assertIn("SS504", rule_ids)
            self.assertEqual(result.files_scanned, 1)

    def test_scans_javascript_with_js_specific_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            js_file = root / "App.jsx"
            js_file.write_text("const home = () => <div>Home</div>;\n", encoding="utf-8")

            result = self._scan(str(root), excludes=[])
            rule_ids = {issue.rule_id for issue in result.issues}

            self.assertIn("SS302", rule_ids)
            self.assertEqual(result.files_scanned, 1)

    def test_scans_go_with_go_specific_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            go_file = root / "main.go"
            go_file.write_text("package My_Pkg\n", encoding="utf-8")

            result = self._scan(str(root), excludes=[])
            rule_ids = {issue.rule_id for issue in result.issues}

            self.assertIn("SS401", rule_ids)
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

    def test_scans_single_file_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "single.py"
            sample.write_text("value = eval('2+2')\n", encoding="utf-8")

            result = self._scan(str(sample), excludes=[])
            rule_ids = {issue.rule_id for issue in result.issues}

            self.assertIn("SS001", rule_ids)
            self.assertEqual(result.files_scanned, 1)

    def test_skips_generated_maven_target_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gen_dir = root / "target"
            gen_dir.mkdir()
            (gen_dir / "generated.py").write_text("value = eval('2+2')\n", encoding="utf-8")

            result = self._scan(str(root), excludes=[])
            self.assertEqual(result.files_scanned, 0)
            self.assertEqual(result.issues, [])

    def test_can_include_generated_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gen_dir = root / "target"
            gen_dir.mkdir()
            (gen_dir / "generated.py").write_text("value = eval('2+2')\n", encoding="utf-8")

            result = self._scan(str(root), excludes=[], skip_generated=False)
            rule_ids = {issue.rule_id for issue in result.issues}

            self.assertEqual(result.files_scanned, 1)
            self.assertIn("SS001", rule_ids)

    def test_inline_ignore_comment_suppresses_issue(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.py"
            sample.write_text("value = eval('2+2')  # supersonar:ignore SS001\n", encoding="utf-8")

            result = self._scan(str(root), excludes=[])
            self.assertEqual(result.issues, [])

    def test_disable_rule_filters_issues(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.py"
            sample.write_text("value = eval('2+2')\n", encoding="utf-8")

            result = self._scan(str(root), excludes=[], disabled_rules=["SS001"])
            self.assertEqual(result.issues, [])

    def test_enable_rule_only_keeps_selected_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.py"
            sample.write_text("# TODO fix\nvalue = eval('2+2')\n", encoding="utf-8")

            result = self._scan(str(root), excludes=[], enabled_rules=["SS004"])
            rule_ids = {issue.rule_id for issue in result.issues}

            self.assertEqual(rule_ids, {"SS004"})


if __name__ == "__main__":
    unittest.main()
