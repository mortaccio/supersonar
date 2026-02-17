from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from supersonar.rules.generic import GenericRuleEngine
from supersonar.rules.go import GoRuleEngine
from supersonar.rules.java import JavaRuleEngine
from supersonar.rules.javascript import JavaScriptRuleEngine
from supersonar.rules.kotlin import KotlinRuleEngine
from supersonar.rules.python import PythonRuleEngine


class RulesEngineTests(unittest.TestCase):
    def test_detects_all_core_rules(self) -> None:
        code = """# todo: remove
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

    def test_detects_subprocess_shell_true(self) -> None:
        code = """import subprocess
subprocess.run("ls -la", shell=True)
"""
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.py"
            sample.write_text(code, encoding="utf-8")
            issues = PythonRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS006", rule_ids)

    def test_detects_unsafe_yaml_load(self) -> None:
        code = """import yaml
value = yaml.load(data)
"""
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.py"
            sample.write_text(code, encoding="utf-8")
            issues = PythonRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS007", rule_ids)

    def test_safe_yaml_loader_not_flagged(self) -> None:
        code = """import yaml
value = yaml.load(data, Loader=yaml.SafeLoader)
"""
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.py"
            sample.write_text(code, encoding="utf-8")
            issues = PythonRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertNotIn("SS007", rule_ids)

    def test_detects_unsafe_pickle_load(self) -> None:
        code = """import pickle
obj = pickle.loads(data)
"""
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.py"
            sample.write_text(code, encoding="utf-8")
            issues = PythonRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS008", rule_ids)

    def test_detects_requests_verify_false(self) -> None:
        code = """import requests
requests.get("https://example.com", verify=False)
"""
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.py"
            sample.write_text(code, encoding="utf-8")
            issues = PythonRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS009", rule_ids)

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

    def test_generic_engine_ignores_dynamic_eval_in_comments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "app.js"
            sample.write_text("// eval(userInput)\n", encoding="utf-8")
            issues = GenericRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertNotIn("SS101", rule_ids)

    def test_generic_engine_skips_dynamic_eval_for_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "README.md"
            sample.write_text("do not do this: eval(userInput)\n", encoding="utf-8")
            issues = GenericRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertNotIn("SS101", rule_ids)

    def test_generic_engine_detects_insecure_http_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "app.js"
            sample.write_text("const api = 'http://example.com/v1';\n", encoding="utf-8")
            issues = GenericRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS107", rule_ids)

    def test_generic_engine_detects_dockerfile_security_issues(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "Dockerfile"
            sample.write_text(
                "FROM node\nRUN curl https://example.com/install.sh | sh\n",
                encoding="utf-8",
            )
            issues = GenericRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS108", rule_ids)
        self.assertIn("SS109", rule_ids)
        self.assertIn("SS110", rule_ids)

    def test_generic_engine_detects_k8s_manifest_security_issues(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "deployment.yaml"
            sample.write_text(
                """apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: app
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
            runAsNonRoot: false
""",
                encoding="utf-8",
            )
            issues = GenericRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS111", rule_ids)
        self.assertIn("SS112", rule_ids)
        self.assertIn("SS113", rule_ids)
        self.assertIn("SS114", rule_ids)

    def test_generic_engine_detects_merge_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "App.java"
            sample.write_text("<<<<<<< HEAD\n", encoding="utf-8")
            issues = GenericRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS005", rule_ids)

    def test_generic_engine_detects_private_key_material(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "secrets.pem"
            sample.write_text("-----BEGIN RSA PRIVATE KEY-----\n", encoding="utf-8")
            issues = GenericRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS102", rule_ids)

    def test_generic_engine_detects_readability_smells(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "style.txt"
            sample.write_text(
                ("x" * 141)
                + "\nline with space   \n"
                + "alpha beta gamma delta epsilon zeta eta theta iota kappa\n"
                + "lambda mu nu xi omicron pi rho sigma tau upsilon\n"
                + "phi chi psi omega alpha beta gamma delta epsilon\n"
                + "more repeated content to trigger duplicate detection\n"
                + "alpha beta gamma delta epsilon zeta eta theta iota kappa\n"
                + "lambda mu nu xi omicron pi rho sigma tau upsilon\n"
                + "phi chi psi omega alpha beta gamma delta epsilon\n"
                + "more repeated content to trigger duplicate detection\n",
                encoding="utf-8",
            )
            issues = GenericRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS103", rule_ids)
        self.assertIn("SS104", rule_ids)
        self.assertIn("SS105", rule_ids)

    def test_python_engine_detects_maintainability_smells(self) -> None:
        long_body = "\n".join("    x += 1" for _ in range(65))
        code = f"""class bad_class:
    pass

def BadName(a, b, c, d, e, f, g):
    x = 0
{long_body}
    return x

def nested():
    if True:
        if True:
            if True:
                if True:
                    if True:
                        return 1
    return 0
"""
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.py"
            sample.write_text(code, encoding="utf-8")
            issues = PythonRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS210", rule_ids)
        self.assertIn("SS211", rule_ids)
        self.assertIn("SS212", rule_ids)
        self.assertIn("SS213", rule_ids)
        self.assertIn("SS214", rule_ids)

    def test_python_engine_detects_structural_quality_smells(self) -> None:
        imports = "\n".join(f"import pkg{i}" for i in range(25))
        many_methods = "\n".join(f"    def method_{i}(self):\n        self.v{i} = {i}" for i in range(16))
        cohesion = """
    def alpha(self):
        self.alpha = 1
    def beta(self):
        self.beta = 2
    def gamma(self):
        self.gamma = 3
"""
        many_funcs = "\n".join(f"def fn_{i}():\n    return {i}" for i in range(22))
        code = f"""{imports}

class Massive:
{many_methods}
{cohesion}

{many_funcs}
"""
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "module.py"
            sample.write_text(code, encoding="utf-8")
            issues = PythonRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS215", rule_ids)
        self.assertIn("SS216", rule_ids)
        self.assertIn("SS217", rule_ids)
        self.assertIn("SS218", rule_ids)

    def test_java_engine_detects_naming_violations(self) -> None:
        code = """package com.Example.Bad;

public class bad_class {
    public static final String apiToken = "x";
    public void DoWork() {}
    public void run(String cmd) { Runtime.getRuntime().exec(cmd); }
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "Other.java"
            sample.write_text(code, encoding="utf-8")
            issues = JavaRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS201", rule_ids)
        self.assertIn("SS202", rule_ids)
        self.assertIn("SS203", rule_ids)
        self.assertIn("SS204", rule_ids)
        self.assertIn("SS205", rule_ids)
        self.assertIn("SS221", rule_ids)

    def test_java_engine_detects_complexity_smells(self) -> None:
        long_body = "\n".join("        sum += 1;" for _ in range(65))
        code = f"""public class App {{
    public int calculate(int a, int b, int c, int d, int e, int f, int g) {{
{long_body}
        return 1;
    }}

    public void deepNest() {{
        if (true) {{
            if (true) {{
                if (true) {{
                    if (true) {{
                        if (true) {{
                            System.out.println("x");
                        }}
                    }}
                }}
            }}
        }}
    }}
}}
"""
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "App.java"
            sample.write_text(code, encoding="utf-8")
            issues = JavaRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS206", rule_ids)
        self.assertIn("SS207", rule_ids)
        self.assertIn("SS208", rule_ids)

    def test_java_engine_detects_structural_quality_smells(self) -> None:
        imports = "\n".join(f"import com.example.dep{i};" for i in range(35))
        many_methods = "\n".join(
            f"""
    public void method{i}() {{
        this.f{i} = {i};
    }}
"""
            for i in range(22)
        )
        code = f"""{imports}

public class BigClass {{
    private int f1;
    private int f2;
    private int f3;
{many_methods}
}}
"""
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "BigClass.java"
            sample.write_text(code, encoding="utf-8")
            issues = JavaRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS209", rule_ids)
        self.assertIn("SS219", rule_ids)
        self.assertIn("SS220", rule_ids)

    def test_javascript_engine_detects_quality_smells(self) -> None:
        long_body = "\n".join("  total += 1;" for _ in range(65))
        code = f"""function Bad_name(a, b, c, d, e, f, g) {{
  let total = 0;
{long_body}
  return total;
}}

const home = () => <div>Home</div>;

function nested() {{
  if (true) {{
    if (true) {{
      if (true) {{
        if (true) {{
          if (true) {{
            return 1;
          }}
        }}
      }}
    }}
  }}
  return 0;
}}

const {{ exec }} = require("child_process");
exec(userInput);
"""
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "app.jsx"
            sample.write_text(code, encoding="utf-8")
            issues = JavaScriptRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS301", rule_ids)
        self.assertIn("SS302", rule_ids)
        self.assertIn("SS303", rule_ids)
        self.assertIn("SS304", rule_ids)
        self.assertIn("SS305", rule_ids)
        self.assertIn("SS306", rule_ids)

    def test_go_engine_detects_quality_smells(self) -> None:
        imports = "\n".join(f'"dep{i}"' for i in range(27))
        long_body = "\n".join("    total++" for _ in range(65))
        code = f"""package My_Pkg

import (
{imports}
)

func bad_name(a int, b int, c int, d int, e int, f int, g int) int {{
    total := 0
{long_body}
    if true {{
        if true {{
            if true {{
                if true {{
                    if true {{
                        total++
                    }}
                }}
            }}
        }}
    }}
    return total
}}
"""
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "main.go"
            sample.write_text(code, encoding="utf-8")
            issues = GoRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS401", rule_ids)
        self.assertIn("SS402", rule_ids)
        self.assertIn("SS403", rule_ids)
        self.assertIn("SS404", rule_ids)
        self.assertIn("SS405", rule_ids)
        self.assertIn("SS406", rule_ids)

    def test_go_engine_detects_security_smells(self) -> None:
        code = """package main

import (
    "crypto/tls"
    "os/exec"
)

func run(input string) {
    _ = &tls.Config{InsecureSkipVerify: true}
    _ = exec.Command("sh", "-c", input)
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "main.go"
            sample.write_text(code, encoding="utf-8")
            issues = GoRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS407", rule_ids)
        self.assertIn("SS408", rule_ids)

    def test_kotlin_engine_detects_quality_smells(self) -> None:
        long_body = "\n".join("        total += 1" for _ in range(65))
        code = f"""package com.Example.Bad

class bad_class {{
    fun BadName(a: Int, b: Int, c: Int, d: Int, e: Int, f: Int, g: Int): Int {{
        var total = 0
{long_body}
        if (true) {{
            if (true) {{
                if (true) {{
                    if (true) {{
                        if (true) {{
                            total += 1
                        }}
                    }}
                }}
            }}
        }}
        return total
    }}
    fun run(cmd: String) {{
        Runtime.getRuntime().exec(cmd)
    }}
}}
"""
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "app.kt"
            sample.write_text(code, encoding="utf-8")
            issues = KotlinRuleEngine().run(sample)

        rule_ids = {issue.rule_id for issue in issues}
        self.assertIn("SS501", rule_ids)
        self.assertIn("SS502", rule_ids)
        self.assertIn("SS503", rule_ids)
        self.assertIn("SS504", rule_ids)
        self.assertIn("SS505", rule_ids)
        self.assertIn("SS506", rule_ids)
        self.assertIn("SS507", rule_ids)


if __name__ == "__main__":
    unittest.main()
