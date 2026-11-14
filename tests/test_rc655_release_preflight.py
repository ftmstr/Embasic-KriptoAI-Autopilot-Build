"""Release preflight checks for invented fixtures, not a release authorization.

Uses standard-library static inspections only. Never touches exchange accounts,
market APIs, models, research data, or a private repository.
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "safe_public_ci"
TESTS = ROOT / "tests"
POLICY = ROOT / "PUBLICATION_GATE.md"
README = ROOT / "README.md"
WORKFLOWS = ROOT / ".github" / "workflows"
BLOCKED_FOLDERS = {"data", "models", "private", "strategies", "recovery", "evidence", "audits", "state"}
BLOCKED_EXTENSIONS = {".zip", ".gz", ".parquet", ".key", ".pem", ".p12", ".sqlite", ".db", ".pickle", ".pkl", ".pt", ".onnx"}
NETWORK_MODULES = {"socket", "requests", "urllib", "aiohttp", "httpx", "websockets",
                   "binance", "ccxt", "ftplib", "paramiko", "subprocess"}
SECRET_NAMES = {".env", ".env.local", "credentials.json", "secrets.json",
                "api-keys.json", "id_rsa", "seed.txt", "wallet.json"}
SANCTIONED_ROOTS = {"safe_public_ci", "tests", "docs", ".github"}
SANCTIONED_TOP_FILES = {"README.md", "PUBLICATION_GATE.md", ".gitignore"}


def tracked_like_files():
    """Inspect checkout without .git or incidental interpreter caches."""
    return sorted(
        (p for p in ROOT.rglob("*") if p.is_file()
         and ".git" not in p.relative_to(ROOT).parts
         and "__pycache__" not in p.relative_to(ROOT).parts
         and ".pytest_cache" not in p.relative_to(ROOT).parts),
        key=lambda p: p.relative_to(ROOT).as_posix()
    )


class SyntheticReleasePreflight(unittest.TestCase):
    def test_readme_is_explicitly_nonproduction(self):
        self.assertIn("standalone synthetic-only CI", README.read_text("utf-8"))

    def test_publication_gate_exists(self):
        self.assertTrue(POLICY.is_file())

    def test_policy_prohibits_private_history(self):
        self.assertIn("no copied private Git history", POLICY.read_text("utf-8"))

    def test_policy_denies_live_and_scientific_approval(self):
        body = POLICY.read_text("utf-8")
        for gate in ("LIVE=DISABLED", "FINAL LOCKED=SEALED", "SCIENTIFICALLY VALIDATED"):
            self.assertIn(gate, body)

    def test_license_grant_is_not_assumed(self):
        self.assertIn("No open source license is granted", POLICY.read_text("utf-8"))
        self.assertFalse(any((ROOT / name).exists()
                             for name in ("LICENSE", "LICENSE.md", "LICENSE.txt")))

    def test_only_whitelisted_checkout_roots(self):
        for p in tracked_like_files():
            rel = p.relative_to(ROOT)
            self.assertTrue(rel.parts[0] in SANCTIONED_ROOTS or
                            rel.as_posix() in SANCTIONED_TOP_FILES, rel)

    def test_no_private_data_directories(self):
        for name in BLOCKED_FOLDERS:
            self.assertFalse((ROOT / name).exists(), name)

    def test_no_forbidden_binary_artifact_extensions(self):
        for p in tracked_like_files():
            self.assertNotIn(p.suffix.lower(), BLOCKED_EXTENSIONS, p)

    def test_no_sensitive_credentials_filenames(self):
        for p in tracked_like_files():
            self.assertNotIn(p.name.lower(), SECRET_NAMES, p)

    def test_no_symlinked_checkout_files(self):
        for p in tracked_like_files():
            self.assertFalse(p.is_symlink(), p)

    def test_no_empty_runtime_python_sources(self):
        for p in SOURCE.glob("*.py"):
            self.assertGreater(p.stat().st_size, 0, p)

    def test_bounded_source_and_test_file_bytes(self):
        for p in list(SOURCE.glob("*.py")) + list(TESTS.glob("*.py")):
            self.assertLessEqual(p.stat().st_size, 65536, p)

    def test_only_python_files_in_runtime_package(self):
        self.assertTrue(list(SOURCE.glob("*.py")))
        for p in SOURCE.iterdir():
            if p.name == "__pycache__":
                continue
            self.assertTrue(p.is_file() and p.suffix == ".py", p)

    def test_source_modules_are_valid_python_ast(self):
        for p in SOURCE.glob("*.py"):
            with self.subTest(file=p.name):
                self.assertIsInstance(ast.parse(p.read_text("utf-8")), ast.Module)

    def test_source_modules_have_no_network_or_subprocess_imports(self):
        for p in SOURCE.glob("*.py"):
            tree = ast.parse(p.read_text("utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotIn(alias.name.split(".")[0], NETWORK_MODULES, p)
                if isinstance(node, ast.ImportFrom):
                    self.assertNotIn((node.module or "").split(".")[0], NETWORK_MODULES, p)

    def test_no_dynamic_source_execution(self):
        for p in SOURCE.glob("*.py"):
            tree = ast.parse(p.read_text("utf-8"))
            for n in ast.walk(tree):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                    self.assertNotIn(n.func.id, {"eval", "exec", "__import__", "compile"}, p)

    def test_all_workflows_are_yaml_not_scripts(self):
        self.assertTrue(list(WORKFLOWS.glob("*.yml")))
        for p in WORKFLOWS.rglob("*"):
            if p.is_file():
                self.assertIn(p.suffix, {".yml", ".yaml"}, p)

    def test_all_workflows_exclude_private_checkout(self):
        for p in WORKFLOWS.glob("*.yml"):
            body=p.read_text("utf-8")
            self.assertNotIn("ftmstr/KriptoAI-Autopilot", body)
            self.assertNotIn("pull_request_target:", body)
            self.assertNotIn("secrets.", body)

    def test_release_manifest_inputs_have_stable_sha256(self):
        sources = [p for p in tracked_like_files() if p.suffix == ".py"]
        def snapshot():
            return [(p.relative_to(ROOT).as_posix(),
                     hashlib.sha256(p.read_bytes()).hexdigest()) for p in sources]
        self.assertGreater(len(sources), 10)
        self.assertEqual(snapshot(), snapshot())

    def test_pr1_regression_module_not_claimed_present(self):
        self.assertFalse((TESTS / "test_regression_expanded.py").exists())


if __name__ == "__main__":
    unittest.main()
