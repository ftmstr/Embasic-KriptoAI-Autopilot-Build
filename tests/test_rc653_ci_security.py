"""Static guardrails for the isolated RC653 hosted CI job.

These checks exercise workflow text, not trusted branch protection or a YAML
security proof. Independent code review remains required before merge/release.
"""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "rc653-branch-synthetic-ci.yml"
CHECKOUT = "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"
SETUP = "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"
ALLOWED_PATHS = {
    "tests/test_rc653_receipt_boundary.py",
    "tests/test_rc653_journal_adversarial.py",
    "tests/test_rc653_ci_security.py",
    ".github/workflows/rc653-branch-synthetic-ci.yml",
    "safe_public_ci/**",
}


class RC653CISecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text(encoding="utf-8")

    def test_workflow_is_present(self):
        self.assertTrue(WORKFLOW.is_file())

    def test_only_rc653_branch_push_trigger(self):
        self.assertIn("on:\n  push:\n    branches:\n      - research/rc653-synthetic-receipt-envelope", self.source)
        for forbidden in ("pull_request:", "pull_request_target:", "workflow_run:",
                          "repository_dispatch:", "workflow_dispatch:", "schedule:",
                          "issue_comment:"):
            self.assertNotIn(forbidden, self.source)

    def test_trigger_is_path_scoped_to_synthetic_changes(self):
        paths = set(re.findall(r"(?m)^\s+- '([^']+)'\s*$", self.source))
        self.assertEqual(paths, ALLOWED_PATHS)

    def test_new_contract_tests_retrigger_ci(self):
        self.assertIn("      - 'tests/test_rc653_ci_security.py'", self.source)

    def test_hosted_ubuntu_and_not_private_runner(self):
        self.assertEqual(self.source.count("runs-on: ubuntu-24.04"), 1)
        for forbidden in ("self-hosted", "runs-on: windows-", "runs-on: macos-"):
            self.assertNotIn(forbidden, self.source)

    def test_global_and_job_tokens_read_only(self):
        self.assertEqual(self.source.count("contents: read"), 2)
        self.assertIsNone(re.search(r"(?m)^\s*[\w-]+:\s*write\s*$", self.source))

    def test_pinned_checkout_commit(self):
        self.assertIn("uses: " + CHECKOUT, self.source)
        self.assertEqual(self.source.count("actions/checkout@"), 1)

    def test_pinned_setup_python_commit(self):
        self.assertIn("uses: " + SETUP, self.source)
        self.assertEqual(self.source.count("actions/setup-python@"), 1)

    def test_exact_python_reproducibility(self):
        self.assertIn("python-version: '3.13.5'", self.source)
        self.assertIn("architecture: x64", self.source)
        self.assertIn("check-latest: false", self.source)
        self.assertIn("sys.version_info[:3] == (3, 13, 5)", self.source)

    def test_checkout_has_no_persisted_access(self):
        for setting in ("persist-credentials: false", "fetch-depth: 1",
                        "submodules: false", "lfs: false"):
            self.assertIn(setting, self.source)
        self.assertNotIn("repository:", self.source)

    def test_only_two_approved_external_actions(self):
        actions = re.findall(r"(?m)^\s+uses:\s+([^\n]+)$", self.source)
        self.assertEqual(actions, [CHECKOUT, SETUP])

    def test_only_three_approved_run_commands(self):
        commands = re.findall(r"(?m)^\s+run:\s+([^\n]+)$", self.source)
        self.assertEqual(commands, [
            'python -c "import sys; assert sys.version_info[:3] == (3, 13, 5)"',
            "python -m compileall -q safe_public_ci tests",
            "python -m unittest discover -s tests -v",
        ])

    def test_synthetic_only_mode_and_bounded_job(self):
        self.assertIn("SAFE_TEST_ONLY: '1'", self.source)
        self.assertIn("timeout-minutes: 6", self.source)

    def test_no_credentials_private_source_or_live_exchange(self):
        for forbidden in ("secrets.", "${{", "BINANCE", "MEXC", "api_key",
                          "private/", "KriptoAI-Autopilot.git", "id-token:"):
            self.assertNotIn(forbidden, self.source)

    def test_no_unreviewed_shell_download_or_deployment(self):
        for forbidden in ("curl ", "wget ", "pip install", "git clone",
                          "ssh ", "docker ", "upload-artifact",
                          "deploy", "gh release", "release:"):
            self.assertNotIn(forbidden, self.source)

    def test_no_soft_fail_or_hidden_test_errors(self):
        for forbidden in ("continue-on-error:", "|| true", "exit 0",
                          "always()", "set +e"):
            self.assertNotIn(forbidden, self.source)


if __name__ == "__main__":
    unittest.main()
